use std::future::Future;
use std::io::{self, IoSlice, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use futures_util::io::{AsyncBufRead, AsyncRead, AsyncWrite};
use futures_util::lock::{Mutex, OwnedMutexGuard, OwnedMutexLockFuture};

use crate::parser::{self, request, stream, EnvIter};
use crate::protocol as fcgi;
use crate::{cgi, Config, ExitStatus};


#[derive(Debug)]
#[must_use = "futures are lazy and do nothing unless polled"]
enum RepeatableLockFuture<T: ?Sized> {
    Poll(OwnedMutexLockFuture<T>),
    Done(OwnedMutexGuard<T>),
}

impl<T: ?Sized> RepeatableLockFuture<T> {
    fn new(mutex: Arc<Mutex<T>>) -> Self {
        Self::Poll(mutex.lock_owned())
    }

    // Cannot impl std::future::Future due to return type
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<&mut T> {
        let this = self.get_mut();
        if let Self::Poll(fut) = this {
            let g = ready!(Pin::new(fut).poll(cx));
            *this = Self::Done(g);
        }
        match this {
            Self::Done(g) => Poll::Ready(&mut *g),
            Self::Poll(_) => unreachable!("RepeatableLockFuture should always be Done here"),
        }
    }
}


/// An unbuffered, `async` writer for output to a FastCGI stream.
///
/// Use `Request::output_stream` to obtain an instance for a given stream. Note
/// that the writer is unbuffered and thus repeated small writes are
/// inefficient. Writes larger than 64 KB are shortened to 64 KB due to
/// FastCGI's stream record framing.
///
/// All writers for a given [`Request`] share an underlying connection. Their
/// writes are therefore synchronized through a `Mutex` and happen in series.
/// A stream record is always written out completely before unlocking the
/// `Mutex` again. If an error occurs, the lock is kept until a subsequent call
/// wrote a sufficient number of bytes.
#[derive(Debug)]
pub struct StreamWriter<W> {
    writer: Arc<Mutex<W>>,
    lock: Option<RepeatableLockFuture<W>>,
    head: fcgi::RecordHeader,
    head_idx: u8,
    orig_len: u16,
}

impl<W> Clone for StreamWriter<W> {
    #[inline]
    fn clone(&self) -> Self {
        Self { writer: self.writer.clone(), lock: None, head: self.head, head_idx: 0, orig_len: 0 }
    }
}

impl<W> StreamWriter<W> {
    /// Returns the stream this writer is writing to.
    #[inline]
    #[must_use]
    pub fn stream(&self) -> fcgi::RecordType {
        self.head.rtype
    }

    #[must_use]
    fn is_writing(head: fcgi::RecordHeader) -> bool {
        // We track the remaining bytes to be written in these fields
        (head.content_length | u16::from(head.padding_length)) != 0
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for StreamWriter<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();
        let lock = this.lock.get_or_insert_with(|| {
            // Set the writer up for a new record
            assert!(!Self::is_writing(this.head), "lock was dropped mid-write");
            this.head.set_lengths(buf.len().try_into().unwrap_or(u16::MAX));
            this.head_idx = 0;
            this.orig_len = this.head.content_length;
            RepeatableLockFuture::new(this.writer.clone())
        });
        assert!(Self::is_writing(this.head), "poll_write called while poll_flush is pending");
        let buf = buf.get(..this.orig_len.into())
            .expect("buf shrunk between calls to poll_write");

        let w = ready!(Pin::new(lock).poll(cx));
        let head = this.head.to_bytes();

        while Self::is_writing(this.head) {
            let payload_idx = buf.len() - usize::from(this.head.content_length);
            let iov = [
                IoSlice::new(&head[this.head_idx.into()..]),
                IoSlice::new(&buf[payload_idx..]),
                IoSlice::new(this.head.padding_bytes()),
            ];
            // Keep lock even in the Err case: header might have already been written
            let mut written = ready!(Pin::new(&mut *w).poll_write_vectored(cx, &iov))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }

            // Calculates how many bytes of each IoSlice were written.
            // This ensures the calculations and casts below do not overflow.
            let mut iov_written = iov.iter().map(|s| {
                if let Some(new_written) = written.checked_sub(s.len()) {
                    written = new_written;
                    return s.len();
                }
                std::mem::take(&mut written)
            });
            const IOV_MSG: &str = "iov_written does not match iov";
            this.head_idx += iov_written.next().expect(IOV_MSG) as u8;
            // If these are modified, this.head was already written to completion.
            // In other words, modifying this.head won't change the output anymore.
            this.head.content_length -= iov_written.next().expect(IOV_MSG) as u16;
            this.head.padding_length -= iov_written.next().expect(IOV_MSG) as u8;
            debug_assert_eq!(written, 0);
        }

        this.lock = None;
        crate::macros::trace!(stream = ?this.stream(), bytes = buf.len(), "record written");
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        assert!(!Self::is_writing(this.head), "poll_flush called while poll_write is pending");

        let lock = this.lock.get_or_insert_with(|| RepeatableLockFuture::new(this.writer.clone()));
        let w = ready!(Pin::new(lock).poll(cx));
        let res = Pin::new(w).poll_flush(cx);

        if res.is_ready() {
            this.lock = None;
        }
        res
    }

    #[inline]
    fn poll_close(self: Pin<&mut Self>, _: &mut Context) -> Poll<io::Result<()>> {
        // Streams can only be closed via Request::close
        Poll::Ready(Ok(()))
    }
}


/// A FastCGI request with a high-level `async` interface.
///
/// The request consists of multiple components, which are available through
/// accessor methods:
/// - A [`Role`](fcgi::Role) that determines the expected behavior of the
///   application.
/// - A set of [`RequestFlags`](fcgi::RequestFlags) (which are usually not
///   relevant to the application).
/// - A [CGI/1.1 environment][env] composed of (Fast)CGI control variables and
///   mapped HTTP headers. See [`cgi::StaticVarName`] for a collection of
///   well-known variable names and the format used for HTTP headers. You can
///   use the variants of that enum directly to retrieve header data via the
///   accessor methods on [`Request`].
/// - A strictly sequential series of input streams provided by the FastCGI
///   client. See below for details.
/// - An (unordered) set of output streams transmitted back to the FastCGI
///   client.
///
/// Since the input streams follow a sequential, [`Role`](fcgi::Role)-based
/// order, we expose them via the [`AsyncRead`] and [`AsyncBufRead`] impls on
/// [`Request`]. The methods from those traits only ever read data from the
/// *active input stream*, which is initially set to the first input stream
/// allowed by the request's [`Role`](fcgi::Role). Reads return 0 bytes when
/// the active stream reached its end.
///
/// A subsequent stream may, at any time, be activated via `Request::set_stream`.
/// See the documentation of that function for details. This allows input
/// streams to be read or skipped as necessary, while interoperating with
/// existing `AsyncRead`-based adapters.
///
/// [env]: https://www.rfc-editor.org/rfc/rfc3875.html#section-4
#[derive(Debug)]
pub struct Request<'a, R, W> {
    parser: stream::Parser<'a>,
    input: R,
    output: Arc<Mutex<W>>,
    lock: Option<RepeatableLockFuture<W>>,
    writeable: bool,
}

impl<'a, R, W> Request<'a, R, W> {
    /// Wraps a [`stream::Parser`] with a reader `R` and a writer `W` into an
    /// `async` [`Request`].
    #[must_use]
    pub fn new(inner: stream::Parser<'a>, input: R, output: W) -> Self {
        let output = Arc::new(Mutex::new(output));
        let mut req = Self { parser: inner, input, output, lock: None, writeable: false };
        if req.role().input_streams().len() <= 1 {
            // Roles with 0 or 1 input stream(s) are writeable after reading the Params stream
            req.set_writeable();
        }
        req
    }

    /// Returns the role of the FastCGI application in this request.
    #[inline]
    #[must_use]
    pub fn role(&self) -> fcgi::Role {
        self.parser.request.role
    }

    /// Returns the control flags for this request.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> fcgi::RequestFlags {
        self.parser.request.flags
    }

    /// Returns the number of environment variables associated with this request.
    #[inline]
    #[must_use]
    pub fn env_len(&self) -> usize {
        self.parser.request.env_len()
    }

    /// Tests whether the variable name is part of the environment of this
    /// request.
    ///
    /// The documentation of [`cgi::VarName`] describes which types may be
    /// substituted for `S`.
    #[inline]
    #[must_use]
    pub fn contains_var<'i, S>(&self, name: S) -> bool
    where
        S: Into<&'i cgi::VarName>,
    {
        self.parser.request.contains_var(name.into())
    }

    /// Retrieves the value stored for the variable name, if there is one.
    ///
    /// The documentation of [`cgi::VarName`] describes which types may be
    /// substituted for `S`.
    #[inline]
    #[must_use]
    pub fn get_var<'i, S>(&self, name: S) -> Option<&[u8]>
    where
        S: Into<&'i cgi::VarName>,
    {
        self.parser.request.get_var(name.into())
    }

    /// Attempts to retrieve the string value stored for the variable name.
    ///
    /// The documentation of [`cgi::VarName`] describes which types may be
    /// substituted for `S`.
    ///
    /// Returns [`None`] if there is no corresponding value *or if the value
    /// is not valid UTF-8*. Use `Request::get_var` if you are interested in
    /// the raw bytes and want to decode them manually.
    #[inline]
    #[must_use]
    pub fn get_var_str<'i, S>(&self, name: S) -> Option<&str>
    where
        S: Into<&'i cgi::VarName>,
    {
        self.parser.request.get_var_str(name.into())
    }

    /// Returns an iterator over all environment variables of this request.
    #[inline]
    pub fn env_iter(&self) -> EnvIter {
        self.parser.request.env_iter()
    }

    /// Returns the active input stream for reading.
    ///
    /// This value is [`None`] if and only if the request's role does not
    /// specify any input streams, such as
    /// [`Role::Authorizer`](fcgi::Role::Authorizer).
    #[inline]
    #[must_use]
    pub fn active_stream(&self) -> Option<fcgi::RecordType> {
        self.parser.active_stream()
    }

    /// Sets the active input stream to `stream`.
    ///
    /// [`AsyncRead`] and [`AsyncBufRead`] methods will only return data from
    /// the new `stream` afterwards. Any buffered data from the previous stream
    /// is discarded (unless `stream` equals `Request::active_stream`).
    ///
    /// # Panics
    /// The sequence of `stream` values must follow the order given by
    /// `self.role().input_streams()`. Passing an absent value or a value
    /// preceding `Request::active_stream` panics immediately. See the
    /// [`Role`](fcgi::Role) documentation for the correct order.
    #[inline]
    pub fn set_stream(&mut self, stream: fcgi::RecordType) {
        self.parser.set_stream(Some(stream))
            .expect("streams should follow the order given by Role::input_streams");
        tracing::debug!(?stream, "active input stream changed");
    }

    /// Tests whether the request has become writeable.
    ///
    /// We call a [`Request`] writeable when it arrives at the beginning of its
    /// final input stream. From then on, `Request::output_stream` may be called
    /// to retrieve output stream writers.
    #[inline]
    #[must_use]
    pub fn is_writeable(&self) -> bool {
        self.writeable
    }

    /// Returns a [`StreamWriter`] for the given output `stream`.
    ///
    /// Unlike input streams, output streams may be mixed freely. It is thus
    /// allowed to operate on multiple [`StreamWriter`] instances in parallel.
    ///
    /// # Panics
    /// `stream` must be a value from `self.role().output_streams()`, otherwise
    /// an assertion panics. See the [`Role`](fcgi::Role) documentation for
    /// allowed values.
    ///
    /// Furthermore, FastCGI requires all but the final input stream to be read
    /// to completion before an application may emit output. This condition is
    /// verified by an assertion and can be checked with `Request::is_writeable`.
    /// Alternatively, awaiting `Request::writeable` guarantees that the
    /// condition is met.
    #[must_use]
    pub fn output_stream(&self, stream: fcgi::RecordType) -> StreamWriter<W> {
        assert!(
            self.role().output_streams().contains(&stream),
            "{stream:?} is not a valid output stream type for {:?}", self.role(),
        );
        assert!(self.writeable, "must receive final input stream to become writeable");
        let head = fcgi::RecordHeader::new(stream, self.parser.request.request_id.get());
        StreamWriter { writer: self.output.clone(), lock: None, head, head_idx: 0, orig_len: 0 }
    }

    #[must_use]
    fn is_final_stream(&self) -> bool {
        self.role().next_input_stream(self.active_stream()).is_none()
    }

    fn set_writeable(&mut self) {
        self.writeable = true;
        tracing::debug!("request became writeable");
    }
}


impl<'a, R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Request<'a, R, W> {
    /// Waits for the request to become writeable.
    ///
    /// This function is a shortcut to setting the final input stream manually
    /// and waiting for stream data to arrive. It thus implicitly changes the
    /// active input stream just like `Request::set_stream` would. Any data from
    /// preceding input streams is discarded.
    ///
    /// If you have been reading from the final input stream already, awaiting
    /// this function is a (cheap) no-op.
    ///
    /// # Errors
    /// Any [`io::Error`] from `R` or `W` is forwarded to the caller.
    /// Additionally, any [`parser::Error`] during protocol parsing is
    /// converted into an [`io::Error`] with an appropriate [`io::ErrorKind`].
    pub async fn writeable(&mut self) -> io::Result<()> {
        use std::future::poll_fn;
        if self.writeable {
            return Ok(());
        }

        // Setting the final stream can only fail if the active stream
        // is None, in which case self.writeable should be true already.
        let stream = self.role().input_streams().last().copied();
        self.parser.set_stream(stream).expect("final stream should always be valid to set");
        poll_fn(|cx| Pin::new(&mut *self).poll_input(cx, None))
            .await.and(Ok(()))
    }

    /// Parses protocol data until the Parser stops at a record boundary.
    ///
    /// The active input stream must be [`None`] to permit skipping forward.
    /// This is verified by a debug assertion.
    async fn record_boundary(&mut self) -> io::Result<()> {
        use futures_util::AsyncReadExt;
        debug_assert!(self.active_stream().is_none());
        if self.parser.is_record_boundary() {
            return Ok(());
        }

        // Can't poll_input() because it doesn't read when the active stream is None.
        // Sending Parser::output_buffer is delayed to subsequent operations.
        let mut read = 0;
        loop {
            match self.parser.parse(read, None) {
                Ok(_) | Err(parser::Error::AbortRequest) => { /* Ignore */ },
                Err(e) => return Err(e.into()),
            }
            if self.parser.is_record_boundary() {
                return Ok(());
            }

            // Parser::stream_buffer should never fill when the active stream is None
            debug_assert!(self.parser.stream_buffer().is_empty());
            self.parser.compress();
            read = self.input.read(self.parser.input_buffer()).await?;
            if read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// Gracefully shuts down the request with the given [`ExitStatus`].
    ///
    /// If the FastCGI client permitted connection reuse in the request's
    /// control flags (`Request::flags`), a [`request::Parser`] containing
    /// leftover buffered data is returned together with `R` and `W`. Otherwise,
    /// the result is an [`io::Error`] with [`io::ErrorKind::ConnectionReset`]
    /// and `R` and `W` are dropped.
    ///
    /// # Errors
    /// Closing the [`Request`] requires all [`StreamWriters`] returned from
    /// `Request::output_stream` to be dropped beforehand. Violating this
    /// requirement results in an [`io::Error`].
    ///
    /// Any [`io::Error`] from `R` or `W` is forwarded to the caller, as well
    /// as converted [`parser::Error`] instances except for
    /// [`parser::Error::AbortRequest`]. The latter variant is handled
    /// internally.
    pub async fn close(mut self, status: ExitStatus) -> io::Result<(request::Parser<'a>, R, W)> {
        use futures_util::AsyncWriteExt;
        // Prepare request for shutdown
        match self.writeable().await {
            Ok(_) => {},
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => { /* Ignore */ },
            Err(e) => return Err(e),
        }
        self.parser.set_stream(None).expect("ignoring stream data should always be allowed");
        self.record_boundary().await?;

        // Send required stream end headers and EndRequest record
        let request_id = self.parser.request.request_id.get();
        let streams = if self.writeable { self.role().output_streams() } else { &[] };
        let endreq = fcgi::body::make_request_epilogue(request_id, status, streams);

        std::mem::drop(self.lock);
        let writers = Arc::strong_count(&self.output) - 1;
        let mut output = match Arc::try_unwrap(self.output) {
            Ok(m) => m.into_inner(),
            Err(_) => return Err(io::Error::new(io::ErrorKind::Other, format!(
                "{writers} StreamWriter(s) not dropped before Request::close",
            ))),
        };

        // TODO(io_slice_advance): switch to write_vectored_all() once stabilized?
        if let out @ [_, ..] = self.parser.output_buffer() {
            // Parser::output_buffer is usually empty, so
            // we don't use complex, (partial) vectored writes.
            output.write_all(out).await?;
            self.parser.consume_output(out.len());
        }
        output.write_all(&endreq).await?;
        crate::macros::trace!("management records flushed");

        // Extract request::Parser if connection should be reused
        if self.parser.request.flags.contains(fcgi::RequestFlags::KeepConn) {
            let parser = self.parser.into_request_parser()?;
            return Ok((parser, self.input, output));
        }
        Err(io::ErrorKind::ConnectionReset.into())
    }

    /// Writes all of `Parser::output_buffer` into `self.output`.
    fn poll_output(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.parser.output_buffer().is_empty() {
            debug_assert!(this.lock.is_none());
            return Poll::Ready(Ok(()));
        }

        let lock = this.lock.get_or_insert_with(|| RepeatableLockFuture::new(this.output.clone()));
        let w = ready!(Pin::new(lock).poll(cx));
        while let out @ [_, ..] = this.parser.output_buffer() {
            // Keep lock even in the Err case: header might have already been written
            let written = ready!(Pin::new(&mut *w).poll_write(cx, out))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            this.parser.consume_output(written);
        }

        this.lock = None;
        crate::macros::trace!("management records flushed");
        Poll::Ready(Ok(()))
    }

    /// Parses buffered and/or fresh protocol data into `dest`.
    fn poll_input(
        self: Pin<&mut Self>,
        cx: &mut Context,
        mut dest: Option<&mut [u8]>,
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // First check if there is buffered stream data available
        match (&mut dest, this.parser.stream_buffer()) {
            // Nothing to do: either dest is 0-length or buffer is already filled
            (Some([]), _) | (None, [_, ..]) => return Poll::Ready(Ok(0)),
            // Write buffered data directly into dest
            (Some(buf), avail @ [_, ..]) => {
                let read = buf.write(avail).expect("writing into &mut [u8] should always succeed");
                this.parser.consume_stream(read);
                return Poll::Ready(Ok(read));
            },
            _ => { /* Need to parse new stream data */ },
        }

        // Make sure Parser::output_buffer is sent out regularly. Since output
        // from the Parser should be rare, the parsing loop below batches it
        // until the next call to poll_input() (either from the user or a wake).
        // The added latency doesn't matter for parser output.
        ready!(Pin::new(&mut *this).poll_output(cx))?;

        // Perform an initial `Parser::parse` without new input to consume buffered protocol data
        let mut read = 0;
        loop {
            let status = this.parser.parse(read, dest.as_deref_mut())?;
            if status.stream_end || status.stream > 0 {
                if !this.writeable && this.is_final_stream() {
                    this.set_writeable();
                }
                return Poll::Ready(Ok(status.stream));
            }

            // Both stream and protocol data buffers are empty here
            this.parser.compress();
            let buf = this.parser.input_buffer();
            read = ready!(Pin::new(&mut this.input).poll_read(cx, buf))?;
            if read == 0 {
                // Connection was closed without end-of-stream record
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for Request<'_, R, W> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_input(cx, Some(buf))
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncBufRead for Request<'_, R, W> {
    #[inline]
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<&[u8]>> {
        self.as_mut().poll_input(cx, None)
            .map_ok(|_| self.into_ref().get_ref().parser.stream_buffer())
    }

    #[inline]
    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.parser.consume_stream(amt);
    }
}


/// A token to track the number of concurrent FastCGI connections.
///
/// An instance of this type must be acquired from a [`Runner`] **before**
/// accepting a new connection. This ensures that the [`Config`]'s `max_conns`
/// is never exceeded. The token is then consumed by `Token::run`. Once that
/// function returns, the [`Runner`] will allow a new connection.
#[derive(Debug)]
#[must_use = "tokens only exist to call Token::run"]
pub struct Token {
    config: Arc<Config>,
    _g: async_lock::SemaphoreGuardArc,
}

impl Token {
    /// Invokes the `handler` once for each FastCGI request from the connection.
    ///
    /// `async` runtimes generally allow the read and write half of a network
    /// connection to be split into separate types, for example via shared
    /// references, cloning, or a function on the connection instance.
    /// `fastcgi_server` is built around working on these halves separately.
    /// The connection should not be used by the caller anymore after passing it
    /// to this function.
    ///
    /// The handler's type `H` is equivalent to a function with signature
    /// `async fn(&mut Request<R, W>) -> io::Result<ExitStatus>`. An [`Err`]
    /// result causes the connection to be torn down. This is meant to simplify
    /// reading from and writing to the request's streams. Use [`Ok(ExitStatus)`]
    /// with different status codes to signal regular (non-IO-related) exits,
    /// which permits connection reuse.
    ///
    /// A graceful response to the request requires all [`StreamWriters`] to be
    /// dropped when the `handler` returns. Otherwise, the request will be left
    /// in an incomplete state and the connection is terminated once the last
    /// [`StreamWriter`] is dropped.
    ///
    /// # Panics
    /// Any panics from the `handler` are propagated through this function,
    /// dropping the connection in the process. `async` runtimes differ in their
    /// handling of panics from spawned tasks, so you might want to consider
    /// catching them at the `Token::run` boundary. [`Request`] and
    /// [`StreamWriter`] can be treated as unwind-safe provided that none of
    /// their instances survive past the `handler` invocation.
    pub async fn run<R, W, H, F>(self, mut input: R, mut output: W, mut handler: H)
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
        H: FnMut(&mut Request<R, W>) -> F,
        F: Future<Output = io::Result<ExitStatus>>,
    {
        // False positive
        #![allow(clippy::manual_let_else)]
        use tracing::Instrument;

        let mut rparser = request::Parser::new(&self.config);
        loop {
            let sparser = match Self::parse_request(rparser, &mut input, &mut output).await {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                    tracing::debug!("connection closed by remote");
                    return;
                },
                Err(e) => {
                    let error: &dyn std::error::Error = &e;
                    tracing::error!(error, "parsing request failed");
                    return;
                },
            };

            let span = tracing::warn_span!(
                "fastcgi_request", request_id = sparser.request.request_id,
                role = ?sparser.request.role, flags = %sparser.request.flags.bits(),
            );

            let out = async {
                let mut req = Request::new(sparser, input, output);
                let status = match handler(&mut req).await {
                    Ok(s) => s,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                        tracing::debug!("request aborted by remote");
                        ExitStatus::ABORT
                    },
                    Err(e) => {
                        let error: &dyn std::error::Error = &e;
                        tracing::error!(error, "IO failed mid-request");
                        return None;
                    },
                };

                let next = match req.close(status).await {
                    Ok(p) => Some(p),
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => None,
                    Err(e) => {
                        let error: &dyn std::error::Error = &e;
                        tracing::error!(error, "closing request failed");
                        return None;
                    },
                };
                let connection = if next.is_some() { "reuse" } else { "close" };
                tracing::debug!(connection, "request completed");
                next
            }.instrument(span).await;

            (rparser, input, output) = match out {
                Some(p) => p,
                None => return,
            };
        }
    }

    async fn parse_request<'a, R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        mut parser: request::Parser<'a>,
        input: &mut R,
        output: &mut W,
    ) -> io::Result<stream::Parser<'a>> {
        use futures_util::{AsyncReadExt, AsyncWriteExt};
        loop {
            let read = input.read(parser.input_buffer()).await?;
            if read == 0 {
                // Client-initiated connection shutdown
                return Err(io::ErrorKind::ConnectionReset.into());
            }

            let status = parser.parse(read);
            if !status.output.is_empty() {
                output.write_all(status.output).await?;
            }
            if status.done {
                return parser.into_stream_parser().map_err(Into::into);
            }
        }
    }
}


/// A [`Token`] printer that limits the number of concurrent FastCGI
/// connections.
///
/// Use `Config::async_runner` to construct a [`Runner`] for up to `max_conns`
/// concurrent connections. The runner should then be moved into the `async`
/// task responsible for accepting incoming FastCGI connections. A [`Token`]
/// must be acquired via `Runner::get_token` **before** accepting a new
/// connection. It serves as the entrypoint to the rest of the library.
///
/// [`Runner`] instances can be shared across multiple `async` tasks, either by
/// cloning or via references. Cloned instances share the same connection limit.
#[derive(Debug, Clone)]
pub struct Runner {
    config: Arc<Config>,
    sema: Arc<async_lock::Semaphore>,
}

impl Runner {
    /// Waits for a [`Token`] to become available and returns it.
    #[inline]
    pub async fn get_token(&self) -> Token {
        let g = self.sema.acquire_arc().await;
        Token { config: self.config.clone(), _g: g }
    }
}

impl Config {
    /// Creates an [`async_io::Runner`](Runner) with a limit of `max_conns`
    /// concurrent connections.
    #[must_use]
    pub fn async_runner(self) -> Runner {
        let sema = async_lock::Semaphore::new(self.max_conns.get());
        Runner { config: self.into(), sema: sema.into() }
    }
}


#[cfg(test)]
mod tests {
    use std::iter::repeat_with;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;
    use super::*;

    #[test]
    fn trait_check() {
        fn ok<T: Send + Unpin>() {}
        // () is trivially Unpin
        ok::<Request<(), ()>>();
        ok::<StreamWriter<()>>();

        fn spawnable<T: Send + 'static>() {}
        spawnable::<Runner>();
        spawnable::<Token>();
    }

    // Most of the code in this module just wires up the individually-tested
    // parsers to a network connection. We test that glue code outside of Rust's
    // test framework with a real webserver in the loop.

    struct CountWaker {
        wakes: AtomicUsize,
    }
    impl CountWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self { wakes: 0.into() })
        }
        fn wakes(&self) -> usize {
            self.wakes.load(Ordering::Relaxed)
        }
    }
    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn make_writer(stream: fcgi::RecordType) -> StreamWriter<Vec<u8>> {
        let writer = Arc::new(Mutex::new(Vec::with_capacity(2048)));
        let head = fcgi::RecordHeader::new(stream, 1);
        StreamWriter { writer, lock: None, head, head_idx: 0, orig_len: 0 }
    }

    #[test]
    fn writer_interleaved() {
        let counter = CountWaker::new();
        let waker = counter.clone().into();
        let mut cx = Context::from_waker(&waker);

        let bytes: Vec<_> = repeat_with(|| fastrand::u8(..)).take(256).collect();
        let mut main = make_writer(fcgi::RecordType::Stdout);
        let mut err = main.clone();
        err.head.rtype = fcgi::RecordType::Stderr;
        assert_eq!(err.stream(), fcgi::RecordType::Stderr);

        for amt in [175, 0, 89] {
            let res = Pin::new(&mut main).poll_write(&mut cx, &bytes[..amt]);
            assert!(matches!(res, Poll::Ready(Ok(n)) if n == amt));
        }
        for amt in [0, 97] {
            let res = Pin::new(&mut err).poll_write(&mut cx, &bytes[..amt]);
            assert!(matches!(res, Poll::Ready(Ok(n)) if n == amt));
        }
        assert_eq!(counter.wakes(), 0);

        {
            // Simulate write with locked mutex
            let _g = main.writer.try_lock_owned().unwrap();
            let res = Pin::new(&mut main).poll_write(&mut cx, &bytes[..221]);
            assert!(res.is_pending());
            // Drop of lock guard calls waker
        }
        assert_eq!(counter.wakes(), 1);
        let res = Pin::new(&mut main).poll_write(&mut cx, &bytes[..221]);
        assert!(matches!(res, Poll::Ready(Ok(221))));

        let res = Pin::new(&mut err).poll_flush(&mut cx);
        assert!(matches!(res, Poll::Ready(Ok(()))));

        std::mem::drop(err);
        let out = Arc::try_unwrap(main.writer)
            .expect("main should hold the only reference to the writer").into_inner();
        assert_eq!(out.len(), 632);
        assert_eq!(&out[..8], b"\x01\x06\x00\x01\x00\xaf\x01\0");
        assert_eq!(&out[184..192], b"\x01\x06\x00\x01\x00\x59\x07\0");
        assert_eq!(&out[288..296], b"\x01\x07\x00\x01\x00\x61\x07\0");
        assert_eq!(&out[400..408], b"\x01\x06\x00\x01\x00\xdd\x03\0");
    }

    #[test]
    #[should_panic(expected = "buf shrunk between calls to poll_write")]
    fn writer_buf_shrink() {
        let waker = CountWaker::new().into();
        let mut cx = Context::from_waker(&waker);
        let mut w = make_writer(fcgi::RecordType::Stderr);
        assert_eq!(w.stream(), fcgi::RecordType::Stderr);

        {
            let _g = w.writer.try_lock_owned().unwrap();
            let res = Pin::new(&mut w).poll_write(&mut cx, &[0x5f; 100]);
            assert!(res.is_pending());
        }
        let res = Pin::new(&mut w).poll_write(&mut cx, &[0x5f; 50]);
        // should panic above
        assert!(matches!(res, Poll::Ready(Ok(50))));
    }

    #[test]
    #[should_panic(expected = "poll_write called while poll_flush is pending")]
    fn writer_mixed_poll() {
        let waker = CountWaker::new().into();
        let mut cx = Context::from_waker(&waker);
        let mut w = make_writer(fcgi::RecordType::Stdout);
        assert_eq!(w.stream(), fcgi::RecordType::Stdout);

        let _g = w.writer.try_lock_owned().unwrap();
        let res = Pin::new(&mut w).poll_flush(&mut cx);
        assert!(res.is_pending());
        let res = Pin::new(&mut w).poll_write(&mut cx, &[0, 58, 172, 9]);
        // should panic above
        assert!(res.is_pending());
    }

    // TODO(msrv): use std::pin::pin once MSRV >= 1.68
    #[test]
    fn runner_limit() {
        let counter = CountWaker::new();
        let waker = counter.clone().into();
        let mut cx = Context::from_waker(&waker);

        let config = Config::with_conns(3.try_into().unwrap());
        let runner = config.async_runner();
        let mut tokens: Vec<_> = (1..=3).map(|idx| {
            let fut = runner.get_token();
            futures_util::pin_mut!(fut);
            match fut.poll(&mut cx) {
                Poll::Ready(t) => t,
                Poll::Pending => panic!("token #{idx} was not available"),
            }
        }).collect();

        assert_eq!(counter.wakes(), 0);
        let fut = runner.get_token();
        futures_util::pin_mut!(fut);
        let res = fut.as_mut().poll(&mut cx);
        assert!(res.is_pending());

        tokens.clear();
        assert_eq!(counter.wakes(), 1);
        let res = fut.as_mut().poll(&mut cx);
        assert!(res.is_ready());
    }
}
