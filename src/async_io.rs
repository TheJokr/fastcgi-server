use std::future::Future;
use std::io::{self, IoSlice, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use futures_util::io::{AsyncBufRead, AsyncRead, AsyncWrite};
use futures_util::lock::{Mutex, OwnedMutexGuard, OwnedMutexLockFuture};

use crate::parser::{self, request, stream, EnvIter};
use crate::protocol as fcgi;
use crate::{cgi, ExitStatus};


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
/// `Mutex` again.
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
/// allowed by the request's [`Role`](fcgi::Role). Reads only ever return 0 bytes
/// if the active stream reached its end.
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
        // Roles with 0 or 1 input stream(s) are writeable after reading the Params stream
        let writeable = inner.request.role.input_streams().len() <= 1;
        let output = Arc::new(Mutex::new(output));
        Self { parser: inner, input, output, lock: None, writeable }
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
    /// converted into an [`io::Error`] with an appropraite [`io::ErrorKind`].
    pub async fn writeable(&mut self) -> io::Result<()> {
        use futures_util::future::poll_fn;
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
        let mut written = 0;
        loop {
            match self.parser.parse(written, None) {
                Ok(_) | Err(parser::Error::AbortRequest) => { /* Ignore */ },
                Err(e) => return Err(e.into()),
            }
            if self.parser.is_record_boundary() {
                return Ok(());
            }

            // Parser::stream_buffer should never fill when the active stream is None
            debug_assert!(self.parser.stream_buffer().is_empty());
            self.parser.compress();
            written = self.input.read(self.parser.input_buffer()).await?;
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
                "all StreamWriters for this Request should be dropped: {writers} left",
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
            this.parser.consume_output(written);
        }

        this.lock = None;
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
        let mut written = 0;
        loop {
            let status = this.parser.parse(written, dest.as_deref_mut())?;
            if status.stream_end || status.stream > 0 {
                if !this.writeable {
                    this.writeable = this.is_final_stream();
                }
                return Poll::Ready(Ok(status.stream));
            }

            // Both stream and protocol data buffers are empty here
            this.parser.compress();
            let buf = this.parser.input_buffer();
            written = ready!(Pin::new(&mut this.input).poll_read(cx, buf))?;
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_check() {
        fn ok<T: Send + Unpin>() {}
        // () is trivially Unpin
        ok::<Request<(), ()>>();
        ok::<StreamWriter<()>>();
    }
}
