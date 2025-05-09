use std::cmp::{min, Ordering};
use std::io::Write;
use std::ops::ControlFlow::{Break, Continue};

use super::{request, Error, Request};
use crate::protocol as fcgi;
use crate::Config;


type ControlFlow = std::ops::ControlFlow<()>;

/// An output report from `Parser::parse`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Status {
    /// The number of bytes written into `dest` (or `Parser::stream_buffer`,
    /// if the former is [`None`]).
    pub stream: usize,

    /// Indicates whether the active input stream reached its end.
    ///
    /// If `true`, future calls to `Parser::parse` will not yield additional
    /// stream data until the next stream (if any) is activated via
    /// `Parser::set_stream`. If the active stream is already [`None`], this
    /// marks the end of the request.
    ///
    /// Otherwise, either `dest` is full or all buffered protocol data has been
    /// parsed. The latter case requires new input to be supplied before the
    /// next call to `Parser::parse`.
    pub stream_end: bool,

    /// The number of bytes written into `Parser::output_buffer`.
    pub output: usize,
}


/// An error type for violations of FastCGI's role-based stream sequencing
/// rules.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("FastCGI {role:?} cannot sequence stream {new:?} after stream {old:?}")]
pub struct SequenceError {
    role: fcgi::Role,
    new: fcgi::RecordType,
    old: Option<fcgi::RecordType>,
}


/// Compares `recv` and `exp` based on the order given by
/// `role.input_streams()`.
///
/// A [`None`] value for `exp` is interpreted as greater-than all other values.
/// Conversely, a `recv` value that is not present in `role.input_streams()` is
/// treated as less-than all other values.
///
/// `recv` and `exp` (if the latter is [`Some`]) should be input stream types.
/// This is verified by a debug assertion.
#[must_use]
fn cmp_input_streams(
    role: fcgi::Role,
    recv: fcgi::RecordType,
    exp: Option<fcgi::RecordType>,
) -> Ordering {
    // None always comes after all other stream types
    let Some(exp) = exp else { return Ordering::Less; };
    debug_assert!(recv.is_input_stream());
    debug_assert!(exp.is_input_stream());
    if recv == exp {
        return Ordering::Equal;
    }

    // Assume recv precedes exp and overwrite otherwise
    let mut recv_pos = Ordering::Less;
    for &s in role.input_streams() {
        if s == recv {
            // recv is present, recv_pos is accurate
            return recv_pos;
        } else if s == exp {
            // recv (if present) must succeed exp
            recv_pos = Ordering::Greater;
        }
    }
    // recv is not present in role.input_streams(), so it can be ignored
    Ordering::Less
}


#[derive(Debug, Clone)]
enum State {
    Stream,
    Skip,
    Values { vars: fcgi::ProtocolVariables },
}


/// A parser which extracts FastCGI stream data from a caller-provided
/// record stream.
///
/// At any time, the parser maintains an *active input stream*. It is set to
/// the first entry of the FastCGI request's `Role::input_streams` upon
/// creation and must advance in the order given by that slice. The current
/// value can be retrieved via `Parser::active_stream` and set via
/// `Parser::set_stream`. A special value of [`None`] means all future stream
/// data will be ignored.
///
/// The caller must feed the record stream into the parser's internal buffer,
/// which is available via `Parser::input_buffer`. After reading `n` bytes
/// into this slice, `Parser::parse(n, dest)` processes the bytes and returns
/// a [`Status`] value. Data from the active stream is either copied directly
/// into a given buffer (if `dest` is [`Some(buf)`]) or into the parser's
/// internal buffer (otherwise). Internally-buffered stream data is accessible
/// via `Parser::stream_buffer` and must be consumed via
/// `Parser::consume_stream`.
///
/// The [`Status`] may further indicate that output bytes were written, which
/// are accessible via `Parser::output_buffer` and must similarly be consumed
/// via `Parser::consume_output`. Output bytes should be sent to the FastCGI
/// client in a timely manner, though `Parser::output_buffer` is preserved
/// across calls to `Parser::parse`.
///
/// The internal buffer is shared dynamically between (parsed) stream data and
/// (raw) protocol data. This makes it necessary to compress gaps in the buffer
/// occasionally. See `Parser::compress` for details.
#[derive(Debug, Clone)]
#[must_use = "Parser must be invoked to consume input"]
pub struct Parser<'a> {
    // Layout: [gap] | <parsed> | [gap] | <raw> | <free>
    buffer: Box<[u8]>,
    parsed_start: usize,
    gap_start: usize,
    raw_start: usize,
    free_start: usize,

    config: &'a Config,
    output: Vec<u8>,
    output_start: usize,

    /// The FastCGI request for which stream data is being parsed.
    pub request: Request,
    stream: Option<fcgi::RecordType>,
    payload_rem: u16,
    padding_rem: u8,
    state: State,
}

macro_rules! debug_assert_invars {
    ($s:ident) => {
        debug_assert!($s.parsed_start <= $s.gap_start);
        debug_assert!($s.gap_start <= $s.raw_start);
        debug_assert!($s.raw_start <= $s.free_start);
        debug_assert!($s.free_start <= $s.buffer.len());
        debug_assert!($s.output_start <= $s.output.len());
    };
}

impl<'a> Parser<'a> {
    /// Creates a new [`Parser`] for the given configuration and [`Request`].
    pub fn new(config: &'a Config, request: Request) -> Self {
        let buffer_size = config.aligned_bufsize();
        let buffer = vec![0; buffer_size].into_boxed_slice();
        Self::from_parser(config, request, buffer, 0, Vec::new())
    }

    /// Creates a new [`Parser`] from a parsed [`Request`] and existing buffers.
    #[inline]
    pub(super) fn from_parser(
        config: &'a Config,
        request: Request,
        buffer: Box<[u8]>,
        input_len: usize,
        output: Vec<u8>,
    ) -> Self {
        debug_assert!(output.is_empty(), "output buffer must be empty for accurate `Status`es");
        let stream = request.role.next_input_stream(None);
        Self {
            buffer, parsed_start: 0, gap_start: 0, raw_start: 0, free_start: input_len,
            config, output, output_start: 0, request, stream, payload_rem: 0, padding_rem: 0,
            state: State::Skip,
        }
    }

    /// Returns the currently active input stream, whose data will be extracted.
    #[inline]
    #[must_use]
    pub fn active_stream(&self) -> Option<fcgi::RecordType> {
        self.stream
    }

    /// Sets the active input stream to `stream`.
    ///
    /// If `stream` is different from `Parser::active_stream`, the internal
    /// stream data buffer is emptied. A [`None`] value for `stream` means all
    /// future stream data will be ignored. This is always valid to set, but
    /// cannot be unset again.
    ///
    /// # Errors
    /// Returns a [`SequenceError`] if `stream` is [`Some(s)`] and either not a
    /// valid input stream type for the request's [`Role`](fcgi::Role), or the
    /// [`Role`](fcgi::Role) requires `stream` to precede
    /// `Parser::active_stream`. The correct order is given by
    /// `Role::input_streams`.
    pub fn set_stream(&mut self, stream: Option<fcgi::RecordType>) -> Result<(), SequenceError> {
        if let Some(s) = stream {
            if cmp_input_streams(self.request.role, s, self.stream) == Ordering::Less {
                return Err(SequenceError { role: self.request.role, new: s, old: self.stream });
            }
        }
        if stream != self.stream {
            if matches!(self.state, State::Stream) {
                // Ignore unparsed data from old stream
                self.state = State::Skip;
            }
            self.discard_stream();
            self.stream = stream;
        }
        Ok(())
    }

    /// Returns the slice of the parser's internal buffer from which stream data
    /// may be consumed.
    ///
    /// `Parser::consume_stream` must be called afterwards with the number of
    /// bytes actually consumed.
    #[inline]
    #[must_use]
    pub fn stream_buffer(&self) -> &[u8] {
        &self.buffer[self.parsed_start..self.gap_start]
    }

    /// Removes the first `amt` bytes from `Parser::stream_buffer` after the
    /// caller consumed them.
    #[inline]
    pub fn consume_stream(&mut self, amt: usize) {
        let parsed_len = self.gap_start - self.parsed_start;
        self.parsed_start += min(amt, parsed_len);
        debug_assert_invars!(self);
    }

    /// Empties `Parser::stream_buffer` by compressing the internal buffer.
    #[inline]
    fn discard_stream(&mut self) {
        self.parsed_start = 0;
        self.gap_start = 0;
        self.compress();
        debug_assert_eq!(self.raw_start, 0);
    }

    /// Returns the slice of the parser's internal buffer into which new input
    /// must be written.
    ///
    /// The number of bytes actually written, such as by [`Read::read`][read],
    /// is later passed to `Parser::parse`. It is invalid to call any other
    /// mutating function on this [`Parser`] in between.
    ///
    /// Use `Parser::compress` to reclaim space in this buffer after a call to
    /// `Parser::parse`.
    ///
    /// [read]: std::io::Read::read
    #[inline]
    #[must_use]
    pub fn input_buffer(&mut self) -> &mut [u8] {
        &mut self.buffer[self.free_start..]
    }

    /// Compresses gaps in the internal buffer to make space available for
    /// `Parser::input_buffer`.
    ///
    /// Data from the internal buffer is consumed during `Parser::parse` and
    /// `Parser::consume_stream`, leaving gaps of unused space behind. To reuse
    /// this space for `Parser::input_buffer`, data must be copied around. It
    /// is most efficient to do so when the buffer is mostly empty, that is,
    /// after parsing all buffered protocol data and fully consuming
    /// `Parser::stream_buffer`.
    pub fn compress(&mut self) {
        if 0 < self.parsed_start && self.parsed_start < self.gap_start {
            self.buffer.copy_within(self.parsed_start..self.gap_start, 0);
        }
        // [parsed_start, gap_start) moved to [0, gap_start - parsed_start)
        self.gap_start -= self.parsed_start;
        self.parsed_start = 0;

        if self.gap_start < self.raw_start && self.raw_start < self.free_start {
            self.buffer.copy_within(self.raw_start..self.free_start, self.gap_start);
        }
        // [raw_start, free_start) moved to [gap_start, free_start - (raw_start - gap_start))
        crate::macros::trace!(freed = self.raw_start - self.gap_start, "buffer compressed");
        self.free_start -= self.raw_start - self.gap_start;
        self.raw_start = self.gap_start;
        debug_assert_invars!(self);
    }

    /// Returns the output buffer, whose contents must be sent to the FastCGI
    /// client.
    ///
    /// `Parser::consume_output` must be called afterwards with the number of
    /// bytes actually sent.
    #[inline]
    #[must_use]
    pub fn output_buffer(&self) -> &[u8] {
        &self.output[self.output_start..]
    }

    /// Removes the first `amt` bytes from `Parser::output_buffer` after the
    /// caller sent them to the FastCGI client.
    #[inline]
    pub fn consume_output(&mut self, amt: usize) {
        let output_len = self.output.len() - self.output_start;
        if amt >= output_len {
            self.output.clear();
            self.output_start = 0;
        } else {
            self.output_start += amt;
        }
        debug_assert_invars!(self);
    }

    /// Tests whether the parser is currently stopped at a record boundary.
    #[inline]
    #[must_use]
    pub fn is_record_boundary(&self) -> bool {
        (self.payload_rem | u16::from(self.padding_rem)) == 0
    }

    /// Parses as much of the provided record stream as possible into `dest`.
    ///
    /// `new_input` specifies the number of bytes written into the slice from
    /// `Parser::input_buffer` since the last call to `Parser::parse`. This may
    /// be zero if the last call left some protocol data in the buffer, such as
    /// when `dest` is full.
    ///
    /// If `dest` is [`Some(buf)`], parsed data from the active input stream is
    /// written directly into `buf`. This requires `Parser::stream_buffer` to
    /// be empty. A `dest` of [`None`] appends stream data to
    /// `Parser::stream_buffer`. The number of bytes written, as well as an
    /// end-of-stream indication, is reported in the returned [`Status`].
    ///
    /// # Errors
    /// Returns an [`Error`] if parsing failed irrecoverably. The type's
    /// documentation explains the cause for each error scenario.
    ///
    /// # Panics
    /// `new_input` must not exceed the length of the slice returned by
    /// `Parser::input_buffer`, otherwise an assertion panics. Similarly, an
    /// assertion panics if `dest` is [`Some(buf)`] while `Parser::stream_buffer`
    /// is not empty.
    pub fn parse(
        &mut self,
        new_input: usize,
        mut dest: Option<&mut [u8]>,
    ) -> Result<Status, Error> {
        assert!(
            dest.is_none() || self.parsed_start == self.gap_start,
            "stream_buffer must be fully consumed before parsing into dest is possible",
        );
        assert!(new_input <= self.buffer.len() - self.free_start);
        self.free_start += new_input;

        let mut res = Status { stream: 0, output: 0, stream_end: self.stream.is_none() };
        while self.raw_start < self.free_start {
            if self.payload_rem > 0 {
                #[allow(clippy::collapsible_if)]
                if self.parse_payload(&mut res, &mut dest).is_break() {
                    break;
                }
            }

            if self.padding_rem > 0 {
                debug_assert_eq!(self.payload_rem, 0);
                let raw_len = self.free_start - self.raw_start;
                if raw_len <= self.padding_rem.into() {
                    self.raw_start = self.free_start;
                    self.padding_rem -= raw_len as u8;
                    break;
                }
                self.raw_start += usize::from(self.padding_rem);
                self.padding_rem = 0;
            }

            if self.parse_head(&mut res)?.is_break() {
                break;
            }
        }
        debug_assert_invars!(self);
        Ok(res)
    }

    #[must_use]
    fn parse_payload(&mut self, res: &mut Status, dest: &mut Option<&mut [u8]>) -> ControlFlow {
        let raw_len = self.free_start - self.raw_start;
        let payload_len = min(usize::from(self.payload_rem), raw_len);
        let payload = &self.buffer[self.raw_start..(self.raw_start + payload_len)];

        let consumed = match &mut self.state {
            State::Stream => {
                let read = if let Some(buf) = dest {
                    buf.write(payload).expect("writing into &mut [u8] should always succeed")
                } else {
                    // Move payload directly from <raw> into <parsed>
                    self.buffer.copy_within(
                        self.raw_start..(self.raw_start + payload_len),
                        self.gap_start,
                    );
                    self.gap_start += payload_len;
                    payload_len
                };
                res.stream += read;
                read
            },

            State::Skip => payload_len,

            State::Values { vars } => {
                // See request::GetValuesState<T> for details
                let mut nvit = fcgi::nv::NVIter::new(payload);
                vars.extend((&mut nvit).filter_map(super::parse_nv_var));
                let remaining = nvit.into_inner().len();

                if raw_len < self.payload_rem.into() {
                    payload_len - remaining
                } else {
                    if remaining != 0 {
                        tracing::warn!(bytes = remaining, "GetValues body ends with incomplete name-value pair");
                    }
                    res.output += vars.write_response(&mut self.output, self.config);
                    payload_len
                }
            },
        };
        debug_assert!(consumed <= payload_len);
        self.raw_start += consumed;
        self.payload_rem -= consumed as u16;
        debug_assert_invars!(self);

        if self.payload_rem == 0 && consumed < raw_len {
            Continue(())
        } else {
            Break(())
        }
    }

    fn parse_head(&mut self, res: &mut Status) -> Result<ControlFlow, Error> {
        debug_assert!(self.is_record_boundary());
        let past_head = self.raw_start + fcgi::RecordHeader::LEN;
        if past_head > self.free_start {
            return Ok(Break(()));
        };
        let head = self.buffer[self.raw_start..past_head].try_into()
            .expect("slice should be same length as array");

        let head = match fcgi::RecordHeader::from_bytes(head) {
            Ok(h) => {
                crate::macros::trace!(header = ?h, "record received");
                h
            },
            Err(fcgi::Error::UnknownRecordType(rtype)) => {
                let request_id = u16::from_be_bytes([head[2], head[3]]);
                self.payload_rem = u16::from_be_bytes([head[4], head[5]]);
                self.padding_rem = head[6];
                tracing::info!(request_id, rtype, payload = self.payload_rem, "unknown record type ignored");

                // Report unknown record type to remote
                let unk = fcgi::body::UnknownType { rtype }.to_record(request_id);
                self.output.extend(unk);
                res.output += unk.len();

                // Skip record body
                self.state = State::Skip;
                self.raw_start = past_head;
                return Ok(Continue(()));
            },
            Err(fcgi::Error::UnknownVersion(v)) => return Err(Error::UnknownVersion(v)),
            Err(e) => return Err(Error::Protocol(e)),
        };

        let req_id = self.request.request_id.get();
        self.state = match head.rtype {
            s if s.is_input_stream() && head.request_id == req_id => {
                match cmp_input_streams(self.request.role, s, self.stream) {
                    // Loop around to move stream body
                    Ordering::Equal if head.content_length != 0 => State::Stream,
                    // Skip earlier streams
                    Ordering::Less => State::Skip,
                    // End of stream or later stream, wait for caller to advance
                    _ => {
                        res.stream_end = true;
                        return Ok(Break(()));
                    },
                }
            },
            fcgi::RecordType::AbortRequest if head.request_id == req_id => {
                // Report AbortRequest record to caller, but keep header
                // in self.buffer for subsequent calls.
                return Err(Error::AbortRequest);
            },

            fcgi::RecordType::BeginRequest if head.request_id != req_id => {
                // Report lack of multiplexing to remote
                let endreq = fcgi::body::EndRequest {
                    protocol_status: fcgi::ProtocolStatus::CantMpxConn,
                    app_status: 0,
                }.to_record(head.request_id);
                self.output.extend(endreq);
                res.output += endreq.len();
                // Skip record body
                State::Skip
            },
            fcgi::RecordType::GetValues if head.is_management() => {
                // Loop around to parse GetValues body
                State::Values { vars: fcgi::ProtocolVariables::empty() }
            },
            _ => {
                // Skip unexpected record types
                State::Skip
            },
        };

        self.payload_rem = head.content_length;
        self.padding_rem = head.padding_length;
        self.raw_start = past_head;
        debug_assert_invars!(self);
        Ok(Continue(()))
    }

    /// Consumes the [`Parser`] to extract any buffered input from it.
    ///
    /// # Errors
    /// Returns [`Error::Interrupted`] if called while the [`Parser`] is not
    /// stopped at a record boundary. Use `Parser::is_record_boundary` to test
    /// this condition beforehand, and continue parsing until it returns `true`.
    pub fn into_input(mut self) -> Result<Vec<u8>, Error> {
        if !self.is_record_boundary() {
            return Err(Error::Interrupted);
        }
        self.discard_stream();
        let mut input = Vec::from(self.buffer);
        input.truncate(self.free_start);
        Ok(input)
    }

    /// Converts this [`Parser`] into a [`request::Parser`] to parse a new
    /// [`Request`].
    ///
    /// # Errors
    /// Returns [`Error::Interrupted`] if called while the [`Parser`] is not
    /// stopped at a record boundary. Use `Parser::is_record_boundary` to test
    /// this condition beforehand, and continue parsing until it returns `true`.
    ///
    /// # Panics
    /// `Parser::output_buffer` must be fully consumed before calling this,
    /// otherwise an assertion panics.
    pub fn into_request_parser(mut self) -> Result<request::Parser<'a>, Error> {
        if !self.is_record_boundary() {
            return Err(Error::Interrupted);
        }
        assert!(
            self.output.is_empty(),
            "output_buffer must be fully consumed before converting into request::Parser",
        );
        self.discard_stream();
        Ok(request::Parser::from_parser(self.config, self.buffer, self.free_start, self.output))
    }
}


#[cfg(test)]
mod tests {
    use std::io::prelude::*;
    use strum::IntoEnumIterator;
    use super::super::test_support;
    use super::*;

    #[test]
    fn trait_check() {
        fn ok<T: Send + Unpin>() {}
        ok::<Parser>();
    }

    #[test]
    fn stream_order() {
        for role in fcgi::Role::iter() {
            stream_order_inner(role);
        }
    }

    fn stream_order_inner(role: fcgi::Role) {
        use Ordering::*;
        for s in fcgi::RecordType::iter().filter(|r| r.is_input_stream()) {
            assert_eq!(cmp_input_streams(role, s, None), Less);
            let s_idx = role.input_streams().iter().position(|&i| i == s);

            for (exp_idx, &exp) in role.input_streams().iter().enumerate() {
                let ref_ord = s_idx.map_or(Less, |idx| idx.cmp(&exp_idx));
                assert_eq!(cmp_input_streams(role, s, Some(exp)), ref_ord);
            }
        }
    }

    fn make_parser(config: &Config, req_id: u16, role: fcgi::Role) -> Parser<'_> {
        let body = fcgi::body::BeginRequest { role, flags: fcgi::RequestFlags::all() };
        let mut request = Request::new(req_id.try_into().unwrap(), body);
        request.params = test_support::params_map();
        Parser::new(config, request)
    }

    fn parse_stream(
        parser: &mut Parser,
        input: &mut &[u8],
        mut dest: Option<&mut [u8]>,
    ) -> Result<(usize, usize), Error> {
        let mut stream = 0;
        let mut output = 0;
        loop {
            // Randomly read between 50 and 256 bytes from the input
            // to stress the parser's continuation capabilities
            let buf = parser.input_buffer();
            let rand_len = min(buf.len(), fastrand::usize(50..=256));
            let read = input.read(&mut buf[..rand_len]).unwrap();

            let status = parser.parse(read, dest.as_deref_mut())?;
            stream += status.stream;
            output += status.output;
            dest = if let Some(buf) = dest {
                Some(&mut buf[status.stream..])
            } else {
                parser.consume_stream(status.stream);
                parser.compress();
                None
            };

            if (status.stream_end && parser.active_stream().is_some()) || input.is_empty() {
                break;
            }
        }
        Ok((stream, output))
    }

    #[test]
    fn conversions() {
        const REQ_ID: u16 = 0x9b06;
        let mut buf = Vec::with_capacity(8192);
        test_support::add_begin(&mut buf, REQ_ID);
        test_support::add_params(
            &mut buf, REQ_ID,
            test_support::PARAMS.iter().copied(),
            &[82, 785],
        );
        test_support::add_get_vals(&mut buf, fcgi::FCGI_NULL_REQUEST_ID);
        test_support::add_input(&mut buf, REQ_ID, fcgi::RecordType::Stdin, &[275, 22, 929]);
        test_support::randomize_padding(&mut buf);
        let mut inp = &*buf;

        let config = Config::with_conns(1.try_into().unwrap());
        let mut parser = request::Parser::new(&config);
        loop {
            let read = inp.read(parser.input_buffer()).unwrap();
            let status = parser.parse(read);
            assert_eq!(status.output, b"");
            if status.done || inp.is_empty() {
                break;
            }
        }

        let mut parser = parser.into_stream_parser().expect("request parser failed");
        assert_eq!(parser.request.request_id.get(), REQ_ID);
        assert_eq!(parser.active_stream(), Some(fcgi::RecordType::Stdin));
        assert!(parser.is_record_boundary());

        let (stream, output) =
            parse_stream(&mut parser, &mut inp, None).expect("stream parser failed");
        assert_eq!(stream, 275 + 22 + 929);
        assert_eq!(output, parser.output_buffer().len());
        assert_eq!(parser.output_buffer(), test_support::VALS_RESULT1);
        parser.consume_output(parser.output_buffer().len());

        let _parser: request::Parser =
            parser.into_request_parser().expect("stream parser should be done with request");
    }

    #[test]
    fn multiple_streams() {
        const REQ_ID: u16 = 0xf1d1;
        let mut buf = Vec::with_capacity(8192);
        test_support::add_input(&mut buf, REQ_ID, fcgi::RecordType::Stdin, &[286, 94, 482]);
        test_support::add_input(&mut buf, REQ_ID, fcgi::RecordType::Data, &[173, 1374]);
        test_support::randomize_padding(&mut buf);
        let mut inp = &*buf;

        let config = Config::with_conns(1.try_into().unwrap());
        let mut parser = make_parser(&config, REQ_ID, fcgi::Role::Filter);
        let (stream, output) = parse_stream(&mut parser, &mut inp, None).expect("parser failed");
        assert_eq!(stream, 286 + 94 + 482);
        assert_eq!(output, 0);

        parser.set_stream(Some(fcgi::RecordType::Data)).unwrap();
        let (stream, output) = parse_stream(&mut parser, &mut inp, None).expect("parser failed");
        assert_eq!(stream, 173 + 1374);
        assert_eq!(output, 0);

        let data = parser.into_input().unwrap();
        assert!(data.len() >= fcgi::RecordHeader::LEN);
    }

    #[test]
    fn mid_stream_records() {
        const REQ_ID: u16 = 0x633d;
        let mut mid = Vec::with_capacity(2048);
        test_support::add_begin(&mut mid, REQ_ID);
        test_support::add_get_vals(&mut mid, fcgi::FCGI_NULL_REQUEST_ID);
        test_support::add_input(&mut mid, REQ_ID, fcgi::RecordType::Data, &[827, 22, 327]);

        // Splice additional records between Stdin records
        // Duplicate BeginRequest should be ignored silently
        let mut buf = Vec::with_capacity(8192);
        test_support::add_input(&mut buf, REQ_ID, fcgi::RecordType::Stdin, &[27, 376, 785]);
        let mid_stream = 2 * fcgi::RecordHeader::LEN + 27 + 376;
        buf.splice(mid_stream..mid_stream, mid);
        test_support::randomize_padding(&mut buf);
        let mut inp = &*buf;

        // Should parse until start of Data stream
        let config = Config::with_conns(1.try_into().unwrap());
        let mut parser = make_parser(&config, REQ_ID, fcgi::Role::Filter);
        let (stream, output) = parse_stream(&mut parser, &mut inp, None).expect("parser failed");
        assert_eq!(stream, 27 + 376);
        assert_eq!(output, parser.output_buffer().len());
        assert_eq!(parser.output_buffer(), test_support::VALS_RESULT1);
        parser.consume_output(parser.output_buffer().len());

        // Should parse until Data stream end header
        parser.set_stream(Some(fcgi::RecordType::Data)).unwrap();
        let (stream, output) = parse_stream(&mut parser, &mut inp, None).expect("parser failed");
        assert_eq!(stream, 827 + 22 + 327);
        assert_eq!(output, 0);

        // Should skip all remaining records
        parser.set_stream(None).unwrap();
        let (stream, output) = parse_stream(&mut parser, &mut inp, None).expect("parser failed");
        assert_eq!(stream, 0);
        assert_eq!(output, 0);
        assert_eq!(parser.into_input().unwrap(), b"");
    }

    #[test]
    fn unknown_record() {
        const REQ_ID: u16 = 0x4a62;
        const UNK_50: &[u8; 16] = b"\x01\x0b\x4a\x62\x00\x08\0\0\x50\0\0\0\0\0\0\0";

        let mut mid = Vec::with_capacity(1024);
        test_support::add_unk(&mut mid, REQ_ID, 0x50);
        test_support::add_input(&mut mid, REQ_ID, fcgi::RecordType::Data, &[381]);

        // Splice unknown records between Stdin records
        let mut buf = Vec::with_capacity(8192);
        test_support::add_input(&mut buf, REQ_ID, fcgi::RecordType::Stdin, &[912, 879]);
        let mid_stream = fcgi::RecordHeader::LEN + 912;
        buf.splice(mid_stream..mid_stream, mid);
        test_support::randomize_padding(&mut buf);
        let mut inp = &*buf;

        let config = Config::with_conns(1.try_into().unwrap());
        let mut parser = make_parser(&config, REQ_ID, fcgi::Role::Responder);
        let (stream, output) = parse_stream(&mut parser, &mut inp, None).expect("parser failed");
        assert_eq!(stream, 912 + 879);
        assert_eq!(output, parser.output_buffer().len());
        assert_eq!(parser.output_buffer(), UNK_50);

        let data = parser.into_input().unwrap();
        assert!(data.len() >= fcgi::RecordHeader::LEN);
    }

    #[test]
    fn multiplexed() {
        const REQ_A: u16 = 0x8c16;
        const REQ_B: u16 = 0x386e;
        const END_B: &[u8; 16] = b"\x01\x03\x38\x6e\x00\x08\0\0\0\0\0\0\x01\0\0\0";

        let mut buf = Vec::with_capacity(8192);
        test_support::add_begin(&mut buf, REQ_B);
        test_support::add_params(&mut buf, REQ_B, test_support::PARAMS.iter().copied(), &[89, 278]);
        test_support::add_input(&mut buf, REQ_A, fcgi::RecordType::Stdin, &[83, 1056]);
        test_support::randomize_padding(&mut buf);
        let mut inp = &*buf;

        let mut dest = vec![0; 2048];
        let config = Config::with_conns(1.try_into().unwrap());
        let mut parser = make_parser(&config, REQ_A, fcgi::Role::Responder);

        // Should only parse the first 50 bytes of Stdin
        let (stream, output) =
            parse_stream(&mut parser, &mut inp, Some(&mut dest[..50])).expect("parser failed");
        assert_eq!(stream, 50);
        assert_eq!(output, parser.output_buffer().len());
        assert_eq!(parser.output_buffer(), END_B);
        parser.consume_output(parser.output_buffer().len());

        // Should parse the remainder
        let (stream, output) =
            parse_stream(&mut parser, &mut inp, Some(&mut *dest)).expect("parser failed");
        assert_eq!(stream, 83 + 1056 - 50);
        assert_eq!(output, 0);

        let data = parser.into_input().unwrap();
        assert!(data.len() >= fcgi::RecordHeader::LEN);
    }

    #[test]
    fn fatal_errs() {
        const REQ_ID: u16 = 0x2850;
        let config = Config::with_conns(1.try_into().unwrap());

        let mut buf = Vec::with_capacity(8192);
        test_support::add_input(&mut buf, REQ_ID, fcgi::RecordType::Stdin, &[286, 93, 619]);
        let mid_stream = 2 * fcgi::RecordHeader::LEN + 286 + 93;
        buf.splice(mid_stream..mid_stream, [0x7d, 0x9e, 0xe4, 0xd9, 0x28, 0xab, 0x45, 0x21]);

        let mut inp = &buf[..(mid_stream - 38)];
        let mut parser = make_parser(&config, REQ_ID, fcgi::Role::Responder);
        parse_stream(&mut parser, &mut inp, None).expect("parser failed");
        assert!(matches!(parser.into_input(), Err(Error::Interrupted)));

        let mut inp = &*buf;
        let mut parser = make_parser(&config, REQ_ID, fcgi::Role::Responder);
        let res = parse_stream(&mut parser, &mut inp, None);
        assert!(matches!(res, Err(Error::UnknownVersion(0x7d))));

        buf.truncate(mid_stream);
        test_support::add_abort(&mut buf, REQ_ID);
        let mut inp = &*buf;
        let mut parser = make_parser(&config, REQ_ID, fcgi::Role::Responder);
        let res = parse_stream(&mut parser, &mut inp, None);
        assert!(matches!(res, Err(Error::AbortRequest)));

        let data = parser.into_input().unwrap();
        assert_eq!(data, &buf[mid_stream..]);
    }

    fn set_buflen(parser: &mut Parser, stream: usize, protocol: usize) {
        assert!(stream + protocol < parser.buffer.len());
        parser.parsed_start = 0;
        parser.gap_start = stream;
        parser.raw_start = parser.gap_start;
        parser.free_start = parser.raw_start + protocol;
        debug_assert_invars!(parser);
    }

    #[test]
    fn stream_mgmt() {
        const REQ_ID: u16 = 0x7aed;
        let config = Config::with_conns(1.try_into().unwrap());

        for role in fcgi::Role::iter() {
            let mut parser = make_parser(&config, REQ_ID, role);
            let mut streams = role.input_streams().iter().map(|&r| Some(r)).chain([None]);
            let mut cur = streams.next().unwrap();
            assert_eq!(parser.active_stream(), cur);

            set_buflen(&mut parser, 100, 0);
            parser.set_stream(cur)
                .expect("Parser should always accept current stream");
            assert_eq!(parser.stream_buffer().len(), 100);

            for s in fcgi::RecordType::iter() {
                if s.is_input_stream() && !role.input_streams().contains(&s) {
                    parser.set_stream(Some(s))
                        .expect_err(&format!("Parser accepted stream {s:?} for {role:?}"));
                    assert_eq!(parser.active_stream(), cur);
                    assert_eq!(parser.stream_buffer().len(), 100);
                }
            }

            for next in streams {
                set_buflen(&mut parser, 100, 0);
                parser.set_stream(next).unwrap_or_else(
                    |e| panic!("Parser should accept stream {next:?} for {role:?}: {e:?}")
                );
                assert_eq!(parser.active_stream(), next);
                assert_eq!(parser.stream_buffer().len(), 0);

                parser.set_stream(cur)
                    .expect_err(&format!("Parser accepted stream {cur:?} after stream {next:?}"));
                assert_eq!(parser.active_stream(), next);
                cur = next;
            }
        }
    }

    #[test]
    fn buffer_mgmt() {
        const REQ_ID: u16 = 0x0d44;
        let config = Config::with_conns(1.try_into().unwrap());
        let mut parser = make_parser(&config, REQ_ID, fcgi::Role::Responder);
        fastrand::fill(&mut parser.buffer);

        parser.parsed_start = 10;
        parser.gap_start = 210;
        parser.raw_start = 495;
        parser.free_start = 500;
        parser.output = test_support::random_bytes(80);
        parser.output_start = 30;
        debug_assert_invars!(parser);
        let free_len = parser.input_buffer().len();

        let data = parser.stream_buffer().to_owned();
        assert_eq!(data.len(), 200);
        parser.consume_stream(75);
        assert_eq!(parser.stream_buffer(), &data[75..]);

        parser.compress();
        assert_eq!(parser.parsed_start, 0);
        assert_eq!(parser.raw_start, parser.gap_start);
        assert!(parser.input_buffer().len() >= free_len + 75);
        assert_eq!(parser.stream_buffer(), &data[75..]);

        let data = parser.output_buffer().to_owned();
        assert_eq!(data.len(), 50);
        parser.consume_output(27);
        assert_eq!(parser.output_buffer(), &data[27..]);

        parser.consume_output(parser.output_buffer().len());
        assert_eq!(parser.output_start, 0);
        assert_eq!(parser.output_buffer(), b"");
    }
}
