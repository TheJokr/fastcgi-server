use std::cmp::Ordering;
use std::io::Write;
use std::ops::ControlFlow::{Break, Continue};

use super::{request, Error, Request};
use crate::protocol as fcgi;
use crate::Config;


type ControlFlow = std::ops::ControlFlow<()>;

/// An output report from `Parser::parse`.
#[derive(Debug, Clone, Copy)]
pub struct Status {
    /// The number of bytes written into `dest` (or `Parser::stream_buffer`,
    /// if the former is [`None`]).
    pub stream: usize,

    /// Indicates whether the active input stream reached its end.
    ///
    /// If `true`, future calls to `Parser::parse` will not yield additional
    /// stream data until the next stream (if any) is activated via
    /// `Parser::set_stream`. If the active stream is already [`None`], this
    /// marks the end of the [`Request`].
    ///
    /// Otherwise, all buffered protocol data has been parsed. New input must
    /// be supplied into the slice returned by `Parser::input_buffer` before
    /// the next call to `Parser::parse`.
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
    // None is never followed by anything
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
/// At any time, the parser maintains an active input stream. It is set to
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
    ///
    /// Uses a default internal buffer size which is suitable for most FastCGI
    /// clients and balances overheads with memory usage.
    #[inline]
    pub fn new(config: &'a Config, request: Request) -> Self {
        Self::with_buffer(super::DEFAULT_BUF_SIZE, config, request)
    }

    /// Creates a new [`Parser`] for the given configuration, [`Request`], and
    /// internal buffer size.
    ///
    /// See `request::Parser::with_buffer` for some hints on buffer sizing.
    pub fn with_buffer(buffer_size: usize, config: &'a Config, request: Request) -> Self {
        let buffer_size = super::aligned_buf_size(buffer_size);
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
    /// valid input stream type for the request's [`Role`], or the [`Role`]
    /// requires `stream` to precede `Parser::active_stream`. The correct order
    /// is given by `Role::input_streams`.
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
        self.parsed_start += std::cmp::min(amt, parsed_len);
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
    /// mutating method on this [`Parser`] in between.
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
    /// after fully consuming `Parser::stream_buffer`.
    pub fn compress(&mut self) {
        if 0 < self.parsed_start && self.parsed_start < self.gap_start {
            self.buffer.copy_within(self.parsed_start..self.gap_start, 0);
        }
        // [parsed_start, gap_start) moved to [0, gap_start - parsed_start)
        self.gap_start -= std::mem::take(&mut self.parsed_start);

        if self.gap_start < self.raw_start && self.raw_start < self.free_start {
            self.buffer.copy_within(self.raw_start..self.free_start, self.gap_start);
        }
        // [raw_start, free_start) moved to [gap_start, free_start - (raw_start - gap_start))
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
    /// `Parser::input_buffer` since the last call to `Parser::parse`. Progress
    /// is only possible if this number is larger than zero.
    ///
    /// If `dest` is [`Some(buf)`], parsed data from the active input stream is
    /// written directly into `buf`. This requires `Parser::stream_buffer` to
    /// be empty. Otherwise, stream data is appended to `Parser::stream_buffer`.
    /// The number of bytes written, as well as an end-of-stream indication, is
    /// reported in the returned [`Status`].
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
        let payload_len = std::cmp::min(usize::from(self.payload_rem), raw_len);
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
                // See super::GetValuesState<T> for details
                let mut nvit = fcgi::nv::NVIter::new(payload);
                vars.extend(
                    (&mut nvit).filter_map(|(n, _)| fcgi::ProtocolVariables::parse_name(n).ok()),
                );
                if raw_len < self.payload_rem.into() {
                    payload_len - nvit.into_inner().len()
                } else {
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
        let Some(head) = self.buffer.get(self.raw_start..past_head) else {
            return Ok(Break(()));
        };
        let head = head.try_into().expect("slice should be same length as array");

        let head = match fcgi::RecordHeader::from_bytes(head) {
            Ok(h) => h,
            Err(fcgi::Error::UnknownRecordType(rtype)) => {
                let request_id = u16::from_be_bytes([head[2], head[3]]);
                self.payload_rem = u16::from_be_bytes([head[4], head[5]]);
                self.padding_rem = head[6];

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
    use strum::IntoEnumIterator;
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
}
