use std::cmp::{max, min};
use std::num::NonZeroU16;
use std::ops::ControlFlow::{Break, Continue};

use compact_str::CompactString;

use super::{stream, Error, Request, SmallBytes};
use crate::cgi;
use crate::protocol as fcgi;
use crate::Config;


type ControlFlow<T> = std::ops::ControlFlow<T, T>;
type SResult<'a> = (&'a mut [u8], State);
type PResult<'a> = ControlFlow<SResult<'a>>;

trait StateBuilder: Sized {
    fn into_state(self) -> State;
    fn wrap_skip(skip: SkipState<Self>) -> State;
    fn wrap_values(vals: GetValuesState<Self>) -> State;

    fn into_skip(self, payload_rem: u16, padding_rem: u8) -> State {
        if (payload_rem | u16::from(padding_rem)) == 0 {
            self.into_state()
        } else {
            Self::wrap_skip(SkipState { next: self, payload_rem, padding_rem })
        }
    }
}


#[derive(Debug, Clone)]
struct SkipState<T> {
    next: T,
    payload_rem: u16,
    padding_rem: u8,
}

impl<T: StateBuilder> SkipState<T> {
    fn drive(mut self, data: &mut [u8]) -> PResult<'_> {
        let payload = usize::from(self.payload_rem);
        let (total, overflow) = match payload.checked_add(self.padding_rem.into()) {
            Some(t) => (t, false),
            None => (payload, true),
        };

        if let Some(new_payload_rem @ 1..) = payload.checked_sub(data.len()) {
            self.payload_rem = new_payload_rem as u16;
            Break((&mut [], T::wrap_skip(self)))
        } else if overflow || data.len() < total {
            // data.len() < payload + self.padding_rem holds here regardless of overflow.
            // Thus, data.len() - payload < self.padding_rem (u8) and the cast is safe.
            self.padding_rem -= (data.len() - payload) as u8;
            self.payload_rem = 0;
            Break((&mut [], T::wrap_skip(self)))
        } else /* data.len() >= total */ {
            Continue((&mut data[total..], self.next.into_state()))
        }
    }
}


#[derive(Debug, Clone)]
struct GetValuesState<T> {
    next: T,
    vars: fcgi::ProtocolVariables,
    payload_rem: u16,
    padding_rem: u8,
}

impl<T: StateBuilder> GetValuesState<T> {
    fn new(next: T, payload_rem: u16, padding_rem: u8) -> Self {
        Self { next, vars: fcgi::ProtocolVariables::empty(), payload_rem, padding_rem }
    }

    fn drive<'a>(
        mut self,
        mut data: &'a mut [u8],
        out: &mut Vec<u8>,
        config: &Config,
    ) -> PResult<'a> {
        if self.payload_rem > 0 {
            let len = min(data.len(), self.payload_rem.into());
            let mut nvit = fcgi::nv::NVIter::new(&data[..len]);
            self.vars.extend((&mut nvit).filter_map(super::parse_nv_var));
            let remaining = nvit.into_inner().len();

            if data.len() < self.payload_rem.into() {
                // Wait for future payload bytes
                let consumed = len - remaining;
                self.payload_rem -= consumed as u16;
                return Break((&mut data[consumed..], T::wrap_values(self)));
            }

            // Payload is complete. Ignore any incomplete trailing data.
            if remaining != 0 {
                tracing::warn!(bytes = remaining, "GetValues body ends with incomplete name-value pair");
            }
            data = &mut data[self.payload_rem.into()..];
            self.payload_rem = 0;
            self.vars.write_response(out, config);
        }

        if data.len() < self.padding_rem.into() {
            self.padding_rem -= data.len() as u8;
            Break((&mut [], T::wrap_values(self)))
        } else {
            Continue((&mut data[self.padding_rem.into()..], self.next.into_state()))
        }
    }
}


macro_rules! to_array {
    ($s:ident, $inp:ident, $siz:expr) => (to_array!($s, $inp, 0, $siz));
    ($s:ident, $inp:ident, $off:expr, $siz:expr) => {
        match $inp.get($off..($off + $siz)) {
            Some(s) => <[u8; $siz]>::try_from(s).expect("slice should be same length as array"),
            None => return Break(($inp, $s.into_state())),
        }
    };
}

macro_rules! fatal {
    ($inp:expr, $err:expr) => {
        return Break(($inp, State::Fatal($err)))
    };
}

macro_rules! try_head {
    ($s:ident, $inp:ident, $out:ident) => {{
        let head = to_array!($s, $inp, fcgi::RecordHeader::LEN);
        match fcgi::RecordHeader::from_bytes(head) {
            Ok(h) => {
                $crate::macros::trace!(header = ?h, "record received");
                h
            },
            Err(fcgi::Error::UnknownRecordType(rtype)) => {
                let request_id = u16::from_be_bytes([head[2], head[3]]);
                let payload = u16::from_be_bytes([head[4], head[5]]);
                let padding = head[6];
                ::tracing::info!(request_id, rtype, payload, "unknown record type ignored");

                // Report unknown record type to remote
                $out.extend(fcgi::body::UnknownType { rtype }.to_record(request_id));
                // Skip record body
                let skip = $s.into_skip(payload, padding);
                return Continue((&mut $inp[fcgi::RecordHeader::LEN..], skip));
            },
            Err(fcgi::Error::UnknownVersion(v)) => fatal!($inp, Error::UnknownVersion(v)),
            Err(e) => fatal!($inp, Error::Protocol(e)),
        }
    }};
}


#[derive(Debug, Clone)]
struct HeaderState;

impl HeaderState {
    fn drive<'a>(self, data: &'a mut [u8], out: &mut Vec<u8>) -> PResult<'a> {
        let head = try_head!(self, data, out);
        match head.rtype {
            fcgi::RecordType::BeginRequest => { /* Handled below */ },
            fcgi::RecordType::GetValues if head.is_management() => {
                // Transition to GetValuesState for body
                let vals = GetValuesState::new(self, head.content_length, head.padding_length);
                return Continue((&mut data[fcgi::RecordHeader::LEN..], Self::wrap_values(vals)));
            },
            _ => {
                // Skip unexpected record types
                let skip = self.into_skip(head.content_length, head.padding_length);
                return Continue((&mut data[fcgi::RecordHeader::LEN..], skip));
            },
        };

        if fcgi::body::BeginRequest::LEN != head.content_length.into() {
            fatal!(data, Error::InvalidRequestLen(head.content_length));
        }
        let body_arr =
            to_array!(self, data, fcgi::RecordHeader::LEN, fcgi::body::BeginRequest::LEN);
        let data = &mut data[(fcgi::RecordHeader::LEN + fcgi::body::BeginRequest::LEN)..];

        let body = match fcgi::body::BeginRequest::from_bytes(body_arr) {
            Ok(b) => b,
            Err(fcgi::Error::UnknownRole(role)) => {
                tracing::info!(request_id = head.request_id, role, "unknown role rejected");
                // Report unknown role type to remote
                out.extend(fcgi::body::EndRequest {
                    protocol_status: fcgi::ProtocolStatus::UnknownRole,
                    app_status: 0,
                }.to_record(head.request_id));
                // Handle padding
                let skip = self.into_skip(0, head.padding_length);
                return Continue((data, skip));
            },
            Err(e) => fatal!(data, Error::Protocol(e)),
        };

        // Parse the request's Params stream in ParamsState
        let Some(req_id) = NonZeroU16::new(head.request_id) else {
            fatal!(data, Error::NullRequest);
        };
        tracing::debug!(request_id = req_id, ?body, "new request received");
        let inner = ParamsStateInner::new(Request::new(req_id, body));
        let params = ParamsState { inner, payload_rem: 0, padding_rem: head.padding_length };
        Continue((data, params.into_state()))
    }
}

impl StateBuilder for HeaderState {
    fn into_state(self) -> State {
        State::Header(self)
    }
    fn wrap_skip(skip: SkipState<Self>) -> State {
        State::HeaderSkip(skip)
    }
    fn wrap_values(vals: GetValuesState<Self>) -> State {
        State::HeaderValues(vals)
    }
}


#[derive(Debug, Clone)]
struct ParamsStateInner {
    req: Request,
    buffer: Vec<u8>,
}

macro_rules! try_fill {
    ($vec:expr, $inp:ident, $len:expr, $must_move:expr) => {
        if let Some(needed @ 1..) = $len.checked_sub($vec.len()) {
            if $inp.len() >= needed {
                let head;
                (head, $inp) = $inp.split_at_mut(needed);
                $vec.extend(&*head);
            } else if $must_move {
                $vec.extend(&*$inp);
                return &mut [];
            } else {
                return $inp;
            }
        }
    };
}

impl ParamsStateInner {
    fn new(req: Request) -> Self {
        Self { req, buffer: Vec::new() }
    }

    /// Parses a single name-value pair with partial data in self.buffer.
    ///
    /// This function is very similar in purpose to [`NVIter`], but handles the
    /// case where a name-value pair is split between multiple Params stream
    /// records.
    ///
    /// self.buffer **must not** be empty when calling
    /// `ParamsStateInner::parse_buffered`!
    fn parse_buffered<'a>(&mut self, mut data: &'a mut [u8], rec_end: bool) -> &'a mut [u8] {
        // Move the length header (two VarInts) into the buffer
        let head_len = 2 + usize::from(self.buffer[0] >> 7) * 3;
        try_fill!(self.buffer, data, head_len, rec_end);
        let head_len = head_len + usize::from(self.buffer[head_len - 1] >> 7) * 3;
        try_fill!(self.buffer, data, head_len, rec_end);

        let mut cur = &*self.buffer;
        let name_len = fcgi::varint::VarInt::read(&mut cur)
            .expect("both VarInts should be in the buffer");
        let val_len = fcgi::varint::VarInt::read(&mut cur)
            .expect("both VarInts should be in the buffer");

        let body_buffered = cur.len();
        debug_assert_eq!(head_len, self.buffer.len() - body_buffered);
        let head_len = self.buffer.len() - body_buffered;

        let (name_len, val_len, val_start, body_len) = (|| {
            let name_len = name_len.try_into().ok()?;
            let val_len = val_len.try_into().ok()?;
            let val_start = head_len.checked_add(name_len)?;
            let body_len = name_len.checked_add(val_len)?;
            Some((name_len, val_len, val_start, body_len))
        })().expect("name-value pair overflowed usize");

        // Wait for sufficient data to extract both name and value
        if body_buffered.saturating_add(data.len()) < body_len {
            if rec_end {
                self.buffer.extend(&*data);
                return &mut [];
            }
            return data;
        }

        let name = if body_buffered == 0 {
            // Name is fully contained in the data slice. Since we moved the
            // length header into self.buffer, name must be at the start of data.
            let raw;
            (raw, data) = data.split_at_mut(name_len);
            raw
        } else {
            // Name is (partially) contained in self.buffer. Move
            // the remainder, but keep value in the data slice.
            try_fill!(self.buffer, data, val_start, rec_end);
            &mut self.buffer[head_len..val_start]
        };
        let name = Self::make_cgivar(name);

        // Unlike name, we treat value as raw bytes and can
        // thus easily compose it from multiple sources.
        let mut val = SmallBytes::with_capacity(val_len);
        if let Some(buffered @ [_, ..]) = self.buffer.get(val_start..) {
            // First, copy any value bytes left in self.buffer
            val.extend_from_slice(buffered);
        }
        if let Some(missing @ 1..) = val_len.checked_sub(val.len()) {
            // Then, copy the remainder from the data slice. It
            // must be at the start of data after extracting name.
            let raw;
            (raw, data) = data.split_at_mut(missing);
            val.extend_from_slice(raw);
        }

        self.req.params.insert(name, val);
        self.buffer.clear();
        data
    }

    /// Lossily converts raw bytes into a (UTF-8 based) [`cgi::OwnedVarName`].
    ///
    /// Valid CGI/1.1 variable names are ASCII-only, but we support invalid
    /// ones as much as possible by replacing non-UTF-8 codepoints.
    #[must_use]
    fn make_cgivar(name: &[u8]) -> cgi::OwnedVarName {
        let conv = CompactString::from_utf8_lossy(name);
        if tracing::event_enabled!(tracing::Level::DEBUG) && name != conv.as_bytes() {
            tracing::debug!(
                original = %name.escape_ascii(), converted = %conv.escape_default(),
                "lossy CGI/1.1 variable name conversion",
            );
        }
        cgi::OwnedVarName::from_compact(conv)
    }

    /// Parses the request's name-value Params stream, taking care to handle
    /// record boundaries.
    fn parse_stream(&mut self, mut data: &mut [u8], rec_end: bool) -> usize {
        let len = data.len();
        if !self.buffer.is_empty() {
            data = self.parse_buffered(data, rec_end);
            if !self.buffer.is_empty() {
                return len - data.len();
            }
        }

        let mut nvit = fcgi::nv::NVIter::new(data);
        self.req.params.extend((&mut nvit).map(
            |(n, v)| (Self::make_cgivar(n), SmallBytes::from_slice(v)),
        ));
        data = nvit.into_inner();

        if rec_end && !data.is_empty() {
            // Reserve sufficient space for name-value pair's length header and name
            self.buffer.reserve(max(data.len(), 64));
            self.buffer.extend(&*data);
            crate::macros::trace!(
                request_id = self.req.request_id,
                buffered = self.buffer.len(), allocated = self.buffer.capacity(),
                "Params name-value pair crossed record boundary",
            );
            len
        } else {
            len - data.len()
        }
    }
}

#[derive(Debug, Clone)]
struct ParamsState {
    inner: ParamsStateInner,
    payload_rem: u16,
    padding_rem: u8,
}

impl ParamsState {
    fn drive<'a>(mut self, mut data: &'a mut [u8], out: &mut Vec<u8>) -> PResult<'a> {
        if self.payload_rem > 0 {
            if data.len() < self.payload_rem.into() {
                let consumed = self.inner.parse_stream(data, false);
                self.payload_rem -= consumed as u16;
                return Break((&mut data[consumed..], self.into_state()));
            }

            let payload;
            (payload, data) = data.split_at_mut(self.payload_rem.into());
            let consumed = self.inner.parse_stream(payload, true);
            debug_assert_eq!(consumed, self.payload_rem.into());
            self.payload_rem = 0;
        }

        if self.padding_rem > 0 {
            if data.len() <= self.padding_rem.into() {
                self.padding_rem -= data.len() as u8;
                return Break((&mut [], self.into_state()));
            }
            data = &mut data[self.padding_rem.into()..];
            self.padding_rem = 0;
        }

        let head = try_head!(self, data, out);
        data = &mut data[fcgi::RecordHeader::LEN..];
        let req_id = self.inner.req.request_id.get();

        match head.rtype {
            fcgi::RecordType::Params if head.request_id == req_id => {
                if head.content_length == 0 {
                    // Params stream is finished, now return the parsed Request
                    if let bytes @ 1.. = self.inner.buffer.len() {
                        tracing::warn!(bytes, "Params stream ends with incomplete name-value pair");
                    }
                    let done = self.inner.req.into_skip(0, head.padding_length);
                    return Continue((data, done));
                }
                // Loop around to parse stream record body
                self.payload_rem = head.content_length;
                self.padding_rem = head.padding_length;
                Continue((data, self.into_state()))
            },
            fcgi::RecordType::AbortRequest if head.request_id == req_id => {
                tracing::debug!(request_id = req_id, "request aborted mid-Params");
                // Report that request was aborted to remote
                out.extend(fcgi::body::EndRequest {
                    protocol_status: fcgi::ProtocolStatus::RequestComplete,
                    app_status: 0,
                }.to_record(req_id));
                // Return to initial HeaderState
                let initial = HeaderState.into_skip(head.content_length, head.padding_length);
                Continue((data, initial))
            },

            fcgi::RecordType::BeginRequest if head.request_id != req_id => {
                // Report lack of multiplexing to remote
                out.extend(fcgi::body::EndRequest {
                    protocol_status: fcgi::ProtocolStatus::CantMpxConn,
                    app_status: 0,
                }.to_record(head.request_id));
                // Skip record body
                let skip = self.into_skip(head.content_length, head.padding_length);
                Continue((data, skip))
            },
            fcgi::RecordType::GetValues if head.is_management() => {
                // Transition to GetValuesState for body
                let next = self.inner;
                let vals = GetValuesState::new(next, head.content_length, head.padding_length);
                Continue((data, State::ParamsValues(vals)))
            },
            _ => {
                // Skip unexpected record types
                let skip = self.into_skip(head.content_length, head.padding_length);
                Continue((data, skip))
            },
        }
    }

    fn into_state(self) -> State {
        State::Params(self)
    }
    fn into_skip(self, payload_rem: u16, padding_rem: u8) -> State {
        // Skipping only makes sense outside of stream record bodies
        debug_assert_eq!(self.payload_rem, 0);
        debug_assert_eq!(self.padding_rem, 0);
        self.inner.into_skip(payload_rem, padding_rem)
    }
}

// We only need to pass ParamsStateInner through wrappers, not the entire
// ParamsState. This reduces the overall size of the State enum.
impl StateBuilder for ParamsStateInner {
    fn into_state(self) -> State {
        State::Params(ParamsState { inner: self, payload_rem: 0, padding_rem: 0 })
    }
    fn wrap_skip(skip: SkipState<Self>) -> State {
        State::ParamsSkip(skip)
    }
    fn wrap_values(vals: GetValuesState<Self>) -> State {
        State::ParamsValues(vals)
    }
}


// Allow completed Request to consume padding from final Params record
impl StateBuilder for Request {
    fn into_state(self) -> State {
        State::Done(self)
    }
    fn wrap_skip(skip: SkipState<Self>) -> State {
        State::DoneSkip(skip)
    }
    fn wrap_values(_: GetValuesState<Self>) -> State {
        unimplemented!("completed Request may only be wrapped in SkipState");
    }
}


#[derive(Debug, Clone)]
enum State {
    Header(HeaderState),
    HeaderSkip(SkipState<HeaderState>),
    HeaderValues(GetValuesState<HeaderState>),
    Params(ParamsState),
    ParamsSkip(SkipState<ParamsStateInner>),
    ParamsValues(GetValuesState<ParamsStateInner>),
    DoneSkip(SkipState<Request>),
    Done(Request),
    Fatal(Error),
}

impl State {
    fn drive<'a>(
        mut self,
        mut data: &'a mut [u8],
        out: &mut Vec<u8>,
        config: &Config,
    ) -> SResult<'a> {
        use State::*;
        loop {
            let next = match self {
                Done(_) | Fatal(_) => return (data, self),
                Header(s) => s.drive(data, out),
                HeaderSkip(s) => s.drive(data),
                HeaderValues(s) => s.drive(data, out, config),
                Params(s) => s.drive(data, out),
                ParamsSkip(s) => s.drive(data),
                ParamsValues(s) => s.drive(data, out, config),
                DoneSkip(s) => s.drive(data),
            };
            (data, self) = match next {
                Break(r) => return r,
                Continue(r) if r.0.is_empty() => return r,
                Continue(r) => r,
            };
        }
    }
}


/// An intermediate result emitted by `Parser::parse` when action is required
/// from the caller.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
#[must_use = "Yield may contain output, which must be written out"]
pub struct Yield<'a> {
    /// Indicates whether the [`Parser`] reached a final parsing state.
    ///
    /// If `true`, future calls to `Parser::parse` do not change the state of the
    /// parser any further. The parser's result, either a [`Request`] with
    /// leftover input or an [`Error`], may be retrieved via
    /// `Parser::into_request`. Alternatively, the [`Parser`] may be converted
    /// into a [`stream::Parser`] via `Parser::into_stream_parser`.
    ///
    /// Otherwise, the parser yielded to the caller to request additional input.
    /// Input must be supplied into the slice returned by `Parser::input_buffer`
    /// before the next call to `Parser::parse`.
    pub done: bool,

    /// Output generated by the parser during parsing, which may be empty.
    ///
    /// If `output` is not empty, the caller must send its contents to the
    /// FastCGI client *before* the next call to `Parser::parse`. The underlying
    /// buffer will be overwritten by future calls to `Parser::parse`.
    pub output: &'a [u8],
}


/// A parser which extracts a FastCGI [`Request`] from a caller-provided
/// record stream.
///
/// The caller must feed the record stream into the parser's internal buffer,
/// which is available via `Parser::input_buffer`. After reading `n` bytes
/// into this slice, `Parser::parse(n)` processes the bytes and returns an
/// intermediate [`Yield`] value. The [`Yield`] may contain output bytes, which
/// must be sent to the FastCGI client before the next `Parser::parse` call.
/// This process is repeated until the [`Yield`] indicates that the parser is
/// done. Finally, the parser is consumed to return the [`Request`] (or an
/// [`Error`]).
#[derive(Debug, Clone)]
#[must_use = "Parser must be invoked to consume input"]
pub struct Parser<'a> {
    config: &'a Config,
    input: Box<[u8]>,
    input_len: usize,
    output: Vec<u8>,
    state: State,
}

impl<'a> Parser<'a> {
    /// Creates a new [`Parser`] with the given configuration.
    pub fn new(config: &'a Config) -> Self {
        let buffer_size = config.aligned_bufsize();
        let buffer = vec![0; buffer_size].into_boxed_slice();
        Self::from_parser(config, buffer, 0, Vec::with_capacity(256))
    }

    /// Creates a new [`Parser`] from another parser's existing buffers.
    #[inline]
    pub(super) fn from_parser(
        config: &'a Config,
        buffer: Box<[u8]>,
        input_len: usize,
        output: Vec<u8>,
    ) -> Self {
        debug_assert!(output.is_empty(), "output buffer not empty, contents would be lost");
        Self { config, input: buffer, input_len, output, state: State::Header(HeaderState) }
    }

    /// Returns the slice of the parser's internal buffer into which new input
    /// must be written.
    ///
    /// The number of bytes actually written, such as by [`Read::read`][read],
    /// is later passed to `Parser::parse`.
    ///
    /// [read]: std::io::Read::read
    #[inline]
    #[must_use]
    pub fn input_buffer(&mut self) -> &mut [u8] {
        &mut self.input[self.input_len..]
    }

    /// Moves the last `rem_len` bytes from the input buffer to the front,
    /// discarding anything else.
    fn move_input(&mut self, rem_len: usize) {
        let used_len = self.input_len.checked_sub(rem_len)
            .expect("remaining input after State::drive() exceeds original input");
        if 0 < used_len && used_len < self.input_len {
            self.input.copy_within(used_len..self.input_len, 0);
            crate::macros::trace!(freed = used_len, "buffer compressed");
        }
        self.input_len = rem_len;
    }

    /// Parses as much of the provided record stream as possible, resulting in
    /// an intermediate [`Yield`].
    ///
    /// `new_input` specifies the number of bytes written into the slice from
    /// `Parser::input_buffer` since the last call to `Parser::parse`. Progress
    /// is only possible if this number is larger than zero.
    ///
    /// The returned [`Yield`] specifies whether the parser has finished parsing
    /// a [`Request`], or whether more input is required. It also carries output
    /// bytes to be sent to the FastCGI client. Refer to its documentation for
    /// details.
    ///
    /// # Panics
    /// `new_input` must not exceed the length of the slice returned by
    /// `Parser::input_buffer`, otherwise an assertion panics.
    pub fn parse(&mut self, new_input: usize) -> Yield {
        assert!(new_input <= self.input.len() - self.input_len);
        self.input_len += new_input;
        self.output.clear();

        let data = &mut self.input[..self.input_len];
        let rem = replace_with::replace_with_and_return(
            &mut self.state, || State::Fatal(Error::Paniced),
            |s| s.drive(data, &mut self.output, self.config),
        );
        let rem_len = rem.len();
        self.move_input(rem_len);

        let mut done = matches!(self.state, State::Done(_) | State::Fatal(_));
        if !done && self.input_len == self.input.len() {
            self.state = State::Fatal(Error::StuckOnInput);
            done = true;
        }
        Yield { done, output: &self.output }
    }

    /// Consumes the [`Parser`] to extract a parsed [`Request`] and leftover
    /// input from it.
    ///
    /// # Errors
    /// Returns an [`Error`] if parsing failed irrecoverably. Otherwise, returns
    /// [`Error::Interrupted`] if called before `Parser::parse` indicated that
    /// the [`Parser`] is done.
    pub fn into_request(self) -> Result<(Request, Vec<u8>), Error> {
        let request = match self.state {
            State::Done(r) => r,
            State::Fatal(e) => return Err(e),
            _ => return Err(Error::Interrupted),
        };
        let mut input = Vec::from(self.input);
        input.truncate(self.input_len);
        Ok((request, input))
    }

    /// Converts this [`Parser`] into a [`stream::Parser`] for the parsed
    /// [`Request`].
    ///
    /// # Errors
    /// Returns an [`Error`] if parsing failed irrecoverably. Otherwise, returns
    /// [`Error::Interrupted`] if called before `Parser::parse` indicated that
    /// the [`Parser`] is done.
    pub fn into_stream_parser(mut self) -> Result<stream::Parser<'a>, Error> {
        let request = match self.state {
            State::Done(r) => r,
            State::Fatal(e) => return Err(e),
            _ => return Err(Error::Interrupted),
        };
        self.output.clear();
        Ok(stream::Parser::from_parser(
            self.config,
            request,
            self.input,
            self.input_len,
            self.output,
        ))
    }
}


#[cfg(test)]
mod tests {
    use std::io::prelude::*;
    use super::super::test_support;
    use super::*;

    #[test]
    fn trait_check() {
        fn ok<T: Send + Unpin>() {}
        ok::<Parser>();
    }

    #[track_caller]
    fn check_request(request: &Request, req_id: u16) {
        assert_eq!(request.request_id.get(), req_id);
        assert_eq!(request.role, fcgi::Role::Responder);
        assert_eq!(request.flags, fcgi::RequestFlags::all());
        assert!(matches!(request.get_var_str(cgi::GATEWAY_INTERFACE.into()), Some("CGI/1.1")));
        assert!(matches!(
            request.get_var_str("HTTP_X_INVAL��_HEAD".into()),
            Some("az%baqw&W2bAbwA"),
        ));
        assert_eq!(request.params, test_support::params_map());
    }

    type IntoRequest = Result<(Request, Vec<u8>), Error>;
    fn run_parser(mut parser: Parser, mut input: &[u8]) -> (IntoRequest, Vec<u8>) {
        let mut output = Vec::with_capacity(256);
        loop {
            // Randomly read between 50 and 256 bytes from the input
            // to stress the parser's continuation capabilities
            let buf = parser.input_buffer();
            let rand_len = min(buf.len(), fastrand::usize(50..=256));
            let read = input.read(&mut buf[..rand_len]).unwrap();

            let status = parser.parse(read);
            output.extend(status.output);
            if status.done || input.is_empty() {
                break;
            }
        }
        (parser.into_request(), output)
    }

    #[test]
    fn regular() {
        const REQ_ID: u16 = 0x2751;
        let mut inp = Vec::with_capacity(8192);
        test_support::add_get_vals(&mut inp, fcgi::FCGI_NULL_REQUEST_ID);
        test_support::add_begin(&mut inp, REQ_ID);
        test_support::add_params(
            &mut inp, REQ_ID,
            test_support::PARAMS.iter().copied(),
            &[20, 172, 39, 27, 103, 92],
        );
        test_support::randomize_padding(&mut inp);
        inp.extend(test_support::BYTES);  // opaque trailing data

        let config = Config::with_conns(1.try_into().unwrap());
        let (res, out) = run_parser(Parser::new(&config), &inp);
        let (request, data) = res.expect("parser failed");

        // Trailing data may not have been read in its entirety
        assert!(data.len() <= test_support::BYTES.len());
        assert_eq!(data, &test_support::BYTES[..data.len()]);
        assert_eq!(out, test_support::VALS_RESULT1);
        check_request(&request, REQ_ID);
    }

    #[test]
    fn abort_retry() {
        const REQ_A: u16 = 0x14f3;
        const REQ_B: u16 = 0xb358;
        const ABORT_A: &[u8; 16] = b"\x01\x03\x14\xf3\x00\x08\0\0\0\0\0\0\0\0\0\0";

        let mut inp = Vec::with_capacity(8192);
        test_support::add_begin(&mut inp, REQ_A);

        // Add params, then delete all but a few records to simulate abort mid-stream
        let params_start = inp.len();
        test_support::add_params(&mut inp, REQ_A, test_support::PARAMS.iter().copied(), &[25, 25]);
        inp.drain((params_start + 2 * fcgi::RecordHeader::LEN + 2 * 25)..);

        test_support::add_abort(&mut inp, REQ_A);
        test_support::add_begin(&mut inp, REQ_B);
        test_support::add_params(
            &mut inp, REQ_B,
            test_support::PARAMS.iter().copied(),
            &[182, 316, 275],
        );
        test_support::randomize_padding(&mut inp);

        let config = Config::with_conns(1.try_into().unwrap());
        let (res, out) = run_parser(Parser::new(&config), &inp);
        let (request, data) = res.expect("parser failed");

        assert_eq!(data, b"");
        assert_eq!(out, ABORT_A);
        check_request(&request, REQ_B);
    }

    #[test]
    fn mid_stream_records() {
        const REQ_ID: u16 = 1;
        let mut inp = Vec::with_capacity(8192);
        test_support::add_get_vals(&mut inp, fcgi::FCGI_NULL_REQUEST_ID);
        test_support::add_begin(&mut inp, REQ_ID);
        let dupes = inp.clone();

        // Splice GetValues and BeginRequest between Params records
        // Duplicate BeginRequest should be ignored silently
        let params_start = inp.len();
        test_support::add_params(
            &mut inp, REQ_ID,
            test_support::PARAMS.iter().copied(),
            &[100, 35, 341],
        );
        let mid_params = params_start + fcgi::RecordHeader::LEN + 100;
        inp.splice(mid_params..mid_params, dupes);
        test_support::randomize_padding(&mut inp);

        let config = Config::with_conns(1.try_into().unwrap());
        let (res, out) = run_parser(Parser::new(&config), &inp);
        let (request, data) = res.expect("parser failed");

        const VALS1_LEN: usize = test_support::VALS_RESULT1.len();
        assert_eq!(data, b"");
        assert_eq!(out.len(), 2 * VALS1_LEN);
        assert_eq!(&out[..VALS1_LEN], test_support::VALS_RESULT1);
        assert_eq!(&out[VALS1_LEN..], test_support::VALS_RESULT1);
        check_request(&request, REQ_ID);
    }

    #[test]
    fn unknown_record() {
        const REQ_ID: u16 = 0x4943;
        const UNK_A7: &[u8; 16] = b"\x01\x0b\x49\x43\x00\x08\0\0\xa7\0\0\0\0\0\0\0";

        let mut inp = Vec::with_capacity(8192);
        test_support::add_unk(&mut inp, REQ_ID, 0xa7);
        let unk = inp.clone();

        // Splice unknown record between Params records
        test_support::add_begin(&mut inp, REQ_ID);
        let params_start = inp.len();
        test_support::add_params(
            &mut inp, REQ_ID,
            test_support::PARAMS.iter().copied(),
            &[71, 40, 184],
        );
        let mid_params = params_start + fcgi::RecordHeader::LEN + 71;
        inp.splice(mid_params..mid_params, unk);
        test_support::randomize_padding(&mut inp);

        let config = Config::with_conns(1.try_into().unwrap());
        let (res, out) = run_parser(Parser::new(&config), &inp);
        let (request, data) = res.expect("parser failed");

        assert_eq!(data, b"");
        assert_eq!(out.len(), 2 * UNK_A7.len());
        assert_eq!(&out[..UNK_A7.len()], UNK_A7);
        assert_eq!(&out[UNK_A7.len()..], UNK_A7);
        check_request(&request, REQ_ID);
    }

    #[test]
    fn unknown_role() {
        const REQ_A: u16 = 0x827f;
        const REQ_B: u16 = 0xaab9;
        const BEGIN: &[u8; 8] = b"\x6e\xc4\xb7\0\0\0\0\0";
        const END_A: &[u8; 16] = b"\x01\x03\x82\x7f\x00\x08\0\0\0\0\0\0\x03\0\0\0";

        let mut inp = Vec::with_capacity(8192);
        inp.extend(fcgi::RecordHeader {
            version: fcgi::Version::V1, rtype: fcgi::RecordType::BeginRequest,
            request_id: REQ_A, content_length: 8, padding_length: 0,
        }.to_bytes());
        inp.extend(BEGIN);
        test_support::add_params(
            &mut inp, REQ_A,
            test_support::PARAMS[..5].iter().copied(),
            &[672, 536],
        );
        test_support::add_abort(&mut inp, REQ_A);

        // Previous params and abort should be ignored
        test_support::add_begin(&mut inp, REQ_B);
        test_support::add_params(&mut inp, REQ_B, test_support::PARAMS.iter().copied(), &[]);
        test_support::randomize_padding(&mut inp);

        let config = Config::with_conns(1.try_into().unwrap());
        let (res, out) = run_parser(Parser::new(&config), &inp);
        let (request, data) = res.expect("parser failed");

        assert_eq!(data, b"");
        assert_eq!(out, END_A);
        check_request(&request, REQ_B);
    }

    #[test]
    fn multiplexed() {
        const REQ_A: u16 = 0x001f;
        const REQ_B: u16 = 0x0a0b;
        const END_B: &[u8; 16] = b"\x01\x03\x0a\x0b\x00\x08\0\0\0\0\0\0\x01\0\0\0";

        let mut inp = Vec::with_capacity(8192);
        test_support::add_begin(&mut inp, REQ_A);
        let params_start = inp.len();
        test_support::add_params(
            &mut inp, REQ_A,
            test_support::PARAMS.iter().copied(),
            &[28, 19, 57, 913],
        );
        let mid_params = params_start + 2 * 8 + 28 + 19;

        // Splice multiplexed request between Params records
        let mut mp = Vec::with_capacity(8192);
        test_support::add_begin(&mut mp, REQ_B);
        test_support::add_params(&mut mp, REQ_B, test_support::PARAMS.iter().copied(), &[284, 682]);
        inp.splice(mid_params..mid_params, mp);
        test_support::randomize_padding(&mut inp);

        let config = Config::with_conns(1.try_into().unwrap());
        let (res, out) = run_parser(Parser::new(&config), &inp);
        let (request, data) = res.expect("parser failed");

        assert_eq!(data, b"");
        assert_eq!(out, END_B);
        check_request(&request, REQ_A);
    }

    #[test]
    fn detect_stuck() {
        const REQ_ID: u16 = 74;
        let mut inp = Vec::with_capacity(8192);
        test_support::add_begin(&mut inp, REQ_ID);
        test_support::add_params(&mut inp, REQ_ID, test_support::PARAMS.iter().copied(), &[]);

        // Parser always allocates a minimum nonzero buffer size,
        // but the name-value pairs from test_support::PARAMS exceed that.
        let config = Config { buffer_size: 0, max_conns: 1.try_into().unwrap() };
        let mut parser = Parser::new(&config);
        assert!(!parser.input_buffer().is_empty());
        let (res, out) = run_parser(parser, &inp);

        assert_eq!(out, b"");
        assert!(matches!(res, Err(Error::StuckOnInput)));
    }

    #[test]
    fn fatal_errs() {
        let config = Config::with_conns(1.try_into().unwrap());
        let parser = Parser::new(&config);
        assert!(matches!(parser.into_request(), Err(Error::Interrupted)));

        let mut inp = Vec::with_capacity(8192);
        test_support::add_begin(&mut inp, 0xa9e6);
        inp.push(0xc5);
        inp.extend(test_support::random_bytes(512));
        let (res, out) = run_parser(Parser::new(&config), &inp);
        assert_eq!(out, b"");
        assert!(matches!(res, Err(Error::UnknownVersion(0xc5))));

        inp.clear();
        test_support::add_begin(&mut inp, fcgi::FCGI_NULL_REQUEST_ID);
        test_support::add_params(
            &mut inp, fcgi::FCGI_NULL_REQUEST_ID,
            test_support::PARAMS.iter().copied(),
            &[267, 78, 186],
        );
        let (res, out) = run_parser(Parser::new(&config), &inp);
        assert_eq!(out, b"");
        assert!(matches!(res, Err(Error::NullRequest)));
    }
}
