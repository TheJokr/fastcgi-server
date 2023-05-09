use std::num::NonZeroU16;
use std::ops::ControlFlow::{Break, Continue};

use compact_str::CompactString;

use crate::cgi;
use crate::protocol as fcgi;
use crate::Config;

mod request;

use request::SmallBytes;
pub use request::Request;


/// Unrecoverable error types that a [`Parser`] may emit.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A panic inside the parser code left the parser in an inconsistent state.
    ///
    /// [`Parser`] instances cannot be reused after a panic. The connection to
    /// the FastCGI client should be closed instead. The client will then open
    /// a new connection if necessary.
    #[error("FastCGI parser state was lost due to an unexpected panic")]
    Paniced,

    /// The parser needed more input to continue parsing, but its input buffer
    /// was already full.
    #[error("FastCGI parser is stuck on a lack of input buffer space")]
    StuckOnInput,

    /// The parser was consumed while in a non-final parsing state, for example
    /// via `Parser::into_request`.
    #[error("FastCGI parser was consumed in the middle of parsing a request")]
    Interrupted,

    /// The parser encountered a FastCGI record with unknown version number.
    ///
    /// Such a record could have an arbitrary layout and size, so we can neither
    /// parse nor skip past it.
    #[error("cannot parse FastCGI record with unknown protocol version {0}")]
    UnknownVersion(u8),

    /// The header of a BeginRequest FastCGI record specified a length that is
    /// different from its fixed-size body.
    #[error(
        "BeginRequest FastCGI record has invalid length {0}, expected {}",
        fcgi::body::BeginRequest::LEN
    )]
    InvalidRequestLen(u16),

    /// The header of a BeginRequest FastCGI record specified request ID 0,
    /// which the protocol reserves for management records.
    #[error("BeginRequest FastCGI record has reserved ID 0, expected nonzero")]
    NullRequest,

    /// A function from the [`protocol`](crate::protocol) module returned an
    /// unexpected error type.
    #[error("unexpected protocol error: {0}")]
    Protocol(#[from] fcgi::Error),
}


type ControlFlow<T> = std::ops::ControlFlow<T, T>;
type SResult<'a> = (&'a mut [u8], State);
type PResult<'a> = ControlFlow<SResult<'a>>;

trait WrapState: Sized {
    fn into_state(self) -> State;
    fn wrap_skip(skip: SkipState<Self>) -> State;
    fn wrap_values(vals: GetValuesState<Self>) -> State;

    #[inline]
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

impl<T: WrapState> SkipState<T> {
    fn drive(mut self, data: &mut [u8]) -> PResult<'_> {
        let total = usize::from(self.payload_rem).saturating_add(self.padding_rem.into());
        if data.len() >= total {
            Continue((&mut data[total..], self.next.into_state()))
        } else if data.len() > self.payload_rem.into() {
            self.padding_rem -= (data.len() - usize::from(self.payload_rem)) as u8;
            self.payload_rem = 0;
            Break((&mut [], T::wrap_skip(self)))
        } else {
            self.payload_rem -= data.len() as u16;
            Break((&mut [], T::wrap_skip(self)))
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

impl<T: WrapState> GetValuesState<T> {
    #[inline]
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
            let len = data.len().min(self.payload_rem.into());
            let mut nvit = fcgi::nv::NVIter::new(&mut data[..len]);
            self.vars.extend(
                // Values in name-value pairs *should* be empty, so ignore them
                // Also silently ignore unknown variable names, per the specification
                (&mut nvit).filter_map(|(n, _)| fcgi::ProtocolVariables::parse_name(n).ok()),
            );
            let consumed = len - nvit.into_inner().len();

            if data.len() < self.payload_rem.into() {
                // Wait for future payload bytes
                self.payload_rem -= consumed as u16;
                return Break((&mut data[consumed..], T::wrap_values(self)));
            }
            // Payload is complete. If consumed < self.payload_rem, the GetValues
            // body ends with an incomplete name-value pair that we ignore.
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
    ($s:ident, $inp:ident, $siz:expr) => {
        to_array!($s, $inp, 0, $siz)
    };
    ($s:ident, $inp:ident, $off:expr, $siz:expr) => {{
        let end = $off + $siz;
        if $inp.len() < end {
            return Break(($inp, $s.into_state()));
        }
        <[u8; $siz]>::try_from(&$inp[$off..end])
            .expect("slice should be same length as array")
    }};
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
            Ok(h) => h,
            Err(fcgi::Error::UnknownVersion(v)) => fatal!($inp, Error::UnknownVersion(v)),
            Err(fcgi::Error::UnknownRecordType(rtype)) => {
                let request_id = u16::from_be_bytes([head[2], head[3]]);
                let payload = u16::from_be_bytes([head[4], head[5]]);
                let padding = head[6];

                // Report unknown record type to remote
                $out.extend(fcgi::body::UnknownType { rtype }.to_record(request_id));
                // Skip record body
                let skip = $s.into_skip(payload, padding);
                return Continue((&mut $inp[fcgi::RecordHeader::LEN..], skip));
            },
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
            Err(fcgi::Error::UnknownRole(_)) => {
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
            fatal!(data, Error::NullRequest)
        };
        let inner = ParamsStateInner::new(Request::new(req_id, body));
        let params = ParamsState { inner, payload_rem: 0, padding_rem: head.padding_length };
        Continue((data, params.into_state()))
    }
}

impl WrapState for HeaderState {
    #[inline]
    fn into_state(self) -> State {
        State::Header(self)
    }
    #[inline]
    fn wrap_skip(skip: SkipState<Self>) -> State {
        State::HeaderSkip(skip)
    }
    #[inline]
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
    #[inline]
    fn new(req: Request) -> Self {
        Self { req, buffer: Vec::new() }
    }

    /// Parses a single name-value pair with partial data in self.buffer.
    ///
    /// This function is very similar in purpose to [`NVIter`], but handles the
    /// case where a name-value pair is split between multiple Params stream
    /// records.
    ///
    /// self.buffer **must** be non-empty before calling
    /// `ParamsStateInner::parse_buffered`!
    fn parse_buffered<'a>(&mut self, mut data: &'a mut [u8], rec_end: bool) -> &'a mut [u8] {
        // Move the length header (two VarInts) into the buffer
        let head_len = 2 + usize::from(self.buffer[0] >> 7) * 3;
        try_fill!(self.buffer, data, head_len, rec_end);
        let head_len = head_len + usize::from(self.buffer[head_len - 1] >> 7) * 3;
        try_fill!(self.buffer, data, head_len, rec_end);

        let mut cur = &*self.buffer;
        let name_len = fcgi::varint::VarInt::read(&mut cur)
            .expect("both VarInts should be in the buffer").to_usize();
        let val_len = fcgi::varint::VarInt::read(&mut cur)
            .expect("both VarInts should be in the buffer").to_usize();
        debug_assert_eq!(head_len, self.buffer.len() - cur.len());

        let head_len = self.buffer.len() - cur.len();
        let val_start = head_len.saturating_add(name_len);
        let total_len = val_start.saturating_add(val_len);

        // Wait for sufficient data to extract both name and value
        let avail = self.buffer.len().saturating_add(data.len());
        if avail < total_len {
            if rec_end {
                self.buffer.extend(&*data);
                return &mut [];
            }
            return data;
        }
        debug_assert!(self.buffer.len() >= head_len);

        let name = if self.buffer.len() == head_len {
            // Name is fully contained in the data slice. Since we moved the
            // length header into self.buffer, name must be at the start of data.
            let raw;
            (raw, data) = data.split_at_mut(name_len);
            CompactString::from_utf8_lossy(raw)
        } else {
            // Name is (partially) contained in self.buffer. Move
            // the remainder, but keep value in the data slice.
            try_fill!(self.buffer, data, val_start, rec_end);
            CompactString::from_utf8_lossy(&self.buffer[head_len..val_start])
        };
        let name = cgi::OwnedVarName::from_compact(name);

        // Unlike name, we treat value as raw bytes and can
        // thus easily compose it from multiple sources.
        let mut val = SmallBytes::with_capacity(val_len);
        if self.buffer.len() > val_start {
            // First, copy any value bytes left in self.buffer
            val.extend_from_slice(&self.buffer[val_start..]);
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
        self.req.params.extend((&mut nvit).map(|(n, v)| {
            // Valid CGI/1.1 variable names are ASCII-only, but
            // we want to support invalid ones as much as possible.
            let name = CompactString::from_utf8_lossy(n);
            (cgi::OwnedVarName::from_compact(name), SmallBytes::from_slice(v))
        }));
        data = nvit.into_inner();

        if rec_end && !data.is_empty() {
            // Reserve sufficient space for name-value pair's length header and name
            self.buffer.reserve(data.len().max(64));
            self.buffer.extend(&*data);
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
            fcgi::RecordType::AbortRequest if head.request_id == req_id => {
                // Report that request was aborted to remote
                out.extend(fcgi::body::EndRequest {
                    protocol_status: fcgi::ProtocolStatus::RequestComplete,
                    app_status: 0,
                }.to_record(req_id));
                // Return to initial HeaderState
                let initial = HeaderState.into_skip(head.content_length, head.padding_length);
                Continue((data, initial))
            },

            fcgi::RecordType::GetValues if head.is_management() => {
                // Transition to GetValuesState for body
                let next = self.inner;
                let vals = GetValuesState::new(next, head.content_length, head.padding_length);
                Continue((data, State::ParamsValues(vals)))
            },
            fcgi::RecordType::Params if head.request_id == req_id => {
                if head.content_length == 0 {
                    // Params stream is finished, now return the parsed Request.
                    // If self.inner.buffer is non-empty here, the stream ends
                    // with an incomplete name-value pair that we ignore.
                    let done = self.inner.req.into_skip(0, head.padding_length);
                    return Continue((data, done));
                }
                // Loop around to parse stream record body
                self.payload_rem = head.content_length;
                self.padding_rem = head.padding_length;
                Continue((data, self.into_state()))
            },
            _ => {
                // Skip unexpected record types
                let skip = self.into_skip(head.content_length, head.padding_length);
                Continue((data, skip))
            },
        }
    }

    #[inline]
    fn into_state(self) -> State {
        State::Params(self)
    }
    #[inline]
    fn into_skip(self, payload_rem: u16, padding_rem: u8) -> State {
        // Skipping only makes sense outside of stream record bodies
        debug_assert_eq!(self.payload_rem, 0);
        debug_assert_eq!(self.padding_rem, 0);
        self.inner.into_skip(payload_rem, padding_rem)
    }
}

// We only need to pass ParamsStateInner through wrappers, not the entire
// ParamsState. This reduces the overall size of the State enum.
impl WrapState for ParamsStateInner {
    #[inline]
    fn into_state(self) -> State {
        State::Params(ParamsState { inner: self, payload_rem: 0, padding_rem: 0 })
    }
    #[inline]
    fn wrap_skip(skip: SkipState<Self>) -> State {
        State::ParamsSkip(skip)
    }
    #[inline]
    fn wrap_values(vals: GetValuesState<Self>) -> State {
        State::ParamsValues(vals)
    }
}


// Allow completed Request to consume padding from final Params record
impl WrapState for Request {
    #[inline]
    fn into_state(self) -> State {
        State::Done(self)
    }
    #[inline]
    fn wrap_skip(skip: SkipState<Self>) -> State {
        State::DoneSkip(skip)
    }
    #[inline]
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
    #[inline]
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
pub struct Yield<'a> {
    /// Indicates whether the [`Parser`] reached a final parsing state.
    ///
    /// If `true`, future calls to `Parser::parse` do not change the state of the
    /// parser any further. The parser's result, either a [`RequestData`] or an
    /// [`Error`], may be retrieved via `Parser::into_request`.
    ///
    /// Otherwise, the parser yielded to the caller to request additional input.
    /// Input must be supplied into the slice returned by
    /// `Parser::get_input_buffer` before the next call to `Parser::parse`.
    pub done: bool,

    /// Output generated by the parser during parsing, which may be empty.
    ///
    /// If `output` is not empty, the caller must send its contents to the
    /// FastCGI client *before* the next call to `Parser::parse`. The underlying
    /// buffer will be overwritten by future calls to `Parser::parse`.
    pub output: &'a [u8],
}

/// A combination of a [`Request`] and leftover data from a [`Parser`].
#[derive(Debug, Clone)]
pub struct RequestData {
    /// The complete [`Request`] parsed by the [`Parser`].
    pub request: Request,
    /// The leftover input bytes in the [`Parser`]'s internal buffer.
    pub input: Vec<u8>,
}


/// A parser which extracts a FastCGI [`Request`] from a caller-provided
/// record stream.
///
/// The caller must feed the record stream into the parser's internal buffer,
/// which is available via `Parser::get_input_buffer`. After reading `n` bytes
/// into this buffer, `Parser::parse(n)` processes the bytes and returns an
/// intermediate [`Yield`] value. The [`Yield`] may contain output bytes, which
/// must be sent to the FastCGI client before the next `Parser::parse` call.
/// This process is repeated until the [`Yield`] indicates that the parser is
/// done. Finally, the parser is consumed with `Parser::into_request` to return
/// the [`Request`] (or an [`Error`]).
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
    /// Creates a new [`Parser`] with the given configuration and default input
    /// buffer size.
    ///
    /// The default size is suitable for most FastCGI clients and balances
    /// overheads with throughput.
    #[inline]
    pub fn new(config: &'a Config) -> Self {
        Self::with_buffer(8192, config)
    }

    /// Creates a new [`Parser`] with the given configuration and input buffer
    /// size.
    ///
    /// The input buffer needs to be at least as large as the longest
    /// name-value pair to be parsed. A sufficient value is given by
    /// `MAX_HEADER_LEN + 13`, where `MAX_HEADER_LEN` is the length of the
    /// longest possible HTTP header passed by the FastCGI client (including
    /// both the header's name and value). In practice, the default size used
    /// by `Parser::new` is a good starting point.
    pub fn with_buffer(buffer_size: usize, config: &'a Config) -> Self {
        // Minimum buffer size required for statically-known parsing units
        // - fcgi::RecordHeader::LEN + fcgi::body::BeginRequest::LEN (16)
        // - Longest expected GetValues name-value pair (17)
        const MIN_INPUT: usize = 24;
        let buffer_size = buffer_size.max(MIN_INPUT);
        // Align to multiple of 8 bytes to match FastCGI recommended padding
        let buffer_size = (buffer_size + 7) & !7;

        Self {
            config,
            input: vec![0; buffer_size].into_boxed_slice(),
            input_len: 0,
            output: Vec::with_capacity(256),
            state: State::Header(HeaderState),
        }
    }

    /// Returns the slice of the parser's internal buffer into which new input
    /// must be written.
    ///
    /// The number of bytes actually written, such as by [`Read::read`][read],
    /// is later passed to `Parser::parse`.
    ///
    /// [read]: std::io::Read::read
    #[inline]
    pub fn get_input_buffer(&mut self) -> &mut [u8] {
        &mut self.input[self.input_len..]
    }

    /// Moves the last `rem_len` bytes from the input buffer to the front,
    /// discarding the rest of the input buffer.
    fn move_input(&mut self, rem_len: usize) {
        let used_len = self.input_len.checked_sub(rem_len)
            .expect("remaining input after State::drive() exceeds original input");
        if 0 < used_len && used_len < self.input_len {
            self.input.copy_within(used_len..self.input_len, 0);
        }
        self.input_len = rem_len;
    }

    /// Parses as much of the provided record stream as possible, resulting in
    /// an intermediate [`Yield`].
    ///
    /// `new_input` specifies the number of bytes written into the slice from
    /// `Parser::get_input_buffer` since the last call to `Parser::parse`.
    /// Progress is only possible if this number is larger than zero.
    ///
    /// The returned [`Yield`] specifies whether the parser has finished parsing
    /// a [`Request`], or whether more input is required. It also carries output
    /// bytes to be sent to the FastCGI client. Refer to its documentation for
    /// details.
    ///
    /// # Panics
    /// `new_input` must not exceed the length of the slice given by
    /// `Parser::get_input_buffer`, otherwise an assertion panics.
    pub fn parse(&mut self, new_input: usize) -> Yield {
        assert!(new_input <= self.input.len() - self.input_len);
        self.input_len += new_input;
        self.output.clear();

        let data = &mut self.input[..self.input_len];
        let rem = replace_with::replace_with_and_return(
            &mut self.state, || State::Fatal(Error::Paniced),
            |s| s.drive(data, &mut self.output, self.config)
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
    pub fn into_request(self) -> Result<RequestData, Error> {
        let request = match self.state {
            State::Done(r) => r,
            State::Fatal(e) => return Err(e),
            _ => return Err(Error::Interrupted),
        };
        let mut input = Vec::from(self.input);
        input.truncate(self.input_len);
        Ok(RequestData { request, input })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_check() {
        fn ok<T: Send + Unpin>() {}
        ok::<Parser>();
        ok::<Request>();
    }
}