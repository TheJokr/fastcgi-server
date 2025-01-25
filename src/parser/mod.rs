use std::collections::{hash_map, HashMap};
use std::fmt;
use std::io;
use std::num::NonZeroU16;

use smallvec::SmallVec;

use crate::cgi;
use crate::protocol as fcgi;

/// A parser for the FastCGI request preamble, yielding a [`Request`].
pub mod request;
/// A parser for FastCGI input stream data after the request preamble.
pub mod stream;


/// Unrecoverable error types shared between the `Parser` types from submodules.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A panic inside the parser code left the parser in an inconsistent state.
    ///
    /// [`request::Parser`] instances cannot be reused after a panic. The
    /// connection to the FastCGI client should be closed instead. The client
    /// will then open a new connection if necessary.
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
    ///
    /// This can only happen in [`request::Parser`].
    #[error(
        "BeginRequest FastCGI record has invalid length {0}, expected {len}",
        len = fcgi::body::BeginRequest::LEN
    )]
    InvalidRequestLen(u16),

    /// The header of a BeginRequest FastCGI record specified request ID 0,
    /// which the protocol reserves for management records.
    ///
    /// This can only happen in [`request::Parser`].
    #[error("BeginRequest FastCGI record has reserved ID 0, expected nonzero")]
    NullRequest,

    /// An AbortRequest FastCGI record was received from the FastCGI client.
    ///
    /// This can only happen in [`stream::Parser`]. [`request::Parser`] handles
    /// AbortRequest records internally.
    #[error("FastCGI client ordered this request to be aborted")]
    AbortRequest,

    /// A function from the [`protocol`](crate::protocol) module returned an
    /// unexpected error type.
    #[error("unexpected protocol error: {0}")]
    Protocol(#[from] fcgi::Error),
}

impl From<Error> for io::Error {
    fn from(v: Error) -> Self {
        match v {
            Error::AbortRequest => io::ErrorKind::ConnectionAborted.into(),
            e @ (Error::UnknownVersion(_)
            | Error::InvalidRequestLen(_)
            | Error::NullRequest
            | Error::Protocol(_)) => Self::new(io::ErrorKind::InvalidData, e),
            e => Self::new(io::ErrorKind::Other, e),
        }
    }
}


/// Attempts to extract a [`fcgi::ProtocolVariables`] item from a
/// [`fcgi::RecordType::GetValues`] name-value pair.
#[must_use]
fn parse_nv_var((name, _): (&[u8], &[u8])) -> Option<fcgi::ProtocolVariables> {
    // Values in name-value pairs *should* be empty, so ignore them
    match fcgi::ProtocolVariables::parse_name(name) {
        Ok(v) => Some(v),
        Err(e) => {
            // Report and ignore unknown variable names (per the specification)
            let error: &dyn std::error::Error = &e;
            tracing::info!(error, name = %name.escape_ascii(), "protocol variable name ignored");
            None
        },
    }
}


const SMALLVEC_BASE_SIZE: usize = std::mem::size_of::<SmallVec<[u8; 0]>>();
// Maximum number of inline bytes before SmallVec exceeds SMALLVEC_BASE_SIZE.
// This derives from SmallVec's layout, which uses 1 usize as discriminant.
const INLINE_BYTES: usize = SMALLVEC_BASE_SIZE - std::mem::size_of::<usize>();
type SmallBytes = SmallVec<[u8; INLINE_BYTES]>;


/// An iterator over the environment variables of a [`Request`].
#[derive(Clone)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct EnvIter<'a> {
    inner: hash_map::Iter<'a, cgi::OwnedVarName, SmallBytes>,
}

// Forward all non-defaulted methods from hash_map::Iter
impl fmt::Debug for EnvIter<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, f)
    }
}

impl<'a> Iterator for EnvIter<'a> {
    type Item = (&'a cgi::OwnedVarName, &'a [u8]);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (k, v.as_ref()))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl std::iter::FusedIterator for EnvIter<'_> {}
impl std::iter::ExactSizeIterator for EnvIter<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}


/// A fully-parsed FastCGI request with its [CGI/1.1 environment][env].
///
/// This is an intermediate representation of a complete FastCGI transaction.
/// The [`BeginRequest`](fcgi::body::BeginRequest) body and the entire `Params`
/// stream are parsed, but other role-dependent streams still need to be
/// extracted from the input. Handling those streams separately allows them to
/// be implemented via `Read`/`Write` traits.
///
/// [env]: https://www.rfc-editor.org/rfc/rfc3875.html#section-4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The ID of this request, to be matched against future records.
    pub request_id: NonZeroU16,
    /// The role of the FastCGI application in this request.
    pub role: fcgi::Role,
    /// The control flags for this request.
    pub flags: fcgi::RequestFlags,
    /// The CGI/1.1 environment associated with this request.
    params: HashMap<cgi::OwnedVarName, SmallBytes>,
}

impl Request {
    #[must_use]
    fn new(id: NonZeroU16, body: fcgi::body::BeginRequest) -> Self {
        Self {
            request_id: id, role: body.role, flags: body.flags,
            // HashMap overallocates by 1/7th and rounds up to a power of 2,
            // so this gives us 64 buckets. 32 buckets would limit the capacity
            // to at most 28, which is not enough for common web requests.
            params: HashMap::with_capacity(40),
        }
    }

    /// Returns the number of environment variables associated with this request.
    #[inline]
    #[must_use]
    pub fn env_len(&self) -> usize {
        self.params.len()
    }

    /// Tests whether the variable name is part of the environment of this
    /// request.
    #[inline]
    #[must_use]
    pub fn contains_var(&self, name: &cgi::VarName) -> bool {
        self.params.contains_key(name)
    }

    /// Retrieves the value stored for the variable name, if there is one.
    #[must_use]
    pub fn get_var(&self, name: &cgi::VarName) -> Option<&[u8]> {
        self.params.get(name).map(AsRef::as_ref)
    }

    /// Attempts to retrieve the string value stored for the variable name.
    ///
    /// Returns [`None`] if there is no corresponding value *or if the value
    /// is not valid UTF-8*. Use `Request::get_var` if you are interested in
    /// the raw bytes and want to decode them manually.
    #[must_use]
    pub fn get_var_str(&self, name: &cgi::VarName) -> Option<&str> {
        self.params.get(name).and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Returns an iterator over all environment variables of this request.
    #[inline]
    pub fn env_iter(&self) -> EnvIter {
        EnvIter { inner: self.params.iter() }
    }
}


#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;
    use super::*;

    fn str_params() -> impl Iterator<Item = (&'static str, &'static [u8])> {
        test_support::PARAMS.iter().filter_map(
            |&(n, v)| Some((std::str::from_utf8(n).ok()?, v))
        )
    }

    #[test]
    fn req_env() {
        let body = fcgi::body::BeginRequest {
            role: fcgi::Role::Responder,
            flags: fcgi::RequestFlags::all(),
        };
        let mut req = Request::new(1.try_into().unwrap(), body);
        req.params.extend(str_params().map(
            |(n, v)| (n.into(), SmallBytes::from_slice(v))
        ));

        assert_eq!(req.env_len(), str_params().count());
        assert!(req.contains_var("request_method".into()));
        assert!(req.contains_var(cgi::GATEWAY_INTERFACE.into()));
        assert!(!req.contains_var("".into()));
        assert!(!req.contains_var("kOHvQ!e&GROq&?0kz>=bQr`O`".into()));

        assert!(matches!(req.get_var(cgi::CONTENT_LENGTH.into()), Some(b"67828")));
        assert!(matches!(req.get_var("http_X_not_uTF8".into()), Some(test_support::BYTES)));
        assert!(req.get_var("".into()).is_none());
        assert!(req.get_var("Y)tdz(".into()).is_none());

        assert!(matches!(req.get_var_str(cgi::HTTP_X_FORWARDED_PROTO.into()), Some("https")));
        assert!(req.get_var_str("HTTP_X_NOT_UTF8".into()).is_none());
        assert!(req.get_var_str("".into()).is_none());
        assert!(req.get_var_str("x9rJb03ASGg45".into()).is_none());

        let mut it = req.env_iter();
        assert_eq!(it.len(), req.env_len());
        assert_eq!(it.clone().count(), it.len());
        for (n, v) in &mut it {
            assert!(str_params().any(
                |(refn, refv)| cgi::VarName::new(refn) == n.borrow() && refv == v
            ));
        }
        assert!(it.next().is_none());
    }
}
