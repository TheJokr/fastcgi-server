use std::collections::HashMap;
use std::fmt::Debug;
use std::iter::FusedIterator;
use std::num::NonZeroU16;

use smallvec::SmallVec;

use crate::cgi;
use crate::protocol as fcgi;

pub mod request;
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
        "BeginRequest FastCGI record has invalid length {0}, expected {}",
        fcgi::body::BeginRequest::LEN
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


const SMALLVEC_BASE_SIZE: usize = std::mem::size_of::<SmallVec<[u8; 0]>>();
// Maximum number of inline bytes before SmallVec exceeds SMALLVEC_BASE_SIZE.
// This derives from SmallVec's layout, which uses 1 usize as discriminant.
const INLINE_BYTES: usize = SMALLVEC_BASE_SIZE - std::mem::size_of::<usize>();
type SmallBytes = SmallVec<[u8; INLINE_BYTES]>;


/// A fully-parsed FastCGI request with its CGI/1.1 environment.
///
/// This is an intermediate representation of a complete FastCGI transaction.
/// The [`BeginRequest`](crate::protocol::body::BeginRequest) body and the
/// entire `Params` stream are parsed, but the other role-dependent streams
/// still need to be extracted from the input. Handling those streams
/// separately allows them to be implemented as `Read`/`Write` traits.
#[derive(Debug, Clone)]
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
            // so this gives us 64 buckets. 32 buckets would require a capacity
            // of at most 28, which is not enough for common web requests.
            params: HashMap::with_capacity(40),
        }
    }

    /// Returns the number of environment variables associated with
    /// this [`Request`].
    #[inline]
    #[must_use]
    pub fn env_len(&self) -> usize {
        self.params.len()
    }

    /// Tests whether the given variable name is part of the environment of
    /// this [`Request`].
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
    /// is not valid UTF-8*. Use `Request::get_var` if you are interested in the
    /// raw bytes and want to decode them manually.
    #[must_use]
    pub fn get_var_str(&self, name: &cgi::VarName) -> Option<&str> {
        self.params.get(name).and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Returns an iterator over all environment variables of this [`Request`].
    #[inline]
    #[must_use]
    pub fn env_iter(&self) -> impl ExactSizeIterator<Item = (&cgi::OwnedVarName, &[u8])>
            + FusedIterator + Clone + Debug + '_
    {
        self.params.iter().map(|(k, v)| (k, v.as_ref()))
    }
}


#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;
    use super::*;

    #[inline]
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
