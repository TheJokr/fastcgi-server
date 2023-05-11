use std::collections::HashMap;
use std::fmt::Debug;
use std::iter::FusedIterator;
use std::num::NonZeroU16;

use smallvec::SmallVec;

use crate::cgi;
use crate::protocol as fcgi;


const SMALLVEC_BASE_SIZE: usize = std::mem::size_of::<SmallVec<[u8; 0]>>();
// Maximum number of inline bytes before SmallVec exceeds SMALLVEC_BASE_SIZE.
// This derives from SmallVec's layout, which uses 1 usize as discriminant.
const INLINE_BYTES: usize = SMALLVEC_BASE_SIZE - std::mem::size_of::<usize>();
pub(super) type SmallBytes = SmallVec<[u8; INLINE_BYTES]>;


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
    pub(super) params: HashMap<cgi::OwnedVarName, SmallBytes>,
}

impl Request {
    #[must_use]
    pub(super) fn new(id: NonZeroU16, body: fcgi::body::BeginRequest) -> Self {
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
mod tests {
    use std::borrow::Borrow;
    use super::super::tests::{BYTES, PARAMS};
    use super::*;

    #[inline]
    fn str_params() -> impl Iterator<Item = (&'static str, &'static [u8])> {
        PARAMS.iter().filter_map(
            |&(n, v)| Some((std::str::from_utf8(n).ok()?, v))
        )
    }

    #[test]
    fn env() {
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
        assert!(matches!(req.get_var("http_X_not_uTF8".into()), Some(BYTES)));
        assert!(matches!(req.get_var("".into()), None));
        assert!(matches!(req.get_var("Y)tdz(".into()), None));

        assert!(matches!(req.get_var_str(cgi::HTTP_X_FORWARDED_PROTO.into()), Some("https")));
        assert!(matches!(req.get_var_str("HTTP_X_NOT_UTF8".into()), None));
        assert!(matches!(req.get_var_str("".into()), None));
        assert!(matches!(req.get_var_str("x9rJb03ASGg45".into()), None));

        let mut it = req.env_iter();
        let mut len = it.len();
        assert_eq!(len, req.env_len());
        for (n, v) in &mut it {
            assert!(str_params().any(
                |(refn, refv)| cgi::VarName::new(refn) == n.borrow() && refv == v
            ));
            len -= 1;
        }
        assert_eq!(len, 0);
        assert!(matches!(it.next(), None));
    }
}
