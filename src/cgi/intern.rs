use std::fmt;


/// A statically-allocated CGI/1.1 variable name.
///
/// All common CGI/1.1 meta variables as well as standardized HTTP request
/// headers and some common `X-*` headers are included as enum variants. They
/// are exposed as constants on the [`cgi`](crate::cgi) module.
///
/// The constants are the most efficient way of creating and storing
/// [`VarName`](super::VarName) and [`OwnedVarName`](super::OwnedVarName). They
/// can be converted into either type with [`From`] impls.
#[allow(missing_docs, non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, strum::IntoStaticStr, strum::EnumString)]
#[strum(use_phf, serialize_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum StaticVarName {
    // From RFC 3875, Section 4.1 (CGI/1.1)
    AUTH_TYPE,
    CONTENT_LENGTH,
    CONTENT_TYPE,
    GATEWAY_INTERFACE,
    PATH_INFO,
    PATH_TRANSLATED,
    QUERY_STRING,
    REMOTE_ADDR,
    REMOTE_HOST,
    REMOTE_IDENT,
    REMOTE_USER,
    REQUEST_METHOD,
    SCRIPT_NAME,
    SERVER_NAME,
    SERVER_PORT,
    SERVER_PROTOCOL,
    SERVER_SOFTWARE,

    // From Apache's variables
    REQUEST_SCHEME,
    REQUEST_URI,
    DOCUMENT_URI,
    REQUEST_FILENAME,
    SCRIPT_FILENAME,
    REMOTE_PORT,
    SERVER_ADMIN,
    DOCUMENT_ROOT,
    HTTP2,
    IPV6,

    // From Apache mod_fcgid
    FCGI_APACHE_ROLE,
    REMOTE_PASSWD,

    // From nginx/conf/fastcgi_params
    FCGI_ROLE,
    SERVER_ADDR,
    REDIRECT_STATUS,

    // Protocol schemes
    HTTP,
    HTTP3,
    HTTPS,

    // Common end-to-end HTTP request headers (from MDN)
    // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
    HTTP_ACCEPT,
    HTTP_ACCEPT_CHARSET,
    HTTP_ACCEPT_ENCODING,
    HTTP_ACCEPT_LANGUAGE,
    HTTP_ACCEPT_PUSH_POLICY,
    HTTP_ACCEPT_SIGNATURE,
    HTTP_ACCESS_CONTROL_REQUEST_HEADERS,
    HTTP_ACCESS_CONTROL_REQUEST_METHOD,
    HTTP_AUTHORIZATION,
    /// W3C baggage propagation (https://www.w3.org/TR/baggage/)
    HTTP_BAGGAGE,
    HTTP_CACHE_CONTROL,
    HTTP_CONTENT_ENCODING,
    HTTP_CONTENT_LANGUAGE,
    HTTP_COOKIE,
    HTTP_DATE,
    HTTP_DEVICE_MEMORY,
    /// W3C tracking preference (https://www.w3.org/TR/tracking-dnt/)
    HTTP_DNT,
    HTTP_DOWNLINK,
    HTTP_DPR,
    HTTP_EARLY_DATA,
    HTTP_ECT,
    HTTP_EXPECT,
    HTTP_FORWARDED,
    HTTP_FROM,
    HTTP_HOST,
    HTTP_IF_MATCH,
    HTTP_IF_MODIFIED_SINCE,
    HTTP_IF_NONE_MATCH,
    HTTP_IF_RANGE,
    HTTP_IF_UNMODIFIED_SINCE,
    HTTP_ORIGIN,
    HTTP_PRAGMA,
    HTTP_RANGE,
    HTTP_REFERER,
    HTTP_RTT,
    HTTP_SAVE_DATA,
    HTTP_SEC_CH_PREFERS_REDUCED_MOTION,
    HTTP_SEC_CH_UA,
    HTTP_SEC_CH_UA_ARCH,
    HTTP_SEC_CH_UA_BITNESS,
    HTTP_SEC_CH_UA_FULL_VERSION,
    HTTP_SEC_CH_UA_FULL_VERSION_LIST,
    HTTP_SEC_CH_UA_MOBILE,
    HTTP_SEC_CH_UA_MODEL,
    HTTP_SEC_CH_UA_PLATFORM,
    HTTP_SEC_CH_UA_PLATFORM_VERSION,
    HTTP_SEC_FETCH_DEST,
    HTTP_SEC_FETCH_MODE,
    HTTP_SEC_FETCH_SITE,
    HTTP_SEC_FETCH_USER,
    HTTP_SERVICE_WORKER_NAVIGATION_PRELOAD,
    /// W3C trace context propagation (https://www.w3.org/TR/trace-context/)
    HTTP_TRACEPARENT,
    /// W3C trace context propagation (https://www.w3.org/TR/trace-context/)
    HTTP_TRACESTATE,
    HTTP_UPGRADE_INSECURE_REQUESTS,
    HTTP_USER_AGENT,
    HTTP_VIA,
    HTTP_VIEWPORT_WIDTH,
    HTTP_WIDTH,
    HTTP_X_CORRELATION_ID,
    HTTP_X_CSRF_TOKEN,
    HTTP_X_FORWARDED_FOR,
    HTTP_X_FORWARDED_HOST,
    HTTP_X_FORWARDED_PROTO,
    HTTP_X_HTTP_METHOD_OVERRIDE,
    HTTP_X_REQUESTED_WITH,
    HTTP_X_REQUEST_ID,
    HTTP_X_XSRF_TOKEN,
}

impl AsRef<str> for StaticVarName {
    #[inline]
    fn as_ref(&self) -> &str {
        self.into()
    }
}

impl fmt::Debug for StaticVarName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_ref(), f)
    }
}

impl fmt::Display for StaticVarName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_ref(), f)
    }
}

impl PartialOrd for StaticVarName {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Can't derive because variants are ordered by origin, not alphabetically
impl Ord for StaticVarName {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Case is normalized by strum during compilation
        self.as_ref().cmp(other.as_ref())
    }
}
