use std::io::{self, Write};


/// Writes a simple CGI/1.1 redirect response into the writer.
///
/// `loc` can specify either a local redirect inside the webserver or a
/// client-side redirect to a new URI. For a local redirect, `loc` must consist
/// of a URI path and an optional query string, such as `/example.html?foo=bar`.
/// A client-side redirect requires an absolute URI, for example
/// `https://example.com/foo?q=bar#baz`.
///
/// The format of `loc` is not verified by this function. Other crates like
/// [`http::Uri`] exist for this purpose. Furthermore, CGI's simple redirect
/// format forbids specifying a non-`302 Found` HTTP status code and additional
/// headers. Use [`write_headers`] for custom redirect responses using the
/// `Location` header.
///
/// # Errors
/// Any errors from [`Write::write_all`] are forwarded to the caller.
#[inline]
pub fn simple_redirect(mut w: impl Write, loc: &str) -> io::Result<usize> {
    const LOCATION: &[u8] = b"Location: ";
    let val = loc.as_bytes();
    w.write_all(LOCATION)?;
    w.write_all(val)?;
    w.write_all(b"\n\n")?;
    Ok(LOCATION.len() + 2 + val.len())
}


/// Writes the headers for an [`http::Response<T>`] into the writer.
///
/// This function is a wrapper around [`write_headers`]. See its documentation
/// for details. The body of the [`http::Response`] is ignored by this function
/// and must be written into the writer manually if necessary, for example
/// using `io::copy`.
///
/// # Errors
/// Any errors from [`Write::write_all`] are forwarded to the caller.
#[inline]
pub fn http_headers<T>(w: impl Write, response: &http::Response<T>) -> io::Result<usize> {
    let headers = response.headers().iter().map(|(n, v)| (n.as_ref(), v.as_ref()));
    write_headers(w, response.status(), headers)
}

/// Writes the headers for a CGI/1.1 document response into the writer.
///
/// `headers` is an iterator over pairs of header names and associated values.
/// A header value must be a single line and therefore may not contain newline
/// characters like `\n` and `\r`. `status` is converted into its own header
/// named [`Status`], which must not be used in `headers`. This is verified by
/// a debug assertion.
///
/// If a document body will be sent, CGI/1.1 requires a `Content-Type` header
/// to be specified. After this function returns [`Ok(n)`], the caller can
/// immediately start writing the body into the writer.
///
/// # Errors
/// Any errors from [`Write::write_all`] are forwarded to the caller.
pub fn write_headers<'a, W, I>(mut w: W, status: http::StatusCode, headers: I) -> io::Result<usize>
where
    W: Write,
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let mut sbuf = *b"Status: \0\0\0 ";
    sbuf[8..11].copy_from_slice(status.as_str().as_bytes());
    let reason: &[u8] = status.canonical_reason().map_or(b"Custom", str::as_bytes);

    w.write_all(&sbuf)?;
    w.write_all(reason)?;
    let mut written = sbuf.len() + reason.len();

    for (name, val) in headers {
        debug_assert!(!name.eq_ignore_ascii_case(b"status"), "header name `Status` is reserved");
        w.write_all(b"\n")?;
        w.write_all(name)?;
        w.write_all(b": ")?;
        w.write_all(val)?;
        written += name.len() + val.len() + 3;
    }

    w.write_all(b"\n\n")?;
    Ok(written + 2)
}
