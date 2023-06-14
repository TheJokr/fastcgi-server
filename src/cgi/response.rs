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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect() -> io::Result<()> {
        const REF: &[&str] = &[
            "/", "/3i-7gjb2-wetb409.html", "/example.html?foo=bar",
            "http://example.com", "https://example.com/foo?q=bar#baz",
            "https://user@example.org/a1zs5/bdg834/cj94k/dh78f?njejk=572#frag",
        ];

        let mut buf = Vec::with_capacity(1024);
        for dest in REF {
            buf.clear();
            let exp = format!("Location: {dest}\n\n");
            let len = simple_redirect(&mut buf, dest)?;
            assert_eq!(len, buf.len());
            assert_eq!(buf, exp.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn doc_response() -> io::Result<()> {
        const REF: &[u8] = b"Status: 200 OK\nContent-Type: text/plain; charset=utf-8\n\
            Etag: TebWmVZhLynbmkSaxnwq\nServer: fastcgi-server\n\n";
        const HEADERS: &[(&[u8], &[u8])] = &[
            (b"Content-Type", b"text/plain; charset=utf-8"),
            (b"Etag", b"TebWmVZhLynbmkSaxnwq"),
            (b"Server", b"fastcgi-server"),
        ];
        check_headers(http::StatusCode::OK, HEADERS, REF)
    }

    #[test]
    fn custom_redirect() -> io::Result<()> {
        const REF: &[u8] = b"Status: 307 Temporary Redirect\n\
            Location: https://example.com/foo.html?bar=baz#frag\n\
            Cache-Control: public, max-age=18682\n\
            Expires: Tue, 13 Jun 2023 12:04:19 GMT\n\n";
        const HEADERS: &[(&[u8], &[u8])] = &[
            (b"Location", b"https://example.com/foo.html?bar=baz#frag"),
            (b"Cache-Control", b"public, max-age=18682"),
            (b"Expires", b"Tue, 13 Jun 2023 12:04:19 GMT"),
        ];
        check_headers(http::StatusCode::TEMPORARY_REDIRECT, HEADERS, REF)
    }

    #[test]
    fn custom_status() -> io::Result<()> {
        const REF: &[u8] = b"Status: 999 Custom\nContent-Type: application/json\n\
            Content-Encoding: brotli\nLast-Modified: Tue, 13 Jun 2023 16:41:40 GMT\n\n";
        const HEADERS: &[(&[u8], &[u8])] = &[
            (b"Content-Type", b"application/json"),
            (b"Content-Encoding", b"brotli"),
            (b"Last-Modified", b"Tue, 13 Jun 2023 16:41:40 GMT"),
        ];
        let status = http::StatusCode::from_u16(999).unwrap();
        check_headers(status, HEADERS, REF)
    }

    fn check_headers(
        status: http::StatusCode,
        headers: &[(&[u8], &[u8])],
        exp: &[u8],
    ) -> io::Result<()> {
        let mut buf = Vec::with_capacity(1024);
        let len = write_headers(&mut buf, status, headers.iter().copied())?;
        assert_eq!(len, buf.len());
        assert_eq!(buf, exp);
        Ok(())
    }

    #[test]
    fn http_response() -> io::Result<()> {
        const REF: &[u8] = b"Status: 503 Service Unavailable\n\
            content-type: text/html; charset=utf-8\n\
            date: Tue, 13 Jun 2023 17:02:36 GMT\nvary: accept\n\
            link: <https://example.com>; rel=\"preconnect\"\n\n";
        let resp = http::response::Builder::new()
            .status(503)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(http::header::DATE, "Tue, 13 Jun 2023 17:02:36 GMT")
            .header(http::header::VARY, "accept")
            .header(http::header::LINK, "<https://example.com>; rel=\"preconnect\"")
            .body(())
            .unwrap();

        let mut buf = Vec::with_capacity(1024);
        let len = http_headers(&mut buf, &resp)?;
        assert_eq!(len, buf.len());
        assert_eq!(buf, REF);
        Ok(())
    }
}
