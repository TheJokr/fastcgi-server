use std::io::{self, Write};
use std::net::Ipv4Addr;

use futures_util::io::BufWriter;
use futures_util::{AsyncWriteExt, FutureExt};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::Instrument;

use fastcgi_server::protocol as fcgi;
use fastcgi_server::{async_io, cgi, Config, ExitStatus};


// Shorthands for the types making up a `Request`. The `Compat` wrapper around the
// reader and writer is a bridge between tokio's traits and those from futures-io.
type Reader<'a> = tokio_util::compat::Compat<tokio::net::tcp::ReadHalf<'a>>;
type Writer<'a> = tokio_util::compat::Compat<tokio::net::tcp::WriteHalf<'a>>;
type Request<'a, 'b, 'c> = async_io::Request<'a, Reader<'b>, Writer<'c>>;

/// Handles a single FastCGI request. Our example is stateless, but state could
/// be passed into the handler as a parameter (for example, an `Arc<T>`).
async fn handler(request: &mut Request<'_, '_, '_>) -> io::Result<ExitStatus> {
    use http::Method;
    // Dispatch the request to a specific route handler
    match parse_request(request) {
        Err(r) => Ok(r),
        Ok((Method::GET, "/redirect")) => handle_redirect(request).await,
        Ok((Method::POST, "/echo")) => handle_echo(request).await,
        Ok((Method::GET | Method::POST, _)) => handle_env(request).await,
        Ok(_) => fallback(request).await,
    }
}

/// Checks and parses CGI variables required by all endpoints. Nonzero
/// `ExitStatus::Complete` values communicate failure to the FastCGI client.
fn parse_request<'a>(request: &'a Request) -> Result<(http::Method, &'a str), ExitStatus> {
    if request.role() != fcgi::Role::Responder {
        tracing::warn!(role = ?request.role(), "not a responder request");
        return Err(ExitStatus::UnknownRole);
    }

    let gateway_interface = request.get_var(cgi::GATEWAY_INTERFACE);
    if gateway_interface != Some(b"CGI/1.1") {
        tracing::error!(?gateway_interface, "request uses unsupported interface");
        return Err(ExitStatus::Complete(1));
    }

    // SERVER_PROTOCOL is specified as case-insensitive
    let protocol = request.get_var(cgi::SERVER_PROTOCOL);
    if protocol.and_then(|p| p.get(..5)).map_or(true, |p| !p.eq_ignore_ascii_case(b"http/")) {
        tracing::error!(?protocol, "request uses unsupported protocol");
        return Err(ExitStatus::Complete(2));
    }

    let method = request.get_var(cgi::REQUEST_METHOD);
    let Some(Ok(method)) = method.map(http::Method::from_bytes) else {
        tracing::error!(?method, "parsing request method failed");
        return Err(ExitStatus::Complete(3));
    };

    let path = request.get_var_str(cgi::SCRIPT_NAME).unwrap_or_default();
    Ok((method, path))
}


const HELLO_CGI: &[u8] = b"hello-cgi-example";

/// Print the CGI environment for arbitrary GET and POST requests.
async fn handle_env(request: &mut Request<'_, '_, '_>) -> io::Result<ExitStatus> {
    // Wait for the FastCGI request to allow writes, otherwise request.output_stream may panic
    request.writeable().await?;

    // Create an HTTP response in CGI/1.1 format using our helpers. They take
    // a std::io::Write instance, so we can't pass our AsyncWrite directly.
    let headers: [(&[u8], &[u8]); 3] = [
        (http::header::CONTENT_TYPE.as_ref(), b"text/plain"),
        (b"x-powered-by", HELLO_CGI),
        (http::header::VARY.as_ref(), b"*"),
    ];
    let headers = headers.iter().copied();
    let mut head = [0; 512];
    let len = cgi::response::write_headers(&mut head[..], http::StatusCode::OK, headers)
        .expect("headers should fit into the stack buffer");

    // Write out the response to the output stream. A BufWriter
    // makes the many small writes below more efficient.
    let mut w = BufWriter::with_capacity(4096, request.output_stream(fcgi::RecordType::Stdout));
    w.write_all(&head[..len]).await?;
    w.write_all(b"Hello CGI!\n\n").await?;

    let mut env: Vec<_> = request.env_iter().collect();
    env.sort_unstable();
    for (name, val) in env {
        w.write_all(name.as_ref().as_bytes()).await?;
        w.write_all(b"=").await?;
        w.write_all(val).await?;
        w.write_all(b"\n").await?;
    }
    // Async BufWriters cannot flush when dropped, so this has to be done manually
    w.flush().await.and(Ok(ExitStatus::SUCCESS))
}

/// Perform different types of CGI redirects depending on request parameters.
async fn handle_redirect(request: &mut Request<'_, '_, '_>) -> io::Result<ExitStatus> {
    request.writeable().await?;

    // We match the query string literally in this example,
    // but usually you would parse it into some type of map.
    let mut resp = [0; 512];
    let len = match request.get_var(cgi::QUERY_STRING) {
        // A redirect with custom status code, but no body. This is non-standard!
        Some(b"type=custom") => {
            let headers: [(&[u8], &[u8]); 1] =
                [(http::header::LOCATION.as_ref(), b"https://example.com/")];
            let status = http::StatusCode::TEMPORARY_REDIRECT;
            cgi::response::write_headers(&mut resp[..], status, headers.iter().copied())
        },

        // A custom redirect with a body, as specified by CGI/1.1
        Some(b"type=body") => {
            let headers: [(&[u8], &[u8]); 2] = [
                (http::header::CONTENT_TYPE.as_ref(), b"text/plain; charset=utf-8"),
                (http::header::LOCATION.as_ref(), b"/local?from=redirect-body"),
            ];
            let headers = headers.iter().copied();
            let body = "Content moved to </local>. Redirecting...\n".as_bytes();
            let mut dest = &mut resp[..];
            cgi::response::write_headers(&mut dest, http::StatusCode::MOVED_PERMANENTLY, headers)
                .and_then(|h| dest.write_all(body).and(Ok(h + body.len())))
        },

        // A local redirect that should be handled inside the webserver
        Some(b"type=local") => {
            cgi::response::simple_redirect(&mut resp[..], "/local?from=redirect")
        },
        // A simple client-side redirect, which always uses status code 302 Found
        _ => cgi::response::simple_redirect(&mut resp[..], "https://example.com/#content"),
    }.expect("response should fit into the stack buffer");

    // Write out the response directly, since we only need to write once
    let mut w = request.output_stream(fcgi::RecordType::Stdout);
    w.write_all(&resp[..len]).await?;
    w.flush().await.and(Ok(ExitStatus::SUCCESS))
}

/// Echo the POSTed data back to the client.
async fn handle_echo(request: &mut Request<'_, '_, '_>) -> io::Result<ExitStatus> {
    if !request.is_writeable() {
        // Awaiting request.writeable() ignores all input streams except for the final one.
        // While a responder-role request only has one input stream in total, we explicitly
        // check that the request is writeable here as an example.
        tracing::error!(role = ?request.role(), "echo request was not writeable immediately");
        return Ok(ExitStatus::Complete(4));
    }

    let content_type = request.get_var(cgi::CONTENT_TYPE).unwrap_or(b"application/octet-stream");
    let headers: [(&[u8], &[u8]); 3] = [
        (http::header::CONTENT_TYPE.as_ref(), content_type),
        (http::header::CACHE_CONTROL.as_ref(), b"no-store"),
        (b"x-powered-by", HELLO_CGI),
    ];

    // Unlike in the previous two handlers, here we include a user-supplied value
    // in our headers. Our buffer could thus be too small. However, any reasonable
    // value for Content-Type will fit into 512 bytes.
    let headers = headers.iter().copied();
    let mut head = [0; 512];
    let len = match cgi::response::write_headers(&mut head[..], http::StatusCode::OK, headers) {
        Ok(l) => l,
        Err(e) => {
            let error: &dyn std::error::Error = &e;
            tracing::error!(error, buffer = head.len(), "failed to write echo response headers");
            return Ok(ExitStatus::Complete(5));
        },
    };

    // Write out the headers and use futures' copy utility for echoing the body.
    // The utility takes care to flush the writer once the input stream is done.
    let mut w = request.output_stream(fcgi::RecordType::Stdout);
    w.write_all(&head[..len]).await?;
    let copied = futures_util::io::copy_buf(&mut *request, &mut w).await?;

    // CONTENT_LENGTH *should* match the stream length. If it doesn't,
    // something is wrong either with the webserver or this library.
    let content_len: u64 =
        request.get_var_str(cgi::CONTENT_LENGTH).and_then(|v| v.parse().ok()).unwrap_or(0);
    if copied != content_len {
        tracing::warn!(read = copied, expected = content_len, "echo input stream ended short");
    }
    Ok(ExitStatus::SUCCESS)
}

/// Generate an error response for valid requests without a handler.
async fn fallback(request: &mut Request<'_, '_, '_>) -> io::Result<ExitStatus> {
    request.writeable().await?;

    // Essentially the same steps as `handle_redirect`: build up headers, a body,
    // and a status code; compose everything into a stack buffer; and finally write
    // the response into the output stream.
    let (status, body) = match request.get_var(cgi::REQUEST_METHOD) {
        Some(b"GET" | b"POST" | b"PUT" | b"DELETE") => {
            (http::StatusCode::NOT_FOUND, b"Unknown URL route\n".as_slice())
        },
        _ => (http::StatusCode::NOT_IMPLEMENTED, b"HTTP method not implemented\n".as_slice()),
    };
    let headers: [(&[u8], &[u8]); 1] =
        [(http::header::CONTENT_TYPE.as_ref(), b"text/plain; charset=utf-8")];

    let mut resp = [0; 512];
    let mut dest = &mut resp[..];
    let len = cgi::response::write_headers(&mut dest, status, headers.iter().copied())
        .and_then(|h| dest.write_all(body).and(Ok(h + body.len())))
        .expect("response should fit into the stack buffer");

    let mut w = request.output_stream(fcgi::RecordType::Stdout);
    w.write_all(&resp[..len]).await?;
    w.flush().await.and(Ok(ExitStatus::SUCCESS))
}


// This hello-world example uses the current-thread runtime for simplicity,
// but the multi-threaded one is recommended for real applications.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    init_tracing();
    // Allow up to 10 concurrent connections on our single-threaded runtime
    let config = Config::with_conns(10.try_into().unwrap());
    let mut runner = config.async_runner();

    // Listen for FastCGI connections until we receive a quit signal
    let res = tokio::select! {
        biased;  // poll in order, so quit() future first
        r = quit() => r,
        r = server(&mut runner) => r,
    };
    if let Err(e) = res {
        let error: &dyn std::error::Error = &e;
        tracing::error!(error, "server loop failed");
    }

    // Gracefully shut down active connections before exiting the runtime
    tracing::info!("shutting down");
    runner.shutdown().await;
}

/// Runs the FastCGI server on localhost:9000.
async fn server(runner: &mut async_io::Runner) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 9000)).await?;
    let local = listener.local_addr()?;
    tracing::info!(protocol = "tcp", %local, "server created");

    loop {
        // We must obtain a token *before* accepting a new connection
        // to ensure Config's max_conns is respected.
        let token = runner.get_token().await;
        let (mut conn, remote) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                let error: &dyn std::error::Error = &e;
                tracing::info!(protocol = "tcp", %local, error, "accept failed");
                continue;
            },
        };

        // Spawn a separate task to handle the connection and wrap it in a tracing span
        let span = tracing::error_span!("fastcgi_connection", protocol = "tcp", %local, %remote);
        tokio::spawn(async move {
            tracing::debug!("new connection accepted");
            // Split the connection into a read and a write half. fastcgi-server
            // is architected around operating on two separate half-connections.
            let (r, w) = conn.split();
            // The handler future needs to be `Box::pin`ned until Rust gets proper async traits.
            // You could also do other work in the closure before returning the boxed future,
            // such as cloning some context to pass to the handler. Borrowing captured
            // variables directly is currently not allowed by Rust.
            token.run(r.compat(), w.compat_write(), |r| handler(r).boxed()).await
        }.instrument(span));
    }
}


/// Waits for a signal to shut the FastCGI server down.
#[cfg(not(unix))]
fn quit() -> impl std::future::Future<Output = io::Result<()>> {
    tokio::signal::ctrl_c()
}

/// Waits for a signal to shut the FastCGI server down.
#[cfg(unix)]
async fn quit() -> io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r,
        _ = term.recv() => Ok(()),
    }
}


/// Sets up a basic `tracing` subscriber to stderr. Its verbosity level is
/// configured with the `RUST_LOG` environment variable.
fn init_tracing() {
    use tracing_subscriber::{filter::LevelFilter, fmt};
    let max_level = match std::env::var("RUST_LOG") {
        Ok(var) if !var.is_empty() => match var.parse::<LevelFilter>() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Ignoring `RUST_LOG={var}`: {e}");
                LevelFilter::INFO
            },
        },
        Ok(_) | Err(std::env::VarError::NotPresent) => LevelFilter::INFO,
        Err(e) => {
            eprintln!("Ignoring `RUST_LOG`: {e}");
            LevelFilter::INFO
        },
    };

    fmt::fmt()
        .with_timer(fmt::time::uptime())
        .with_max_level(max_level)
        .with_writer(std::io::stderr)
        .init();
}
