// TODO(docs): #![deny(missing_docs)]
#![deny(unsafe_code, single_use_lifetimes, unused_lifetimes, pointer_structural_match)]
#![warn(keyword_idents, let_underscore_drop, unreachable_pub, unused_import_braces)]

#![deny(clippy::suspicious, clippy::cargo)]
#![deny(clippy::exit, clippy::semicolon_inside_block, clippy::unwrap_used)]
#![warn(clippy::pedantic, clippy::multiple_crate_versions)]
#![allow(clippy::enum_glob_use, clippy::cast_possible_truncation, clippy::items_after_statements)]

use std::num::NonZeroUsize;


/// Helpful extension traits shared across the crate.
pub(crate) mod ext;

// TODO(docs): Based on FastCGI spec (especially Section 8)
// See: https://fastcgi-archives.github.io/FastCGI_Specification.html
pub mod protocol;

// TODO(docs): Helpers for CGI/1.1 requests/responses
pub mod cgi;

// TODO(docs): Pure FastCGI record stream parsers. Chunks of bytes are fed
// in by the caller, processed, and (if applicable) output bytes are returned.
// Has parsers for both request preamble and input streams.
pub mod parser;


/// The central configuration for [`fastcgi_server`](crate).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// The maximum number of concurrent FastCGI connections from the client.
    ///
    /// This parameter effectively defines the maximum amount of concurrency
    /// this crate will exhibit. Each connection supports one request at a time
    /// (that is, no multiplexing).
    ///
    /// The default is set to the OS's reported parallelism, such as the number
    /// of available CPU cores. This is often appropriate for compute-bound
    /// workloads with the FastCGI client on `localhost`. If using `async` APIs
    /// or networked operations, a much higher number may be advisable.
    pub max_conns: NonZeroUsize,
}

impl Config {
    /// Creates a new [`Config`] with all settings set to their documented defaults.
    #[must_use = "Creating a Config is not free and has no side effects"]
    pub fn new() -> Self {
        let concurrency = std::thread::available_parallelism()
            .unwrap_or(1.try_into().expect("fallback should be nonzero"));
        Self { max_conns: concurrency }
    }
}

impl Default for Config {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
