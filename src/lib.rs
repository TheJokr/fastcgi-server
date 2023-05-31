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
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {
    /// The allocation size for the internal buffer of a FastCGI [`parser`].
    ///
    /// Each concurrent connection allocates one buffer of this size. Input data
    /// is read from a socket directly into that buffer, so choosing this
    /// parameter is a tradeoff between memory usage and syscall overhead. The
    /// library's overall memory usage can thereby be tuned, though some smaller
    /// allocations are still necessary.
    ///
    /// The default value is 8 KiB, which is suitable for many FastCGI
    /// applications and clients. However, if the application expects large
    /// inputs (like file uploads), a value in the 10s to 100s of KiB might be
    /// reasonable. Much higher numbers are usually not needed as the OS already
    /// buffers network data.
    ///
    /// **Note:** At a minimum, the buffer needs to be large enough to hold the
    /// longest HTTP header (name and value) that may be passed by the FastCGI
    /// client, plus 13 extra bytes. `buffer_size` should therefore generally
    /// not be less than 8 KiB.
    pub buffer_size: usize,

    /// The maximum number of concurrent FastCGI connections from the client.
    ///
    /// This parameter effectively defines the maximum amount of concurrency
    /// this crate will exhibit. Each connection supports one request at a time
    /// (that is, no multiplexing).
    ///
    /// The default is set to the OS's [reported parallelism][ncpus], such as
    /// the number of available CPU cores. This is often appropriate for
    /// compute-bound workloads with the FastCGI client on `localhost`. If
    /// using `async` APIs or networked operations, a much higher number may
    /// be advisable.
    ///
    /// [ncpus]: std::thread::available_parallelism
    pub max_conns: NonZeroUsize,
}

impl Config {
    /// Buffer size to balance syscall overhead with memory usage.
    const DEFAULT_BUF_SIZE: usize = 8192;

    /// Creates a new [`Config`] with all settings set to their
    /// documented defaults.
    #[must_use = "Creating a Config is not free and has no side effects"]
    pub fn new() -> Self {
        let concurrency = std::thread::available_parallelism()
            .unwrap_or(1.try_into().expect("fallback should be nonzero"));
        Self::with_conns(concurrency)
    }

    /// Creates a new [`Config`] with defaults for all settings but `max_conns`.
    ///
    /// Calculating the default for `max_conns` in `Config::new` can be
    /// expensive depending on the OS setup. This function should be used if
    /// `max_conns` is to be customized. Other settings can then either be left
    /// at their defaults or changed directly on the returned instance.
    #[inline]
    #[must_use]
    pub fn with_conns(max_conns: NonZeroUsize) -> Self {
        Self { buffer_size: Self::DEFAULT_BUF_SIZE, max_conns }
    }

    /// Aligns `buffer_size` upwards according to FastCGI recommendations.
    #[inline]
    #[must_use]
    const fn aligned_bufsize(&self) -> usize {
        // Minimum buffer size required for statically-known parsing units
        // - fcgi::RecordHeader::LEN + fcgi::body::BeginRequest::LEN (16)
        // - Longest expected GetValues name-value pair (17)
        const MIN_BUF_SIZE: usize = 24;
        if self.buffer_size <= MIN_BUF_SIZE {
            return MIN_BUF_SIZE;
        }
        // Align to multiple of 8 bytes to match FastCGI recommended padding
        match self.buffer_size.checked_add(7) {
            Some(r) => r & !7,
            None => self.buffer_size,
        }
    }
}

impl Default for Config {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use std::iter::repeat_with;
    use super::*;
    use crate::protocol as fcgi;

    #[test]
    fn config_bufsize() {
        const BEGIN_REC_LEN: usize = fcgi::RecordHeader::LEN + fcgi::body::BeginRequest::LEN;
        let (max_var, _) =
            fcgi::ProtocolVariables::all().iter_names().max_by_key(|(n, _)| n.len()).unwrap();
        let max_var_nv = fcgi::nv::write((max_var.as_bytes(), b""), std::io::sink()).unwrap();

        let mut config = Config { buffer_size: 0, max_conns: 1.try_into().unwrap() };
        assert!(config.aligned_bufsize() >= BEGIN_REC_LEN);
        assert!(config.aligned_bufsize() >= max_var_nv);

        config.buffer_size = Config::DEFAULT_BUF_SIZE;
        assert_eq!(config.aligned_bufsize(), Config::DEFAULT_BUF_SIZE);

        let rand_size = repeat_with(|| fastrand::usize(..)).take(50);
        for s in rand_size.chain([0, 1, 50, 255, Config::DEFAULT_BUF_SIZE]) {
            config.buffer_size = s;
            assert_eq!(config.aligned_bufsize() % 8, 0);
        }
    }
}
