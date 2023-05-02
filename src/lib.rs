// TODO(docs): #![deny(missing_docs)]
#![deny(unsafe_code, single_use_lifetimes, unused_lifetimes, pointer_structural_match)]
#![warn(keyword_idents, let_underscore_drop, unreachable_pub, unused_import_braces)]

#![deny(clippy::suspicious, clippy::cargo)]
#![deny(clippy::exit, clippy::semicolon_inside_block, clippy::unwrap_used)]
#![warn(clippy::pedantic, clippy::multiple_crate_versions)]
#![allow(clippy::enum_glob_use, clippy::items_after_statements)]


/// Helpful extension traits shared across the crate.
pub(crate) mod ext;

// TODO(docs): Based on FastCGI spec (especially Section 8)
// See: https://fastcgi-archives.github.io/FastCGI_Specification.html
pub mod protocol;

// TODO(docs): Helpers for CGI/1.1 requests/responses
pub mod cgi;
