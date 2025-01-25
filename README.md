# fastcgi-server
[![CI Status](https://github.com/TheJokr/fastcgi-server/actions/workflows/ci.yml/badge.svg)](https://github.com/TheJokr/fastcgi-server/actions/workflows/ci.yml)
[![Crate MSRV](https://img.shields.io/badge/msrv-1.66-blue)](Cargo.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0%2FMIT-informational)](#license)

A safe Rust implementation of FastCGI on the server (aka handler/upstream) side.
The library focuses on generality and performance, avoiding allocations and data
copies where possible. It exposes both an easy-to-use high-level request/response
interface as well as lower-level FastCGI primitives for customized operations.

## Alternative FastCGI crates
| Name | Differences | Concurrency | License |
| ---- | ----------- | ----------- | ------- |
| [fastcgi](https://crates.io/crates/fastcgi) | Server, allocation-heavy, no tests | Threaded | MIT |
| [gfcgi](https://crates.io/crates/gfcgi) | Server, incomplete, officially abandoned | Threaded | MIT |
| [outer_cgi](https://crates.io/crates/outer_cgi) | Hybrid CGI/FastCGI server, `unsafe`-heavy, no tests | Threaded | zlib |
| [tokio-fastcgi](https://crates.io/crates/tokio-fastcgi) | Server, requires `tokio`, supports multiplexing, fully buffers input streams, limited testing | Async | Apache 2.0 |
| [fastcgi-client](https://crates.io/crates/fastcgi-client) | Client, requires `tokio`, limited testing | Async | Apache 2.0 |
| [async-fcgi](https://crates.io/crates/async-fcgi) | Purpose-built webserver client, requires `tokio` | Async | AGPL 3.0 |

## License
fastcgi-server is licensed under either the [Apache License (Version 2.0)](LICENSE-APACHE)
or the [MIT License](LICENSE-MIT) at your option.

## Contributing
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
