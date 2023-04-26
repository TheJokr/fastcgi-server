use std::io;

pub mod body;
mod fields;
pub mod nv;
mod varint;
mod vars;

pub use fields::*;
pub use vars::*;


/// The fixed FastCGI request ID for management records.
pub const FCGI_NULL_REQUEST_ID: u16 = 0;

/// The socket file descriptor passed to a FastCGI application, if it was
/// spawned directly by an HTTP server.
///
/// # Example
/// TODO(docs): show how to create a Listener from the RawFd
#[cfg(any(target_family = "unix", target_family = "wasm"))]
pub const FCGI_LISTENSOCK_FILENO: std::os::fd::RawFd = 0;


/// Error types that may occur while parsing a FastCGI record stream.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The FastCGI version field specifies an unknown version identifier.
    #[error("unknown FastCGI protocol version {0}")]
    UnknownVersion(u8),
    /// The FastCGI record type field specifies an unknown record type.
    #[error("unknown FastCGI record type {0}")]
    UnknownRecordType(u8),
    /// The FastCGI request role field specifies an unknown role identifier.
    #[error("unknown FastCGI role {0}")]
    UnknownRole(u16),
    /// The FastCGI request flags contain at least one unknown flag bit.
    #[error("unknown FastCGI request flags {0:#010b}")]
    UnknownFlags(u8),
    /// The FastCGI response protocol status specifies an unknown status.
    #[error("unknown FastCGI protocol status {0}")]
    UnknownStatus(u8),
    /// The FastCGI variable name did not match any well-known name.
    #[error("unknown FastCGI variable name {0}")]
    UnknownVariable(Box<str>),

    /// The input value is too large to be encoded as a FastCGI VarInt.
    #[error("input is too large to be encoded as a FastCGI VarInt")]
    InvalidVarInt,

    /// An unexpected error occured during an IO operation. This can only
    /// happen in functions taking a generic [`Read`] or [`Write`] parameter.
    #[error(transparent)]
    Io(#[from] io::Error),
}


/// A FastCGI record header.
#[derive(Debug, Clone, Copy)]
pub struct RecordHeader {
    /// The FastCGI version of this record.
    pub version: Version,
    /// The type of this record, defining its payload.
    pub rtype: RecordType,
    /// The ID of the request this record belongs to.
    pub request_id: u16,
    /// The length of this record's payload.
    pub content_length: u16,
    /// The amount of padding following this record.
    pub padding_length: u8,
}

impl RecordHeader {
    /// Tests whether this [`RecordHeader`] represents a management record.
    #[inline]
    #[must_use]
    pub fn is_management(&self) -> bool {
        self.rtype.is_management() && self.request_id == FCGI_NULL_REQUEST_ID
    }

    /// Tests whether this [`RecordHeader`] represents a stream record.
    #[inline]
    #[must_use]
    pub fn is_stream(&self) -> bool {
        self.rtype.is_stream()
    }

    /// The number of bytes in the wire format of a [`RecordHeader`].
    pub const FCGI_HEADER_LEN: usize = 8;

    /// Parses the input bytes into a FastCGI [`RecordHeader`].
    ///
    /// # Errors
    /// Returns an error if any of the header components are invalid.
    pub fn from_bytes(data: [u8; Self::FCGI_HEADER_LEN]) -> Result<Self, Error> {
        Ok(Self {
            version: Version::try_from(data[0])?,
            rtype: RecordType::try_from(data[1])?,
            request_id: u16::from_be_bytes([data[2], data[3]]),
            content_length: u16::from_be_bytes([data[4], data[5]]),
            padding_length: data[6],
        })
    }

    /// Encodes the [`RecordHeader`] into its binary wire format.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::FCGI_HEADER_LEN] {
        let mut buf = [0; Self::FCGI_HEADER_LEN];
        buf[0] = self.version.into();
        buf[1] = self.rtype.into();
        buf[2..4].copy_from_slice(&u16::to_be_bytes(self.request_id));
        buf[4..6].copy_from_slice(&u16::to_be_bytes(self.content_length));
        buf[6] = self.padding_length;
        buf
    }
}
