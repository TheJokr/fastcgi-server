/// Types representing the bodies of fixed-size FastCGI records.
pub mod body;
mod fields;
/// An encoder and decoder for FastCGI name-value pairs.
pub mod nv;
/// An encoder and decoder for FastCGI's variable-length integers.
pub mod varint;
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


/// Error types that may occur while processing FastCGI protocol elements.
#[derive(Debug, Clone, thiserror::Error)]
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
    /// The FastCGI variable name did not match any well-known value.
    #[error("unknown FastCGI protocol variable name")]
    UnknownVariable,

    /// The input value is too large to be encoded as a FastCGI VarInt.
    #[error("input is too large to be encoded as a FastCGI VarInt")]
    InvalidVarInt,
}


/// A FastCGI record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub const LEN: usize = 8;

    /// Parses the input bytes into a FastCGI [`RecordHeader`].
    ///
    /// # Errors
    /// Returns an error if any of the header components are invalid.
    pub fn from_bytes(data: [u8; Self::LEN]) -> Result<Self, Error> {
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
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut buf = [0; Self::LEN];
        buf[0] = self.version.into();
        buf[1] = self.rtype.into();
        buf[2..4].copy_from_slice(&u16::to_be_bytes(self.request_id));
        buf[4..6].copy_from_slice(&u16::to_be_bytes(self.content_length));
        buf[6] = self.padding_length;
        buf
    }
}


#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;
    use super::*;

    #[test]
    fn header_roundtrip() -> Result<(), Error> {
        for rtype in RecordType::iter() {
            let orig = RecordHeader {
                version: Version::V1, rtype, request_id: fastrand::u16(..),
                content_length: fastrand::u16(..), padding_length: fastrand::u8(..),
            };
            let rt = RecordHeader::from_bytes(orig.to_bytes())?;
            assert_eq!(orig, rt);
        }
        Ok(())
    }

    #[test]
    fn header_spec() -> Result<(), Error> {
        const GOOD: [u8; 8] = [0x01, 0x09, 0x46, 0xaf, 0x32, 0xa4, 0x8b, 0x00];
        let head = RecordHeader::from_bytes(GOOD)?;
        assert_eq!(head.version, Version::V1);
        assert_eq!(head.rtype, RecordType::GetValues);
        assert_eq!(head.request_id, 0x46af);
        assert_eq!(head.content_length, 0x32a4);
        assert_eq!(head.padding_length, 0x8b);
        Ok(())
    }

    #[test]
    fn header_invalid() {
        const BAD_VERSION: [u8; 8] = [0xe5, 0x03, 0xc8, 0xf4, 0xe0, 0xa3, 0x76, 0xa8];
        let bad_version = RecordHeader::from_bytes(BAD_VERSION);
        assert!(matches!(bad_version, Err(Error::UnknownVersion(0xe5))));

        const BAD_RTYPE: [u8; 8] = [0x01, 0x7a, 0xdb, 0x58, 0x1b, 0x4b, 0x87, 0x6b];
        let bad_rtype = RecordHeader::from_bytes(BAD_RTYPE);
        assert!(matches!(bad_rtype, Err(Error::UnknownRecordType(0x7a))));
    }

    #[test]
    fn is_mgmt() {
        use RecordType::*;
        for rtype in [GetValues, GetValuesResult, Unknown] {
            let mut head = RecordHeader {
                version: Version::V1, rtype, request_id: FCGI_NULL_REQUEST_ID,
                content_length: fastrand::u16(..), padding_length: fastrand::u8(..),
            };
            assert!(head.is_management());
            head.request_id = fastrand::u16(1..);
            assert!(!head.is_management());
        }

        let mut head = RecordHeader {
            version: Version::V1, rtype: RecordType::BeginRequest,
            request_id: FCGI_NULL_REQUEST_ID, content_length: fastrand::u16(..),
            padding_length: fastrand::u8(..),
        };
        assert!(!head.is_management());
        head.request_id = fastrand::u16(1..);
        assert!(!head.is_management());
    }
}
