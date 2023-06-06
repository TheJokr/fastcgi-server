use super::Error as ProtocolError;
use super::{ProtocolStatus, RecordHeader, RecordType, RequestFlags, Role, Version};


/// The body of a [`RecordType::Unknown`] FastCGI record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnknownType {
    /// The type of the unknown record.
    pub rtype: u8,
}

impl UnknownType {
    /// The number of bytes in the wire format of an [`UnknownType`] body.
    pub const LEN: usize = 8;

    /// Parses the input bytes into a FastCGI [`UnknownType`] record body.
    #[inline]
    #[must_use]
    pub fn from_bytes(data: [u8; Self::LEN]) -> Self {
        Self { rtype: data[0] }
    }

    /// Encodes the [`UnknownType`] record body into its binary wire format.
    #[inline]
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut buf = [0; Self::LEN];
        buf[0] = self.rtype;
        buf
    }

    /// Encodes a full [`UnknownType`] record into its binary wire format.
    #[must_use]
    pub fn to_record(self, request_id: u16) -> [u8; RecordHeader::LEN + Self::LEN] {
        let head = RecordHeader {
            version: Version::V1, rtype: RecordType::Unknown,
            request_id, content_length: Self::LEN as u16, padding_length: 0,
        }.to_bytes();
        let body = self.to_bytes();

        let mut buf = [0; RecordHeader::LEN + Self::LEN];
        buf[..RecordHeader::LEN].copy_from_slice(&head);
        buf[RecordHeader::LEN..].copy_from_slice(&body);
        buf
    }
}


/// The body of a [`RecordType::BeginRequest`] FastCGI record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BeginRequest {
    /// The role of the FastCGI application in this request.
    pub role: Role,
    /// The control flags for this request.
    pub flags: RequestFlags,
}

impl BeginRequest {
    /// The number of bytes in the wire format of a [`BeginRequest`] body.
    pub const LEN: usize = 8;

    /// Parses the input bytes into a FastCGI [`BeginRequest`] record body.
    ///
    /// # Errors
    /// Returns an error if any of the body components are invalid.
    pub fn from_bytes(data: [u8; Self::LEN]) -> Result<Self, ProtocolError> {
        let role = u16::from_be_bytes([data[0], data[1]]);
        Ok(Self { role: Role::try_from(role)?, flags: RequestFlags::from(data[2]) })
    }

    /// Encodes the [`BeginRequest`] record body into its binary wire format.
    #[inline]
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut buf = [0; Self::LEN];
        buf[..2].copy_from_slice(&u16::to_be_bytes(self.role.into()));
        buf[2] = self.flags.into();
        buf
    }

    /// Encodes a full [`BeginRequest`] record into its binary wire format.
    #[must_use]
    pub fn to_record(self, request_id: u16) -> [u8; RecordHeader::LEN + Self::LEN] {
        let head = RecordHeader {
            version: Version::V1, rtype: RecordType::BeginRequest,
            request_id, content_length: Self::LEN as u16, padding_length: 0,
        }.to_bytes();
        let body = self.to_bytes();

        let mut buf = [0; RecordHeader::LEN + Self::LEN];
        buf[..RecordHeader::LEN].copy_from_slice(&head);
        buf[RecordHeader::LEN..].copy_from_slice(&body);
        buf
    }
}


/// The body of a [`RecordType::EndRequest`] FastCGI record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndRequest {
    /// The application's response status code, as would be set via exit(3)
    /// in regular CGI.
    pub app_status: u32,
    /// The protocol status code for this response.
    pub protocol_status: ProtocolStatus,
}

impl EndRequest {
    /// The number of bytes in the wire format of an [`EndRequest`] body.
    pub const LEN: usize = 8;

    /// Parses the input bytes into a FastCGI [`EndRequest`] record body.
    ///
    /// # Errors
    /// Returns an error if any of the body components are invalid.
    pub fn from_bytes(data: [u8; Self::LEN]) -> Result<Self, ProtocolError> {
        Ok(Self {
            app_status: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            protocol_status: ProtocolStatus::try_from(data[4])?,
        })
    }

    /// Encodes the [`EndRequest`] record body into its binary wire format.
    #[inline]
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut buf = [0; Self::LEN];
        buf[..4].copy_from_slice(&self.app_status.to_be_bytes());
        buf[4] = self.protocol_status.into();
        buf
    }

    /// Encodes a full [`EndRequest`] record into its binary wire format.
    #[must_use]
    pub fn to_record(self, request_id: u16) -> [u8; RecordHeader::LEN + Self::LEN] {
        let head = RecordHeader {
            version: Version::V1, rtype: RecordType::EndRequest,
            request_id, content_length: Self::LEN as u16, padding_length: 0,
        }.to_bytes();
        let body = self.to_bytes();

        let mut buf = [0; RecordHeader::LEN + Self::LEN];
        buf[..RecordHeader::LEN].copy_from_slice(&head);
        buf[RecordHeader::LEN..].copy_from_slice(&body);
        buf
    }
}


#[cfg(test)]
mod tests {
    use std::iter::repeat_with;
    use strum::IntoEnumIterator;
    use super::*;

    #[test]
    fn unknown_roundtrip() {
        let rand_rt = repeat_with(|| fastrand::u8(..)).take(5);
        for rtype in rand_rt.chain([0, 1, 82, 246, u8::MAX]) {
            let orig = UnknownType { rtype };
            let rt = UnknownType::from_bytes(orig.to_bytes());
            assert_eq!(orig, rt);
        }
    }

    #[test]
    fn unknown_spec() {
        const GOOD: [u8; 8] = [0xe7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let body = UnknownType::from_bytes(GOOD);
        assert_eq!(body.rtype, 0xe7);
    }

    #[test]
    fn unknown_record() {
        const REF: [u8; 16] = [
            0x01, 0x0b, 0x76, 0xa8, 0x00, 0x08, 0x00, 0x00,
            0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let record = UnknownType { rtype: 0xf6 }.to_record(0x76a8);
        assert_eq!(record, REF);
    }

    #[test]
    fn beginrequest_roundtrip() -> Result<(), ProtocolError> {
        for role in Role::iter() {
            for flags in [RequestFlags::empty(), RequestFlags::KeepConn] {
                let orig = BeginRequest { role, flags };
                let rt = BeginRequest::from_bytes(orig.to_bytes())?;
                assert_eq!(orig, rt);
            }
        }
        Ok(())
    }

    #[test]
    fn beginrequest_spec() -> Result<(), ProtocolError> {
        const GOOD: [u8; 8] = [0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        let body = BeginRequest::from_bytes(GOOD)?;
        assert_eq!(body.role, Role::Responder);
        assert_eq!(body.flags, RequestFlags::KeepConn);

        const BAD_FLAGS: [u8; 8] = [0x00, 0x01, 0xf7, 0x65, 0x5c, 0x91, 0x2d, 0x00];
        let bad_flags = BeginRequest::from_bytes(BAD_FLAGS)?;
        assert_eq!(bad_flags.role, Role::Responder);
        assert_eq!(bad_flags.flags.bits(), 0xf7);
        Ok(())
    }

    #[test]
    fn beginrequest_record() {
        const REF: [u8; 16] = [
            0x01, 0x01, 0xfb, 0x2a, 0x00, 0x08, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let record =
            BeginRequest { role: Role::Authorizer, flags: RequestFlags::empty() }.to_record(0xfb2a);
        assert_eq!(record, REF);
    }

    #[test]
    fn beginrequest_invalid() {
        const BAD_ROLE: [u8; 8] = [0xa3, 0x03, 0x00, 0xf1, 0x34, 0x51, 0xb2, 0x19];
        let bad_role = BeginRequest::from_bytes(BAD_ROLE);
        assert!(matches!(bad_role, Err(ProtocolError::UnknownRole(0xa303))));
    }

    #[test]
    fn endrequest_roundtrip() -> Result<(), ProtocolError> {
        let rand_u32 = repeat_with(|| fastrand::u32(..)).take(10);
        for app_status in rand_u32.chain([0, 1, 178, 28825, u32::MAX]) {
            for protocol_status in ProtocolStatus::iter() {
                let orig = EndRequest { app_status, protocol_status };
                let rt = EndRequest::from_bytes(orig.to_bytes())?;
                assert_eq!(orig, rt);
            }
        }
        Ok(())
    }

    #[test]
    fn endrequest_spec() -> Result<(), ProtocolError> {
        const GOOD: [u8; 8] = [0x57, 0xfe, 0x26, 0x57, 0x00, 0x00, 0x00, 0x00];
        let body = EndRequest::from_bytes(GOOD)?;
        assert_eq!(body.app_status, 0x57fe_2657);
        assert_eq!(body.protocol_status, ProtocolStatus::RequestComplete);
        Ok(())
    }

    #[test]
    fn endrequest_record() {
        const REF: [u8; 16] = [
            0x01, 0x03, 0x41, 0xfd, 0x00, 0x08, 0x00, 0x00,
            0xd9, 0xf3, 0x2e, 0x7c, 0x02, 0x00, 0x00, 0x00,
        ];
        let record =
            EndRequest { app_status: 0xd9f3_2e7c, protocol_status: ProtocolStatus::Overloaded }
                .to_record(0x41fd);
        assert_eq!(record, REF);
    }

    #[test]
    fn endrequest_invalid() {
        const BAD_STATUS: [u8; 8] = [0xbf, 0x23, 0x4d, 0x4d, 0x6a, 0x03, 0xc1, 0x0f];
        let bad_status = EndRequest::from_bytes(BAD_STATUS);
        assert!(matches!(bad_status, Err(ProtocolError::UnknownStatus(0x6a))));
    }
}
