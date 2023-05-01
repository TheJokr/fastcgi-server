use super::Error as ProtocolError;
use super::{ProtocolStatus, RequestFlags, Role};


/// The body of a [`RecordType::Unknown`] FastCGI record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnknownType {
    /// The type of the unknown record.
    pub rtype: u8,
}

impl UnknownType {
    /// Parses the input bytes into a FastCGI [`UnknownType`] record body.
    #[inline]
    #[must_use]
    pub fn from_bytes(data: [u8; 8]) -> Self {
        Self { rtype: data[0] }
    }

    /// Encodes the [`UnknownType`] record body into its binary wire format.
    #[inline]
    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        let mut buf = [0; 8];
        buf[0] = self.rtype;
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
    /// Parses the input bytes into a FastCGI [`BeginRequest`] record body.
    ///
    /// # Errors
    /// Returns an error if any of the body components are invalid.
    pub fn from_bytes(data: [u8; 8]) -> Result<Self, ProtocolError> {
        let role = u16::from_be_bytes([data[0], data[1]]);
        Ok(Self {
            role: Role::try_from(role)?,
            flags: RequestFlags::try_from(data[2])?,
        })
    }

    /// Encodes the [`BeginRequest`] record body into its binary wire format.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        let mut buf = [0; 8];
        buf[..2].copy_from_slice(&u16::to_be_bytes(self.role.into()));
        buf[2] = self.flags.into();
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
    /// Parses the input bytes into a FastCGI [`EndRequest`] record body.
    ///
    /// # Errors
    /// Returns an error if any of the body components are invalid.
    pub fn from_bytes(data: [u8; 8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            app_status: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            protocol_status: ProtocolStatus::try_from(data[4])?,
        })
    }

    /// Encodes the [`EndRequest`] record body into its binary wire format.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        let mut buf = [0; 8];
        buf[..4].copy_from_slice(&u32::to_be_bytes(self.app_status));
        buf[4] = self.protocol_status.into();
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
        for rtype in rand_rt.chain([0, 1, 246, u8::MAX]) {
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
        Ok(())
    }

    #[test]
    fn beginrequest_invalid() {
        const BAD_ROLE: [u8; 8] = [0xa3, 0x03, 0x00, 0xf1, 0x34, 0x51, 0xb2, 0x19];
        let bad_role = BeginRequest::from_bytes(BAD_ROLE);
        assert!(matches!(bad_role, Err(ProtocolError::UnknownRole(0xa303))));

        const BAD_FLAGS: [u8; 8] = [0x00, 0x01, 0xf7, 0x65, 0x5c, 0x91, 0x2d, 0x00];
        let bad_flags = BeginRequest::from_bytes(BAD_FLAGS);
        assert!(matches!(bad_flags, Err(ProtocolError::UnknownFlags(0xf6))));
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
    fn endrequest_invalid() {
        const BAD_STATUS: [u8; 8] = [0xbf, 0x23, 0x4d, 0x4d, 0x6a, 0x03, 0xc1, 0x0f];
        let bad_status = EndRequest::from_bytes(BAD_STATUS);
        assert!(matches!(bad_status, Err(ProtocolError::UnknownStatus(0x6a))));
    }
}
