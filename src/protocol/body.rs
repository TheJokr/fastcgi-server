use super::Error as ProtocolError;
use super::{ProtocolStatus, RequestFlags, Role};


/// The body of a [`RecordType::Unknown`] FastCGI record.
#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
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
