use std::fmt;

use super::Error as ProtocolError;


/// A validated FastCGI version number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, strum::FromRepr)]
pub enum Version {
    /// FastCGI Version 1
    V1 = 1,
}

impl TryFrom<u8> for Version {
    type Error = ProtocolError;

    /// Parses a [`u8`] as a FastCGI [`Version`].
    ///
    /// # Errors
    /// Returns an error if the [`u8`] is not a valid version identifier.
    #[inline]
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Self::from_repr(v.into())
            .ok_or(ProtocolError::UnknownVersion(v))
    }
}

impl From<Version> for u8 {
    #[inline]
    fn from(v: Version) -> Self {
        v as Self
    }
}


/// A validated FastCGI role identifier.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, strum::FromRepr)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum Role {
    Responder = 1,
    Authorizer = 2,
    Filter = 3,
}

impl TryFrom<u16> for Role {
    type Error = ProtocolError;

    /// Parses a [`u16`] as a FastCGI [`Role`].
    ///
    /// # Errors
    /// Returns an error if the [`u16`] is not a valid role identifier.
    #[inline]
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Self::from_repr(v.into())
            .ok_or(ProtocolError::UnknownRole(v))
    }
}

impl From<Role> for u16 {
    #[inline]
    fn from(v: Role) -> Self {
        v as Self
    }
}

impl Role {
    /// Tests whether the given [`RecordType`] is a valid stream record
    /// for this [`Role`].
    #[must_use]
    pub fn is_stream_ok(self, record: RecordType) -> bool {
        use RecordType::*;
        #[allow(clippy::match_like_matches_macro)]
        match (self, record) {
            (_, Params | Stderr) => true,
            (Self::Responder, Stdin | Stdout) => true,
            (Self::Authorizer, Stdout) => true,
            (Self::Filter, Stdin | Data | Stdout) => true,
            _ => false,
        }
    }
}


bitflags::bitflags! {
    /// A set of FastCGI request flags.
    #[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RequestFlags: u8 {
        /// Keep the connection open after processing this request.
        const KeepConn = 1;
    }
}

impl From<u8> for RequestFlags {
    /// Converts a [`u8`] into a FastCGI [`RequestFlags`] set.
    ///
    /// Any non-standard flags are retained during the conversion. The set can
    /// be manually validated using `RequestFlags::validate`.
    #[inline]
    fn from(v: u8) -> Self {
        Self::from_bits_retain(v)
    }
}

impl From<RequestFlags> for u8 {
    #[inline]
    fn from(v: RequestFlags) -> Self {
        v.bits()
    }
}

impl fmt::Debug for RequestFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RequestFlags({self:#010b})")
    }
}

impl RequestFlags {
    /// Validates whether the [`RequestFlags`] set contains any non-standard flags.
    ///
    /// # Errors
    /// Returns a [`ProtocolError::UnknownFlags`] if any of the set's flags is not
    /// part of the FastCGI specification.
    pub fn validate(self) -> Result<(), ProtocolError> {
        let raw = self.bits();
        let trunc = Self::from_bits_truncate(raw).bits();
        if raw == trunc {
            Ok(())
        } else {
            // Some bit(s) got truncated
            let unk = raw & !trunc;
            Err(ProtocolError::UnknownFlags(unk))
        }
    }
}


/// A validated FastCGI response protocol status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, strum::FromRepr)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum ProtocolStatus {
    /// The request completed successfully.
    RequestComplete = 0,
    /// A second, multiplexed request was received and the FastCGI application
    /// does not support multiplexing.
    CantMpxConn = 1,
    /// The FastCGI application is already handling its maximum number
    /// of parallel requests.
    Overloaded = 2,
    /// The FastCGI application does not implement the requested role.
    UnknownRole = 3,
}

impl TryFrom<u8> for ProtocolStatus {
    type Error = ProtocolError;

    /// Parses a [`u8`] as a FastCGI [`ResponseStatus`].
    ///
    /// # Errors
    /// Returns an error if the [`u8`] is not a valid response protocol status.
    #[inline]
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Self::from_repr(v.into())
            .ok_or(ProtocolError::UnknownStatus(v))
    }
}

impl From<ProtocolStatus> for u8 {
    #[inline]
    fn from(v: ProtocolStatus) -> Self {
        v as Self
    }
}


/// A validated FastCGI record type.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, strum::FromRepr)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum RecordType {
    BeginRequest = 1,
    AbortRequest = 2,
    EndRequest = 3,
    Params = 4,
    Stdin = 5,
    Stdout = 6,
    Stderr = 7,
    Data = 8,
    GetValues = 9,
    GetValuesResult = 10,
    Unknown = 11,
}

impl TryFrom<u8> for RecordType {
    type Error = ProtocolError;

    /// Parses a [`u8`] as a FastCGI [`RecordType`].
    ///
    /// # Errors
    /// Returns an error if the [`u8`] is not a valid record type.
    #[inline]
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Self::from_repr(v.into())
            .ok_or(ProtocolError::UnknownRecordType(v))
    }
}

impl From<RecordType> for u8 {
    #[inline]
    fn from(v: RecordType) -> Self {
        v as Self
    }
}

impl RecordType {
    /// Tests whether this [`RecordType`] represents a management record.
    #[inline]
    #[must_use]
    pub fn is_management(self) -> bool {
        matches!(self, Self::GetValues | Self::GetValuesResult | Self::Unknown)
    }

    /// Tests whether this [`RecordType`] represents an input stream record.
    #[inline]
    #[must_use]
    pub fn is_input_stream(self) -> bool {
        matches!(self, Self::Stdin | Self::Data)
    }

    /// Tests whether this [`RecordType`] represents an output stream record.
    #[inline]
    #[must_use]
    pub fn is_output_stream(self) -> bool {
        matches!(self, Self::Stdout | Self::Stderr)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_reqflag_overlap() {
        let mut seen = RequestFlags::empty();
        for f in RequestFlags::all() {
            assert!(!seen.intersects(f), "{} overlaps with {}", f.0, seen.0);
            seen.insert(f);
        }
    }

    #[test]
    fn reqflag_validate() {
        let flags = RequestFlags::all();
        assert!(matches!(flags.validate(), Ok(())));

        let flags = RequestFlags::from(0x39);
        assert!(matches!(flags.validate(), Err(ProtocolError::UnknownFlags(0x38))));
    }
}
