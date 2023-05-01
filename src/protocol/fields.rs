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
    /// A validated set of FastCGI request flags.
    #[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RequestFlags: u8 {
        /// Keep the connection open after processing this request.
        const KeepConn = 1;
    }
}

impl TryFrom<u8> for RequestFlags {
    type Error = ProtocolError;

    /// Parses a [`u8`] as a FastCGI [`RequestFlags`] set.
    ///
    /// # Errors
    /// Returns an error if the [`u8`] is not a valid set of request flags.
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        let f = Self::from_bits_truncate(v);
        if f.bits() == v {
            Ok(f)
        } else {
            // Some bit(s) got truncated
            let unk = v & !f.bits();
            Err(ProtocolError::UnknownFlags(unk))
        }
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
        const UNUSED_BITS: u32 = RequestFlags::all().bits().leading_zeros();
        const WIDTH: usize = 2 /* 0b */ + 8 /* bits */ - (UNUSED_BITS as usize);
        write!(f, "RequestFlags({self:#0WIDTH$b})")
    }
}


/// A validated FastCGI response protocol status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, strum::FromRepr)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum ProtocolStatus {
    /// The request completed successfully.
    RequestComplete = 0,
    /// A second, multiplexed request was received and the FastCGI application
    /// doesn't support multiplexing.
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
        use RecordType::*;
        matches!(self, GetValues | GetValuesResult | Unknown)
    }

    /// Tests whether this [`RecordType`] represents a stream record.
    #[inline]
    #[must_use]
    pub fn is_stream(self) -> bool {
        use RecordType::*;
        matches!(self, Params | Stdin | Stdout | Stderr | Data)
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
}
