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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, strum::FromRepr)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum Role {
    /// A FastCGI responder generates a [CGI/1.1-style][resp] HTTP response for
    /// an HTTP request.
    ///
    /// This role is equivalent to a regular CGI/1.1 program, but uses FastCGI
    /// streams for communication.
    ///
    /// # Available Streams
    /// | Direction | Streams                                        |
    /// | :-------- | ---------------------------------------------- |
    /// | Input     | [`RecordType::Stdin`]                          |
    /// | Output    | [`RecordType::Stdout`], [`RecordType::Stderr`] |
    ///
    /// [resp]: https://www.rfc-editor.org/rfc/rfc3875.html#section-6
    Responder = 1,

    /// A FastCGI authorizer decides whether an HTTP request should be processed
    /// by the webserver.
    ///
    /// A positive decision is indicated by a `200 OK` response without a body.
    /// Otherwise, if access shall be denied, a regular non-`200 OK` response
    /// must be returned (like [`Role::Responder`]).
    ///
    /// # Available Streams
    /// | Direction | Streams                                        |
    /// | :-------- | ---------------------------------------------- |
    /// | Input     | *None*                                         |
    /// | Output    | [`RecordType::Stdout`], [`RecordType::Stderr`] |
    Authorizer = 2,

    /// A FastCGI filter is a responder that receives an additional input stream
    /// from the FastCGI client.
    ///
    /// # Available Streams
    /// | Direction | Streams                                        |
    /// | :-------- | ---------------------------------------------- |
    /// | Input     | [`RecordType::Stdin`], [`RecordType::Data`]    |
    /// | Output    | [`RecordType::Stdout`], [`RecordType::Stderr`] |
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
    /// Returns the expected input stream [`RecordType`] values for this [`Role`].
    ///
    /// Input streams must be received one after the other in the order given
    /// in the slice, according to the FastCGI specification. The enum variants'
    /// documentation also lists the order for reference.
    #[must_use]
    pub fn input_streams(self) -> &'static [RecordType] {
        use RecordType::*;
        match self {
            Self::Responder => &[Stdin],
            Self::Authorizer => &[],
            Self::Filter => &[Stdin, Data],
        }
    }

    /// Returns the next expected input stream [`RecordType`] for this [`Role`]
    /// after `current`.
    ///
    /// If `current` is [`None`], the first expected input stream type is
    /// returned. Otherwise, `current` should be one of the input stream types
    /// from `Role::input_streams`. This is verified by a debug assertion.
    ///
    /// A return value of [`None`] indicates that no further input streams are
    /// expected.
    ///
    /// # Examples
    /// This function is equivalent to `next_stream` below, but more efficient.
    /// ```
    /// use fastcgi_server::protocol::{Role, RecordType};
    /// fn next_stream(role: Role, current: Option<RecordType>) -> Option<RecordType> {
    ///     let mut it = role.input_streams().iter().copied();
    ///     if let Some(cur) = current {
    ///         it.find(|&s| s == cur);
    ///     }
    ///     it.next()
    /// }
    ///
    /// let role = Role::Filter;
    /// let current = Some(RecordType::Stdin);
    /// assert_eq!(role.next_input_stream(current), next_stream(role, current));
    /// assert_eq!(role.next_input_stream(current), Some(RecordType::Data));
    /// ```
    #[must_use]
    pub fn next_input_stream(self, current: Option<RecordType>) -> Option<RecordType> {
        use RecordType::*;
        debug_assert!(
            current.map_or(true, |s| self.input_streams().contains(&s)),
            "{current:?} is not a valid input stream type for {self:?}",
        );
        match (self, current) {
            (Self::Responder | Self::Filter, None) => Some(Stdin),
            (Self::Filter, Some(Stdin)) => Some(Data),
            _ => None,
        }
    }

    /// Returns the allowed output stream [`RecordType`] values for this [`Role`].
    ///
    /// The order is insignificant as output stream records may be mixed freely.
    /// See the enum variants' documentation for a textual description.
    #[inline]
    #[must_use]
    pub fn output_streams(self) -> &'static [RecordType] {
        use RecordType::*;
        // Same for all standardized roles
        &[Stdout, Stderr]
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
    use strum::IntoEnumIterator;
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
        assert!(flags.validate().is_ok());

        let flags = RequestFlags::from(0x39);
        assert!(matches!(flags.validate(), Err(ProtocolError::UnknownFlags(0x38))));
    }

    #[test]
    fn role_streams() {
        for role in Role::iter() {
            let mut state = None;
            let comp: Vec<_> = std::iter::from_fn(|| {
                state = role.next_input_stream(state);
                state
            }).fuse().collect();
            assert_eq!(comp, role.input_streams());
        }
    }
}
