use std::fmt;
use std::io::{self, prelude::*};

use super::Error as ProtocolError;


/// A [`u32`] which can be variably encoded in either 1 or 4 bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VarInt(u32);

impl VarInt {
    /// The bit indicating whether the 4-byte encoding is used.
    const LONG_BIT: u8 = 1 << 7;
    /// The maximum value a [`VarInt`] can encode.
    pub const MAX: Self = VarInt((1 << 31) - 1);

    /// Decodes a [`VarInt`] from the reader's input.
    ///
    /// # Errors
    /// Any errors from [`Read::read_exact`] are forwarded to the caller.
    pub fn read(mut r: impl Read) -> io::Result<Self> {
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf[0..1])?;
        if buf[0] & Self::LONG_BIT == 0 {
            return Ok(buf[0].into());
        }

        buf[0] &= !Self::LONG_BIT;
        r.read_exact(&mut buf[1..])?;
        Ok(Self(u32::from_be_bytes(buf)))
    }

    /// Encodes the [`VarInt`] into the writer's output.
    ///
    /// # Errors
    /// Any errors from [`Write::write_all`] are forwarded to the caller.
    pub fn write(self, mut w: impl Write) -> io::Result<usize> {
        if self < Self::LONG_BIT.into() {
            #[allow(clippy::cast_possible_truncation)]
            let e = [self.0 as u8];
            w.write_all(&e).and(Ok(e.len()))
        } else {
            let mut e: [u8; 4] = u32::to_be_bytes(self.0);
            e[0] |= Self::LONG_BIT;
            w.write_all(&e).and(Ok(e.len()))
        }
    }

    /// Converts the [`VarInt`] into a [`usize`], saturating at [`usize::MAX`].
    ///
    /// On lower-end platforms, [`usize`] may be smaller than [`u32`]. Saturating
    /// in these cases is useful for indexing, which is bounded by [`usize::MAX`]
    /// because of addressing limitations anyway.
    #[inline]
    #[must_use]
    pub fn to_usize(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl From<VarInt> for u32 {
    /// Extracts the contained [`u32`].
    #[inline]
    fn from(v: VarInt) -> Self {
        v.0
    }
}

impl From<u8> for VarInt {
    #[inline]
    fn from(v: u8) -> Self {
        Self(v.into())
    }
}

impl From<u16> for VarInt {
    #[inline]
    fn from(v: u16) -> Self {
        Self(v.into())
    }
}

impl TryFrom<u32> for VarInt {
    type Error = ProtocolError;

    /// Converts a [`u32`] into a [`VarInt`], unless the [`u32`] is too large.
    ///
    /// # Errors
    /// Returns an error if the [`u32`] is too large to be variably-encoded.
    #[inline]
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        if v > Self::MAX.into() {
            Err(ProtocolError::InvalidVarInt)
        } else {
            Ok(VarInt(v))
        }
    }
}

impl TryFrom<usize> for VarInt {
    type Error = ProtocolError;

    /// Converts a [`usize`] into a [`VarInt`], unless the [`usize`] is too large.
    ///
    /// # Errors
    /// Returns an error if the [`usize`] is too large to be variably-encoded.
    #[inline]
    fn try_from(v: usize) -> Result<Self, Self::Error> {
        match u32::try_from(v) {
            Ok(v) => VarInt::try_from(v),
            Err(_) => Err(ProtocolError::InvalidVarInt),
        }
    }
}


impl fmt::Display for VarInt {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}


#[cfg(test)]
mod tests {
    use std::iter::repeat_with;
    use super::*;

    #[test]
    fn convert() {
        let ok = VarInt::try_from(378u32);
        assert!(matches!(ok, Ok(VarInt(378))));
        let ok = VarInt::try_from(45828usize);
        assert!(matches!(ok, Ok(VarInt(45828))));

        let fail = VarInt::try_from(u32::MAX);
        assert!(matches!(fail, Err(ProtocolError::InvalidVarInt)));
        if usize::try_from(u32::MAX).is_ok() {
            // usize::MAX >= u32::MAX
            let fail = VarInt::try_from(usize::MAX);
            assert!(matches!(fail, Err(ProtocolError::InvalidVarInt)));
        }

        if usize::try_from(VarInt::MAX.0).is_err() {
            // usize::MAX < VarInt::MAX
            assert_eq!(VarInt::MAX.to_usize(), usize::MAX);
        }
    }

    #[test]
    fn roundtrip() -> io::Result<()> {
        let rand_v = repeat_with(|| fastrand::u32(..=VarInt::MAX.0)).take(50);
        for v in rand_v.chain([0, 1, 62, 127, 178, 251, 6819, VarInt::MAX.0]) {
            let orig = VarInt(v);
            let mut buf = [0; 4];
            let len = orig.write(&mut buf[..])?;
            let rt = VarInt::read(&buf[..len])?;
            assert_eq!(orig, rt);
        }
        Ok(())
    }

    #[test]
    fn parse_spec() -> io::Result<()> {
        const SHORT: &[u8] = &[96];
        const LONG: &[u8] = &[0x80 | 0x11, 0xda, 0xef, 0x31];
        assert_eq!(VarInt::read(SHORT)?, VarInt(96));
        assert_eq!(VarInt::read(LONG)?, VarInt(0x11da_ef31));
        Ok(())
    }

    #[test]
    fn parse_invalid() {
        const LONG: &[u8] = &[0x80 | 0x11, 0xda, 0xef, 0x31];
        for len in 1..4 {
            let buf = &LONG[..len];
            match VarInt::read(buf) {
                Ok(v) => panic!("decoded {buf:?} as {v:?}"),
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            }
        }
    }
}
