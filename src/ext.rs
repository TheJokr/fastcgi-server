use std::io::Write;
use std::ops::{Deref, DerefMut};

use smallvec::SmallVec;


/// An extension trait for byte slices that is generic over mutability.
pub trait Bytes: Sized + Deref<Target = [u8]> {
    /// Moves the start of the slice forwards by `n` bytes.
    ///
    /// # Panics
    /// Panics if `n` exceeds the slice's length.
    #[must_use]
    fn advance_by(self, n: usize) -> Self;

    /// Divides the slice into two at index `mid`.
    ///
    /// `&self[mid]` becomes the first element of the second slice.
    ///
    /// # Panics
    /// Panics if `mid` exceeds the slice's length.
    #[must_use]
    fn split_at(self, mid: usize) -> (Self, Self);
}

impl Bytes for &[u8] {
    #[inline]
    fn advance_by(self, n: usize) -> Self {
        &self[n..]
    }
    #[inline]
    fn split_at(self, mid: usize) -> (Self, Self) {
        self.split_at(mid)
    }
}

impl Bytes for &mut [u8] {
    #[inline]
    fn advance_by(self, n: usize) -> Self {
        &mut self[n..]
    }
    #[inline]
    fn split_at(self, mid: usize) -> (Self, Self) {
        self.split_at_mut(mid)
    }
}


/// A trait for generic abstraction over [`Vec<u8>`]-like types.
pub trait BytesVec: DerefMut<Target = [u8]> + Write {
    /// Copies and appends all bytes from `other` to this [`BytesVec`] in-order.
    fn extend_from_slice(&mut self, other: &[u8]);
}

impl BytesVec for Vec<u8> {
    #[inline]
    fn extend_from_slice(&mut self, other: &[u8]) {
        self.extend(other);
    }
}

impl<const N: usize> BytesVec for SmallVec<[u8; N]> {
    #[inline]
    fn extend_from_slice(&mut self, other: &[u8]) {
        self.extend_from_slice(other);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    const REF: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    #[test]
    fn bytes_shared() {
        let mut bytes = REF;
        bytes = bytes.advance_by(20);
        assert_eq!(bytes, &REF[20..]);

        let head;
        (head, bytes) = bytes.split_at(7);
        assert_eq!(head, &REF[20..27]);
        assert_eq!(bytes, &REF[27..]);
    }

    #[test]
    fn bytes_exclusive() {
        let mut buf = REF.to_owned();
        let mut bytes = &mut *buf;
        bytes = bytes.advance_by(25);
        assert_eq!(bytes, &REF[25..]);

        let head;
        (head, bytes) = bytes.split_at(20);
        assert_eq!(head, &REF[25..45]);
        assert_eq!(bytes, &REF[45..]);
    }

    #[test]
    fn bytesvec() {
        let mut v = Vec::from(&REF[..26]);
        BytesVec::extend_from_slice(&mut v, &REF[26..]);
        assert_eq!(v, REF);

        let mut sv = <SmallVec<[u8; REF.len()]>>::from_slice(&REF[..26]);
        BytesVec::extend_from_slice(&mut sv, &REF[26..]);
        assert_eq!(&*sv, REF);
    }
}
