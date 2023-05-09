use std::ops::Deref;


/// An extension trait for byte slices that is generic over mutability.
pub trait Bytes: Deref<Target = [u8]> {
    /// Moves the head of the slice by `n` bytes.
    ///
    /// # Panics
    /// Panics if `n` exceeds the slice's length. This may leave the slice
    /// in a fallback state.
    fn advance_by(&mut self, n: usize);

    /// Splits off and returns the first `len` bytes of the slice.
    ///
    /// `self` contains the remaining bytes afterwards.
    ///
    /// # Panics
    /// Panics if `len` exceeds the slice's length. This may leave the slice
    /// in a fallback state.
    fn split_head(&mut self, len: usize) -> Self;
}

impl Bytes for &[u8] {
    #[inline]
    fn advance_by(&mut self, n: usize) {
        *self = &self[n..];
    }
    #[inline]
    fn split_head(&mut self, len: usize) -> Self {
        let head;
        (head, *self) = self.split_at(len);
        head
    }
}

impl Bytes for &mut [u8] {
    #[inline]
    fn advance_by(&mut self, n: usize) {
        replace_with::replace_with(self, || &mut [], |s| &mut s[n..]);
    }
    #[inline]
    fn split_head(&mut self, len: usize) -> Self {
        replace_with::replace_with_and_return(self, || &mut [], |s| s.split_at_mut(len))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    const REF: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    #[test]
    fn shared() {
        let mut bytes = REF;
        bytes.advance_by(20);
        assert_eq!(bytes, &REF[20..]);

        let head = bytes.split_head(7);
        assert_eq!(head, &REF[20..27]);
        assert_eq!(bytes, &REF[27..]);
    }

    #[test]
    fn exclusive() {
        let mut buf = REF.to_owned();
        let mut bytes = &mut *buf;
        bytes.advance_by(25);
        assert_eq!(bytes, &REF[25..]);

        let head = bytes.split_head(20);
        assert_eq!(head, &REF[25..45]);
        assert_eq!(bytes, &REF[45..]);
    }
}
