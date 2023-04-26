use std::io::prelude::*;

use super::varint::VarInt;
use super::Error as ProtocolError;


/// An iterator decoding complete name-value pairs from its input.
#[derive(Debug, Clone)]
pub struct NVIter<'a> {
    data: &'a [u8],
}

impl<'a> NVIter<'a> {
    /// Creates a new [`NVIter`] over the referenced input bytes.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Extracts the remaining input bytes from the iterator.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> &'a [u8] {
        self.data
    }
}

impl<'a> Iterator for NVIter<'a> {
    /// The name-value pair returned by the iterator.
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let mut cur = self.data;
        let name_len = VarInt::read(&mut cur).ok()?.to_usize();
        let val_len = VarInt::read(&mut cur).ok()?.to_usize();
        let total_len = name_len + val_len;

        if cur.len() >= total_len {
            self.data = &cur[total_len..];
            Some((&cur[..name_len], &cur[name_len..total_len]))
        } else {
            None
        }
    }
}

impl std::iter::FusedIterator for NVIter<'_> {}


/// Encodes a name-value pair into the writer's output.
///
/// # Errors
/// Any errors from [`Write::write_all`] are forwarded to the caller.
pub fn write((name, value): (&[u8], &[u8]), mut w: impl Write) -> Result<usize, ProtocolError> {
    let mut written = VarInt::try_from(name.len())?.write(&mut w)?;
    written += VarInt::try_from(value.len())?.write(&mut w)?;
    w.write_all(name)?;
    w.write_all(value)?;
    Ok(written + name.len() + value.len())
}
