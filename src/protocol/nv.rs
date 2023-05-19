use std::io::{self, prelude::*};

use super::varint::VarInt;
use crate::ext::Bytes;


/// An iterator decoding FastCGI name-value pairs from its input.
///
/// This iterator is generic over its input `T`, which can be either
/// a `&[u8]` or a `&mut [u8]`. The returned name-value pairs are carved
/// out of the input slice and thus have the same type `T`.
#[derive(Debug, Clone)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct NVIter<T> {
    data: T,
}

impl<T> NVIter<T> {
    /// Creates a new [`NVIter`] over the input byte slice.
    #[inline]
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Extracts the remaining input bytes from the iterator.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> T {
        self.data
    }
}

impl<T: Bytes> Iterator for NVIter<T> {
    /// The name-value pair returned by the iterator.
    type Item = (T, T);

    fn next(&mut self) -> Option<Self::Item> {
        let mut cur = &*self.data;
        let name_len = VarInt::read(&mut cur).ok()?.try_into().ok()?;
        let val_len = VarInt::read(&mut cur).ok()?.try_into().ok()?;
        let head_len = self.data.len() - cur.len();
        let total_len = head_len.checked_add(name_len)?.checked_add(val_len)?;

        if self.data.len() >= total_len {
            let mut nv = self.data.split_head(total_len);
            nv.advance_by(head_len);
            let name = nv.split_head(name_len);
            Some((name, nv))
        } else {
            None
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // A name-value pair always consists of at least 2 bytes
        (0, Some(self.data.len() / 2))
    }
}
impl<T: Bytes> std::iter::FusedIterator for NVIter<T> {}


/// Encodes a FastCGI name-value pair into the writer's output.
///
/// # Errors
/// Returns an error with [`io::ErrorKind::InvalidInput`] if either part of the
/// name-value pair exceeds the bounds of a FastCGI [`VarInt`]. Additionally,
/// any errors from [`Write::write_all`] are forwarded to the caller.
pub fn write((name, value): (&[u8], &[u8]), mut w: impl Write) -> io::Result<usize> {
    let mut written = 0;
    for len in [name.len(), value.len()] {
        written += match VarInt::try_from(len) {
            Ok(v) => v.write(&mut w)?,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
        }
    }

    w.write_all(name)?;
    w.write_all(value)?;
    Ok(written + name.len() + value.len())
}


#[cfg(test)]
mod tests {
    use super::*;

    type NV<'a> = <NVIter<&'a [u8]> as Iterator>::Item;

    // Used in Params stream
    const SHORT: NV = (b"GATEWAY_INTERFACE", b"CGI/1.1");
    const SHORT_ENC: &[u8] = b"\x11\x07GATEWAY_INTERFACECGI/1.1";
    // Exercises VarInt's long format
    const LONG: NV = (
        b"sTmRLkuxlXufZ#r?8UAN6GaUC=G|N@bU`d)H>^Z6!M~H~YM@5%~7KkTVr(6Z;MmQ}^C~l_OMxyDjQ&W$~p7G]=aYb\
            GNIY:qr#&3<#{Y0ww76I[A>!'p*N+pSH@awPG[%,,LllGj*8KFT:{#+Fni4l=[ga][",
        b"Chf=T+gf+YWUg/-sh.F6M;umM67rMy@ph4OPr`_84{s[iTB?di)5.,\\TuEoRwU!fVl__e#*lZgjp|J+CN+0vVJ8h\
            'YQTV5|Z(aOuWN`12xk9a}:byqe'Tg*5IE3ex@$}{9;y_r)9a?_w(0ZKE(/O/KZ>\\g+SqZ>~",
    );
    const LONG_ENC: &[u8] = b"\x80\x00\x00\x9b\x80\x00\x00\xa0\
        sTmRLkuxlXufZ#r?8UAN6GaUC=G|N@bU`d)H>^Z6!M~H~YM@5%~7KkTVr(6Z;MmQ}^C~l_OMxyDjQ&W$~p7G]=aYb\
            GNIY:qr#&3<#{Y0ww76I[A>!'p*N+pSH@awPG[%,,LllGj*8KFT:{#+Fni4l=[ga][\
        Chf=T+gf+YWUg/-sh.F6M;umM67rMy@ph4OPr`_84{s[iTB?di)5.,\\TuEoRwU!fVl__e#*lZgjp|J+CN+0vVJ8h\
            'YQTV5|Z(aOuWN`12xk9a}:byqe'Tg*5IE3ex@$}{9;y_r)9a?_w(0ZKE(/O/KZ>\\g+SqZ>~";

    // Used in GetValues payload
    const NAME_ONLY: NV = (b"FCGI_MAX_CONNS", b"");
    // Not used in FastCGI, but should be handled for robustness
    const VALUE_ONLY: NV = (b"", b"'qZm*]*\"d^ig3p23k4L'");
    const NV_PAIRS: &[NV] = &[
        NAME_ONLY,
        VALUE_ONLY,
        SHORT,
        LONG,
        (b"FCGI_MPXS_CONNS", b"1"),       // GetValuesResult
        (b"FCGI_MAX_REQS", b"37589372"),  // GetValuesResult
        (b"CONTENT_LENGTH", b"8382142"),  // Params stream
        // Random bytes to test robustness
        (b"}wnJ?^dLn.!cVfJ", b"'HWSwg,NP2md'"),
        (b"T8'K", b"'ch(wconvA'"),
        (b"WhKK7B`cL1j/X!*|l", b"'TAr@O%.^K`'"),
        (b"{`0KJfv.T;E", b"'x/P5H[rRM,\"r'"),
        (b"eO7=", b"'4}mixU_z6=N<-E<?uEWLK\\A{-'"),
        (b"F`8-p", b"\"7Oo%=](kA@0OpN':\\WcL7x\""),
        (b"\"wBC5,}bUbp<-RRw\\Lr[", b"'naY'"),
        (b"_4jL04fo+$&b7!A", b"'0o/7==#MV{,wE[gTmNzf:@P'"),
    ];

    #[test]
    fn write_spec() -> io::Result<()> {
        let mut buf = Vec::with_capacity(1000);
        let len = write(SHORT, &mut buf)?;
        assert_eq!(len, buf.len());
        assert_eq!(buf, SHORT_ENC);

        buf.clear();
        let len = write(LONG, &mut buf)?;
        assert_eq!(len, buf.len());
        assert_eq!(buf, LONG_ENC);
        Ok(())
    }

    #[test]
    fn roundtrip() -> io::Result<()> {
        let mut buf = Vec::with_capacity(4000);
        for &nv in NV_PAIRS {
            write(nv, &mut buf)?;
        }
        parse_inner(&*buf, NV_PAIRS.iter());
        Ok(())
    }

    #[test]
    fn parse_mut() {
        let mut buf = Vec::with_capacity(4000);
        buf.extend([LONG_ENC, SHORT_ENC].into_iter().cycle().take(20).flatten());
        let orig_it = [LONG, SHORT].iter().cycle().take(20);
        parse_inner(&mut *buf, orig_it);
    }

    fn parse_inner<'a>(buf: impl Bytes, mut orig_it: impl Iterator<Item = &'a NV<'a>>) {
        let mut rt_it = NVIter::new(buf);
        if let (min_len, Some(max_len)) = rt_it.size_hint() {
            let (orig_min, orig_max) = orig_it.size_hint();
            assert!(min_len <= orig_min);
            assert!(max_len >= orig_max.expect("orig_it is unbounded"));
        }

        for rt_nv in &mut rt_it {
            let &orig_nv = orig_it.next()
                .expect("NVIter returned too many elements");
            assert_eq!(orig_nv.0, &*rt_nv.0);
            assert_eq!(orig_nv.1, &*rt_nv.1);
        }
        assert!(orig_it.next().is_none(), "NVIter returned too few elements");

        let rem = &*rt_it.into_inner();
        assert_eq!(rem.len(), 0, "NVIter did not consume all input: {rem:?}");
    }

    #[test]
    fn parse_invalid() -> io::Result<()> {
        parse_invalid_impl(SHORT)?;
        parse_invalid_impl(LONG)
    }

    fn parse_invalid_impl(nv: NV) -> io::Result<()> {
        let mut buf = Vec::with_capacity(1000);
        write(nv, &mut buf)?;
        for len in [0, 1, buf.len() / 3, buf.len() / 2, buf.len().saturating_sub(5)] {
            let trunc = &buf[..len];
            let mut it = NVIter::new(trunc);
            assert!(it.next().is_none());
            assert_eq!(it.into_inner(), trunc);
        }

        let extend_by = buf.len() / 3;
        buf.extend_from_within(..extend_by);
        let mut it = NVIter::new(&*buf);
        assert_eq!(it.next(), Some(nv));
        assert!(it.next().is_none());
        assert_eq!(it.into_inner(), &buf[..extend_by]);
        Ok(())
    }
}
