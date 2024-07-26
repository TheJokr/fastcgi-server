use compact_str::{CompactString, ToCompactString};

use super::Error as ProtocolError;
use super::{nv, RecordHeader, RecordType, FCGI_NULL_REQUEST_ID};
use crate::ext::BytesVec;
use crate::Config;


bitflags::bitflags! {
    /// A set of queryable FastCGI protocol variable names.
    ///
    /// The FastCGI client (HTTP server) can send a query for any combination
    /// of these names to the FastCGI server in a [`GetValues`][GetValues]
    /// record. The client responds with the names and values in a
    /// [`GetValuesResult`][GetValuesResult] record.
    ///
    /// [GetValues]: super::RecordType::GetValues
    /// [GetValuesResult]: super::RecordType::GetValuesResult
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ProtocolVariables: u8 {
        /// The maximum number of concurrent connections accepted by the application.
        const FCGI_MAX_CONNS = 0x01;
        /// The maximum number of concurrent requests accepted by the application.
        const FCGI_MAX_REQS = 0x02;
        /// Whether the application accepts multiplexed requests ("1") or not ("0").
        const FCGI_MPXS_CONNS = 0x04;
    }
}

impl ProtocolVariables {
    /// Parses the input bytes into a well-known FastCGI
    /// [`ProtocolVariables`] item.
    ///
    /// # Errors
    /// Returns an error if the variable name is unknown, which may also
    /// stem from an improper encoding.
    pub fn parse_name(name: &[u8]) -> Result<Self, ProtocolError> {
        // All well-known variable names are ASCII-only
        match std::str::from_utf8(name) {
            Ok(s) => Self::from_name(s).ok_or(ProtocolError::UnknownVariable),
            Err(_) => Err(ProtocolError::UnknownVariable),
        }
    }

    /// The maximum number of bytes in the wire format of a `GetValuesResult`
    /// record emitted by `ProtocolVariables::write_response`.
    pub const RESPONSE_LEN: usize = 104;

    /// Appends a `GetValuesResult` record in wire format to the [`BytesVec`].
    ///
    /// Variable names are taken from this [`ProtocolVariables`] set. The
    /// corresponding values are inferred from the [`Config`].
    ///
    /// The canonical [`BytesVec`] implementation is [`Vec<u8>`], but there may
    /// also be other implementors. See the trait documentation for details.
    ///
    /// # Panics
    /// Panics if appending to the [`BytesVec`] fails, which by definition of a
    /// [`Vec`] should be impossible.
    pub fn write_response<V: BytesVec>(self, out: &mut V, config: &Config) -> usize {
        // Reserve space for the header in out, which may already contain data
        let start = out.len();
        out.extend_from_slice(&[0; RecordHeader::LEN]);
        let mut len = 0;

        for (name, var) in self.iter_names() {
            let value = match var {
                Self::FCGI_MAX_CONNS | Self::FCGI_MAX_REQS => config.max_conns.to_compact_string(),
                Self::FCGI_MPXS_CONNS => CompactString::const_new("0"),
                _ => unreachable!("All flags should be explicitly handled"),
            };
            // name and value are guaranteed to fit into a VarInt here
            len += nv::write((name.as_bytes(), value.as_bytes()), &mut *out)
                .expect("writing into BytesVec should always succeed");
        }

        // GetValuesResult is not a stream, so its name-value pairs must fit
        // into a single record body per the specification. This means len can
        // safely be cast to a u16.
        let mut head = RecordHeader::new(RecordType::GetValuesResult, FCGI_NULL_REQUEST_ID);
        head.set_lengths(len as u16);
        out.extend_from_slice(head.padding_bytes());
        out[start..(start + RecordHeader::LEN)].copy_from_slice(&head.to_bytes());
        out.len() - start
    }
}


#[cfg(test)]
mod tests {
    use smallvec::SmallVec;
    use super::*;

    #[test]
    fn no_flag_overlap() {
        let mut seen = ProtocolVariables::empty();
        for f in ProtocolVariables::all() {
            assert!(!seen.intersects(f), "{} overlaps with {}", f.0, seen.0);
            seen.insert(f);
        }
    }

    #[test]
    fn roundtrip() -> Result<(), ProtocolError> {
        for (name, f) in ProtocolVariables::all().iter_names() {
            assert_eq!(ProtocolVariables::parse_name(name.as_bytes())?, f);
        }
        Ok(())
    }

    #[test]
    fn parse_spec() -> Result<(), ProtocolError> {
        assert_eq!(
            ProtocolVariables::parse_name(b"FCGI_MAX_CONNS")?,
            ProtocolVariables::FCGI_MAX_CONNS,
        );
        assert_eq!(
            ProtocolVariables::parse_name(b"FCGI_MAX_REQS")?,
            ProtocolVariables::FCGI_MAX_REQS,
        );
        assert_eq!(
            ProtocolVariables::parse_name(b"FCGI_MPXS_CONNS")?,
            ProtocolVariables::FCGI_MPXS_CONNS,
        );
        Ok(())
    }

    #[test]
    fn parse_unk() {
        const UNK_VAR: &str = "Atä w_3tFA-Es^Ü2";
        match ProtocolVariables::parse_name(UNK_VAR.as_bytes()) {
            Ok(v) => panic!("parsed {UNK_VAR:?} as {}", v.0),
            Err(ProtocolError::UnknownVariable) => (),
            Err(e) => panic!("returned unexpected error {e:#?}"),
        }
    }

    #[test]
    fn parse_invalid() {
        const INVALID_VAR: &[u8] = b"ASg w-f#32\xFE \xFF+_a+";
        match ProtocolVariables::parse_name(INVALID_VAR) {
            Ok(v) => panic!("parsed invalid UTF-8 as {}", v.0),
            Err(ProtocolError::UnknownVariable) => (),
            Err(e) => panic!("returned unexpected error {e:#?}"),
        }
    }

    #[test]
    fn response_len() {
        let vars = ProtocolVariables::all();
        let max_config =
            Config { buffer_size: usize::MAX, max_conns: usize::MAX.try_into().unwrap() };

        let mut buf = Vec::with_capacity(ProtocolVariables::RESPONSE_LEN.next_power_of_two());
        let written = vars.write_response(&mut buf, &max_config);
        assert_eq!(
            ProtocolVariables::RESPONSE_LEN, buf.len(),
            "ProtocolVariables::RESPONSE_LEN should be {}", buf.len(),
        );
        assert_eq!(written, buf.len());
    }

    #[test]
    fn response() {
        const REF: &[u8] = b"\x01\x0a\0\0\x00\x37\x01\0\x0e\x03FCGI_MAX_CONNS183\
            \x0d\x03FCGI_MAX_REQS183\x0f\x01FCGI_MPXS_CONNS0\0";
        let vars = ProtocolVariables::all();
        let config = Config::with_conns(183.try_into().unwrap());

        let mut heap = Vec::with_capacity(ProtocolVariables::RESPONSE_LEN);
        heap.extend([0x7d; 8]);  // some existing data
        let written = vars.write_response(&mut heap, &config);
        assert_eq!(heap.len(), 8 + REF.len());
        assert_eq!(&heap[8..], REF);
        assert_eq!(written, REF.len());

        let mut stack = <SmallVec<[u8; ProtocolVariables::RESPONSE_LEN]>>::new();
        let written = vars.write_response(&mut stack, &config);
        assert!(!stack.spilled());
        assert_eq!(&*stack, REF);
        assert_eq!(written, REF.len());
    }
}
