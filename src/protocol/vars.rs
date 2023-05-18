use compact_str::{CompactString, ToCompactString};

use super::Error as ProtocolError;
use super::{nv, RecordHeader, RecordType, Version, FCGI_NULL_REQUEST_ID};
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

    /// Appends a `GetValuesResult` record in wire format to the [`Vec<u8>`]
    /// based on variable names from this [`ProtocolVariables`] set and variable
    /// values from the [`Config`].
    pub fn write_response(self, out: &mut Vec<u8>, config: &Config) {
        // Reserve space for the header in out, which may already contain data
        let start = out.len();
        out.extend([0; RecordHeader::LEN]);
        let mut len = 0;

        for (name, var) in self.iter_names() {
            let value = match var {
                Self::FCGI_MAX_CONNS | Self::FCGI_MAX_REQS => config.max_conns.to_compact_string(),
                Self::FCGI_MPXS_CONNS => CompactString::new_inline("0"),
                _ => unreachable!("All flags should be explicitly handled"),
            };
            // name and value are guaranteed to fit into a VarInt here
            len += nv::write((name.as_bytes(), value.as_bytes()), &mut *out)
                .expect("writing into Vec<u8> should always succeed");
        }

        // Specification recommends padding to multiple of 8 bytes
        let mut padding = len % 8;
        if padding > 0 {
            padding = 8 - padding;
            out.extend(&[0; 7][..padding]);
        }

        let head = RecordHeader {
            version: Version::V1, rtype: RecordType::GetValuesResult,
            request_id: FCGI_NULL_REQUEST_ID, content_length: len as u16,
            padding_length: padding as u8,
        }.to_bytes();
        out[start..(start + RecordHeader::LEN)].copy_from_slice(&head);
    }
}


#[cfg(test)]
mod tests {
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
        let max_config = Config { max_conns: usize::MAX.try_into().unwrap() };

        let mut buf = Vec::with_capacity(ProtocolVariables::RESPONSE_LEN.next_power_of_two());
        vars.write_response(&mut buf, &max_config);
        assert_eq!(
            ProtocolVariables::RESPONSE_LEN, buf.len(),
            "ProtocolVariables::RESPONSE_LEN should be {}", buf.len(),
        );
    }

    #[test]
    fn response() {
        const REF: &[u8] = b"\x01\x0a\0\0\x00\x37\x01\0\x0e\x03FCGI_MAX_CONNS183\
            \x0d\x03FCGI_MAX_REQS183\x0f\x01FCGI_MPXS_CONNS0\0";
        let vars = ProtocolVariables::all();
        let config = Config { max_conns: 183.try_into().unwrap() };

        let mut buf = Vec::with_capacity(ProtocolVariables::RESPONSE_LEN);
        vars.write_response(&mut buf, &config);
        assert_eq!(buf, REF);
    }
}
