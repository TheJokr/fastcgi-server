use super::Error as ProtocolError;


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
    /// Converts the input bytes into a well-known FastCGI
    /// [`ProtocolVariables`] item.
    ///
    /// # Errors
    /// Returns an error if the variable name is unknown, which may also
    /// occur when it is not UTF-8 encoded.
    pub fn parse_name(name: &[u8]) -> Result<Self, ProtocolError> {
        let name = String::from_utf8_lossy(name);
        Self::from_name(&name).ok_or_else(
            || ProtocolError::UnknownVariable(name.into())
        )
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
            Err(ProtocolError::UnknownVariable(s)) => assert_eq!(s.as_ref(), UNK_VAR),
            Err(e) => panic!("returned unexpected error {e:#?}"),
        }
    }

    #[test]
    fn parse_invalid() {
        const INVALID_VAR: &[u8] = b"ASg w-f#32\xFE \xFF+_a+";
        const REPL_REPR: &str = "ASg w-f#32� �+_a+";
        match ProtocolVariables::parse_name(INVALID_VAR) {
            Ok(v) => panic!("parsed {REPL_REPR:?} as {}", v.0),
            Err(ProtocolError::UnknownVariable(s)) => assert_eq!(s.as_ref(), REPL_REPR),
            Err(e) => panic!("returned unexpected error {e:#?}"),
        }
    }
}
