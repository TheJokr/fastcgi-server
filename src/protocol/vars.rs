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
