use thiserror::Error;
#[derive(Error, Debug)]
pub enum BRSKIPRMError {
    #[error("Malformed - Reason {0}")]
    Malformed(String),

    #[error("Expected Encoded AgentSignedData, but got Decoded")]
    ExpectedEncodedData,
    #[error("Expected Decoded AgentSignedData, but got Encoded")]
    ExpectedDecodedData,
    #[error("Missing registrar agent ee certificate subject key identifier")]
    MissingRegAgtCertSKID,
    #[cfg(feature = "openssl")]
    #[error(transparent)]
    OpensslError {
        #[from]
        source: openssl::error::ErrorStack,
    },

    #[cfg(feature = "json")]
    #[error(transparent)]
    JWSError(#[from] josekit::JoseError),

    #[error("Internal crate error. Please report this issue.")]
    InternalError,
}
