use core::fmt::Display;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum SigneableError {
    #[error("Missing Builder Attribute")]
    MissingBuilderAttribute(String),

    #[cfg(feature = "jws")]
    #[error("JOSE Error {0}")]
    JoseError(#[from] josekit::JoseError),

    #[error("Cose Error {0}")]
    #[cfg(feature = "cose")]
    CoseError(#[from] CoseErrorWrapper),

    #[error("Signing Error {0}")]
    SigningError(String),

    #[error("Verifying Error {0}")]
    VerifyingError(String),

    #[error("Invalid Header Format{0}")]
    InvalidHeaderFormat(String),

    #[error("General Error {0}")]
    GeneralError(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
#[cfg(feature = "cose")]
pub struct CoseErrorWrapper(pub coset::CoseError);

#[cfg(feature = "cose")]
impl Display for CoseErrorWrapper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "cose")]
impl From<coset::CoseError> for CoseErrorWrapper {
    fn from(e: coset::CoseError) -> Self {
        CoseErrorWrapper(e)
    }
}
