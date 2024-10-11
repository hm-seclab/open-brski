#![feature(trait_alias)]
pub mod error;
pub mod signeable;
use error::SigneableError;
use serde::{de::DeserializeOwned, Serialize};
pub use signeable::*;
use signer_verifyer::{MultipleSignerVerifyer, SignatureAdder};
pub mod algorithm;

#[cfg(feature = "cose")]
pub mod cose;
pub mod header;
#[cfg(feature = "jws")]
pub mod jws;

#[cfg(feature = "jws")]
pub type DefaultSignerVerifyer = jws::JoseSignerVerifyer;

#[cfg(all(feature = "cose", not(feature = "jws")))]
pub type DefaultSignerVerifyer = cose::CoseSignerVerifyer;

#[derive(Clone, Debug)]
pub enum SignatureType {
    None,
    JWS,
    COSE,
}

impl Default for SignatureType {
    fn default() -> Self {
        SignatureType::None
    }
}

impl SignatureType {
    pub fn get_sv<T: Serialize + DeserializeOwned>(
        self,
    ) -> Result<Box<dyn SignerVerifyer<T>>, SigneableError> {
        get_sv_for_context(self)
    }
    pub fn get_sigadder(self) -> Result<Box<dyn SignatureAdder>, SigneableError> {
        get_sigadder_for_context(self)
    }
}

fn get_sv_for_context<T: Serialize + DeserializeOwned>(
    context: SignatureType,
) -> Result<Box<dyn SignerVerifyer<T>>, SigneableError> {
    match context {
        #[cfg(feature = "jws")]
        SignatureType::JWS => Ok(Box::new(jws::JoseSignerVerifyer::default())),
        #[cfg(feature = "cose")]
        SignatureType::COSE => Ok(Box::new(cose::CoseSignerVerifyer::default())),
        // This catches the above too, if they're configured out
        _ => Err(SigneableError::GeneralError(anyhow::anyhow!(
            "Unknown signing context"
        ))),
    }
}
fn get_sigadder_for_context(
    context: SignatureType,
) -> Result<Box<dyn SignatureAdder>, SigneableError> {
    match context {
        #[cfg(feature = "jws")]
        SignatureType::JWS => Ok(Box::new(jws::JoseSignerVerifyer::default())),
        #[cfg(feature = "cose")]
        SignatureType::COSE => Ok(Box::new(cose::CoseSignerVerifyer::default())),
        // See above
        _ => Err(SigneableError::GeneralError(anyhow::anyhow!(
            "Unknown or signing context"
        ))),
    }
}
