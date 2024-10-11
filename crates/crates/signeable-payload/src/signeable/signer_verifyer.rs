use crate::{error::SigneableError, header::HeaderSet};

use super::{signing_context::BasicSigningContext, verifying_context::BasicVeryingContext};

pub struct VerifyResult<T> {
    pub(crate) payload: T,
    pub(crate) headers: HeaderSet,
}
pub trait SignerVerifyer<T> {
    // A function that signed a payload and returns the signed data
    fn sign(
        &self,
        payload: T,
        header: HeaderSet,
        privkey: &[u8],
        ctx: BasicSigningContext,
    ) -> Result<Vec<u8>, SigneableError>;

    // A function that verifies a signed data and returns the payload
    fn verify(
        &self,
        signed_data: &[u8],
        ctx: Option<BasicVeryingContext>,
    ) -> Result<VerifyResult<T>, SigneableError>;
}

pub trait SignatureAdder {
    // A function that adds a signature to a signed data and returns the signed data. Only some implementations will support adding multiple signatures.
    // This function is expected to throw an error if the implementation does not support adding multiple signatures.// A function that adds a signature to a signed data and returns the signed data. Only some implementations will support adding multiple signatures.
    // This function is expected to throw an error if the implementation does not support adding multiple signatures.
    fn add_signature(
        &self,
        signed_data: &[u8],
        header: HeaderSet,
        privkey: &[u8],
        ctx: BasicSigningContext,
    ) -> Result<Vec<u8>, SigneableError>;
}

pub trait MultipleSignerVerifyer<T>: SignerVerifyer<T> + SignatureAdder {}
