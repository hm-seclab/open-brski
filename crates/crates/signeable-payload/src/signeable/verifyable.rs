use std::sync::Arc;

use crate::error::SigneableError;

use super::{
    signer_verifyer::SignerVerifyer,
    verified::{self, Verified},
    verifying_context::BasicVeryingContext,
};

pub struct Verifyable<T> {
    pub(crate) data: Vec<u8>,
    pub(crate) verifier: Arc<Box<dyn SignerVerifyer<T>>>,
}

impl<T> Verifyable<T> {
    pub(crate) fn new(data: Vec<u8>, verifier: impl SignerVerifyer<T> + 'static) -> Self {
        Verifyable {
            data,
            verifier: Arc::new(Box::new(verifier)),
        }
    }

    pub(crate) fn new_boxed(data: Vec<u8>, verifier: Box<dyn SignerVerifyer<T>>) -> Self {
        Verifyable {
            data,
            verifier: Arc::new(verifier),
        }
    }
    pub fn verify(self, ctx: Option<BasicVeryingContext>) -> Result<Verified<T>, SigneableError> {
        let verified = self.verifier.verify(&self.data, ctx)?;

        Ok(Verified::new(verified.payload, verified.headers))
    }
}
