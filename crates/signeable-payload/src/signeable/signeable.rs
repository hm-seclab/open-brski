use std::sync::Arc;

use crate::{error::SigneableError, header::HeaderSet};

use super::{
    signed::Signed, signer_verifyer::SignerVerifyer, signing_context::BasicSigningContext,
    verifyable::Verifyable,
};

pub struct Signeable<T> {
    payload: T,
    header: HeaderSet,
    signer: Arc<Box<dyn SignerVerifyer<T>>>,
}

impl<T> Signeable<T> {
    pub(crate) fn new(
        payload: T,
        header: HeaderSet,
        signer: impl SignerVerifyer<T> + 'static,
    ) -> Self {
        Signeable {
            payload,
            header,
            signer: Arc::new(Box::new(signer)),
        }
    }

    pub(crate) fn new_boxed(
        payload: T,
        header: HeaderSet,
        signer: Box<dyn SignerVerifyer<T>>,
    ) -> Self {
        Signeable {
            payload,
            header,
            signer: Arc::new(signer),
        }
    }
    pub fn sign(
        self,
        privkey: impl AsRef<[u8]>,
        ctx: BasicSigningContext,
    ) -> Result<Signed<T>, SigneableError> {
        let signed_data =
            self.signer
                .sign(self.payload, self.header.clone(), privkey.as_ref(), ctx)?;
        Ok(Signed::new(signed_data, self.header))
    }

    pub fn sign_into_verify(
        self,
        key: impl AsRef<[u8]>,
        ctx: BasicSigningContext,
    ) -> Result<Verifyable<T>, SigneableError> {
        let signed_data = self
            .signer
            .sign(self.payload, self.header, key.as_ref(), ctx)?;
        Ok(Verifyable {
            data: signed_data,
            verifier: self.signer,
        })
    }
}
