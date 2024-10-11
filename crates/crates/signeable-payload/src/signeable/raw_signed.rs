use core::fmt::Debug;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{error::SigneableError, header::HeaderSet};

use super::{
    signed::Signed,
    signer_verifyer::{SignatureAdder, SignerVerifyer},
    signing_context::BasicSigningContext,
    verified::Verified,
    verifyable::Verifyable,
    verifying_context::BasicVeryingContext,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RawSigned<T> {
    data: Vec<u8>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> From<Signed<T>> for RawSigned<T> {
    fn from(signed: Signed<T>) -> Self {
        Self {
            data: signed.data(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: PartialEq> PartialEq for RawSigned<T> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<T: Eq> Eq for RawSigned<T> {}

impl<T: Clone> Clone for RawSigned<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> RawSigned<T> {
    pub fn new(data: Vec<u8>) -> Self {
        RawSigned {
            data,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn into_verifyable(self, verifier: impl SignerVerifyer<T> + 'static) -> Verifyable<T> {
        Verifyable::new(self.data, verifier)
    }

    pub fn into_verifyable_boxed(self, verifier: Box<dyn SignerVerifyer<T>>) -> Verifyable<T> {
        Verifyable::new_boxed(self.data, verifier)
    }

    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn add_signature(
        &self,
        header: HeaderSet,
        privkey: impl AsRef<[u8]>,
        signer: impl SignatureAdder + 'static,
        ctx: BasicSigningContext,
    ) -> Result<Signed<T>, SigneableError> {
        let res = signer.add_signature(&self.data, header.clone(), privkey.as_ref(), ctx)?;
        Ok(Signed::new(res, header))
    }
    pub fn add_signature_boxed(
        &self,
        header: HeaderSet,
        privkey: impl AsRef<[u8]>,
        signer: Box<dyn SignatureAdder + 'static>,
        ctx: BasicSigningContext,
    ) -> Result<Signed<T>, SigneableError> {
        let res = signer.add_signature(&self.data, header.clone(), privkey.as_ref(), ctx)?;
        Ok(Signed::new(res, header))
    }
}

impl<T> AsRef<[u8]> for RawSigned<T> {
    fn as_ref(&self) -> &[u8] {
        let x = &self.data;
        x.as_ref()
    }
}

impl<T> From<Vec<u8>> for RawSigned<T> {
    fn from(data: Vec<u8>) -> Self {
        Self {
            data,
            _marker: std::marker::PhantomData,
        }
    }
}
