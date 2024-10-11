use core::fmt::{Debug, Display};
use std::sync::Arc;

use crate::{error::SigneableError, header::HeaderSet};

use super::{
    signeable::Signeable, signed::Signed, signer_verifyer::SignerVerifyer,
    signing_context::BasicSigningContext,
};

pub struct Unsigned<T> {
    payload: T,
    header: HeaderSet,
}

impl<T: Debug> Debug for Unsigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unsigned")
            .field("payload", &self.payload)
            .field("header", &self.header)
            .finish()
    }
}

impl<T> Unsigned<T> {
    pub fn new(payload: T, header: HeaderSet) -> Self {
        Unsigned { payload, header }
    }

    pub fn header(&self) -> &HeaderSet {
        &self.header
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn into_signeable(self, signer: impl SignerVerifyer<T> + 'static) -> Signeable<T> {
        Signeable::new(self.payload, self.header, signer)
    }

    pub fn into_signeable_boxed(self, signer: Box<dyn SignerVerifyer<T>>) -> Signeable<T> {
        Signeable::new_boxed(self.payload, self.header, signer)
    }
}
