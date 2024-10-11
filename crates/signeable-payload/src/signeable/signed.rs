use core::fmt::Debug;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{error::SigneableError, header::HeaderSet};

use super::{
    raw_signed::RawSigned, signer_verifyer::SignerVerifyer, verified::Verified,
    verifyable::Verifyable, verifying_context::BasicVeryingContext,
};

pub struct Signed<T> {
    raw: RawSigned<T>,
    header: HeaderSet,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Debug for Signed<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Signed {{ raw of length: {:?}, header: {:?} }}",
            self.raw.data().len(),
            self.header
        )
    }
}

impl Serialize for Signed<()> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.raw.data().clone())
    }
}

impl<T: PartialEq> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw && self.header == other.header
    }
}

impl<T: Eq> Eq for Signed<T> {}

impl<T: Clone> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            header: self.header.clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> Signed<T> {
    pub(crate) fn new(data: Vec<u8>, header: HeaderSet) -> Self {
        Self {
            raw: RawSigned::new(data),
            header,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn data(&self) -> Vec<u8> {
        self.raw.data()
    }

    pub fn header(&self) -> &HeaderSet {
        &self.header
    }

    pub fn into_verifyable(self, verifier: impl SignerVerifyer<T> + 'static) -> Verifyable<T> {
        Verifyable::new(self.raw.data().clone().to_vec(), verifier)
    }

    pub fn into_raw(self) -> RawSigned<T> {
        self.raw
    }
}

impl<T> AsRef<[u8]> for Signed<T> {
    fn as_ref(&self) -> &[u8] {
        let x = &self.raw;
        x.as_ref()
    }
}

impl<T> From<Vec<u8>> for Signed<T> {
    fn from(data: Vec<u8>) -> Self {
        Self {
            raw: RawSigned::new(data),
            header: HeaderSet::new(),
            _marker: std::marker::PhantomData,
        }
    }
}

#[cfg(feature = "axum")]
impl<T> axum::response::IntoResponse for Signed<T> {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        let mut res = axum::http::Response::new(self.raw.data().into());
        if let Some(content_type) = self.header.content_type() {
            res.headers_mut()
                .insert("content-type", content_type.parse().unwrap());
        }
        res
    }
}
