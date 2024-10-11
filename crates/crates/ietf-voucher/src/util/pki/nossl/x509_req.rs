use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// A wrapper around an X.509 certificate.
/// It will always be serialized by serde as a DER-encoded X.509 certificate.
/// To serialize it as a PEM-encoded X.509 certificate, use serde_as base64. This will convert the certificate to a PEM-encoded string and then base64 encode it.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct X509Req(Vec<u8>);

impl AsRef<[u8]> for X509Req {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_ref()
    }
}

impl TryFrom<Vec<u8>> for X509Req {
    type Error = crate::error::VoucherError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(X509Req(value))
    }
}
