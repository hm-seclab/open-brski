use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// A wrapper around an X.509 certificate.
/// It will always be serialized by serde as a DER-encoded X.509 certificate.
/// To serialize it as a PEM-encoded X.509 certificate, use serde_as base64. This will convert the certificate to a PEM-encoded string and then base64 encode it.
pub struct X509Req {
    csr: openssl::x509::X509Req,
    der: Vec<u8>,
}

impl Clone for X509Req {
    fn clone(&self) -> Self {
        let csr = openssl::x509::X509Req::from_der(&self.der).unwrap();
        X509Req {
            csr,
            der: self.der.clone(),
        }
    }
}

impl Eq for X509Req {}

impl std::fmt::Debug for X509Req {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509Req")
            .field(
                "csr",
                &format!(
                    "{}",
                    String::from_utf8(self.csr.to_text().unwrap()).unwrap()
                ),
            )
            .field(
                "der",
                &format!(
                    "DER-encoded X.509 certificate with length {}",
                    self.der.len()
                ),
            )
            .finish()
    }
}

impl From<openssl::x509::X509Req> for X509Req {
    fn from(x509: openssl::x509::X509Req) -> Self {
        let der = x509.to_der().unwrap();

        X509Req { csr: x509, der }
    }
}

impl Deref for X509Req {
    type Target = openssl::x509::X509Req;

    fn deref(&self) -> &Self::Target {
        &self.csr
    }
}

impl Serialize for X509Req {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.der)
    }
}

impl<'de> Deserialize<'de> for X509Req {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let x509 = openssl::x509::X509Req::from_der(&bytes).map_err(serde::de::Error::custom)?;

        Ok(X509Req {
            csr: x509,
            der: bytes,
        })
    }
}

impl AsRef<[u8]> for X509Req {
    fn as_ref(&self) -> &[u8] {
        &self.der
    }
}

impl TryFrom<Vec<u8>> for X509Req {
    type Error = openssl::error::ErrorStack;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let x509 = openssl::x509::X509Req::from_der(&value)?;
        Ok(X509Req {
            csr: x509,
            der: value,
        })
    }
}

impl PartialEq for X509Req {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}
