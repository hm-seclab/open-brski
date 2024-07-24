use std::ops::Deref;

use base64::Engine;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::FromDer;

/// A wrapper around an X.509 certificate.
/// It will always be serialized by serde as a DER-encoded X.509 certificate.
/// To serialize it as a PEM-encoded X.509 certificate, use serde_as base64. This will convert the certificate to a PEM-encoded string and then base64 encode it.
#[derive(Clone)]
pub struct X509<'a> {
    certificate: x509_parser::certificate::X509Certificate<'a>,
    der: &'a [u8],
}

impl Eq for X509<'_> {}

impl std::fmt::Display for X509<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            base64::prelude::BASE64_STANDARD.encode(self.der)
        )
    }
}

impl std::fmt::Debug for X509<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509")
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

impl<'a> From<&'a x509_parser::certificate::X509Certificate<'a>> for X509<'a> {
    fn from(x509: &'a x509_parser::certificate::X509Certificate<'a>) -> Self {

        X509 {
            certificate: x509.clone(),
            der: x509.as_ref(),
        }
    }
}

impl<'a> Deref for X509<'a> {
    type Target = x509_parser::certificate::X509Certificate<'a>;

    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl Serialize for X509<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.der)
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for X509<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: &'a [u8] = Deserialize::deserialize(deserializer)?;
        let x509 = x509_parser::certificate::X509Certificate::from_der(&bytes).map_err(serde::de::Error::custom)?.1;

        Ok(X509 {
            certificate: x509,
            der: &bytes,
        })
    }
}

impl AsRef<[u8]> for X509<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.der
    }
}

impl<'a> TryFrom<&'a Vec<u8>> for X509<'a> {
    type Error = x509_parser::error::X509Error;

    fn try_from(value: &'a Vec<u8>) -> Result<Self, Self::Error> {

        let bytes = value.as_ref();

        let x509 = x509_parser::certificate::X509Certificate::from_der(&bytes)?.1;
        Ok(X509 {
            certificate: x509,
            der: &bytes,
        })
    }
}

impl PartialEq for X509<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}
