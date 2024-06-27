use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// A wrapper around an X.509 certificate.
/// It will always be serialized by serde as a DER-encoded X.509 certificate.
/// To serialize it as a PEM-encoded X.509 certificate, use serde_as base64. This will convert the certificate to a PEM-encoded string and then base64 encode it.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct X509(Vec<u8>);
