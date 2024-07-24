//! General JWS signatures: see RFC 7515 section 7.2.2
//! General signatures are JSON (unlike compact signatures),
//! and support a single signature protecting a set of headers and a
//! payload.
//!
//! The RFC specifies unprotected headers as well, but this implementation
//! doesn't support them.

use super::util::{serialize_header, signing_input};
use super::{Header, RegisteredHeader, Secret};
use crate::biscuit::errors::{Error, ValidationError};
use crate::biscuit::jwa::SignatureAlgorithm;
use crate::biscuit::serde_custom;
use data_encoding::BASE64URL_NOPAD;

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use super::util::deserialize_reject;

/// This is for serialization, and deserialisation when the signature
/// hasn't been verified, not exposed externally
#[derive(Serialize, Deserialize)]
pub(crate) struct GeneralRaw {

    #[serde(with = "serde_custom::byte_sequence")]
    pub(crate) payload: Vec<u8>,

    pub(crate) signatures: Vec<Signature>,
}

impl GeneralRaw {
    /// JWS Signing Input
    pub(crate) fn signing_input(&self) -> Vec<Vec<u8>> {
        self.signatures
            .iter()
            .map(|s| signing_input(&s.protected_header, &self.payload))
            .collect()
    }
}

/// This is for serialization, and deserialisation when the signature
/// hasn't been verified, not exposed externally
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Signature {
    #[serde(rename = "protected", with = "serde_custom::byte_sequence")]
    pub(crate) protected_header: Vec<u8>,

    #[serde(with = "serde_custom::byte_sequence")]
    pub(crate) signature: Vec<u8>,

    // Headers unprotected by the signature are rejected
    #[serde(
        rename = "header",
        default,
        deserialize_with = "deserialize_reject",
        skip_serializing
    )]
    #[allow(dead_code)]
    pub(crate) unprotected_header: (),
}