
use super::{Header, RegisteredHeader, Secret};
use crate::biscuit::errors::{Error, ValidationError};
use crate::biscuit::jwa::SignatureAlgorithm;
use crate::biscuit::serde_custom;

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use data_encoding::BASE64URL_NOPAD;

// Not using CompactPart::to_bytes here, bounds are overly restrictive
pub(crate) fn serialize_header<H: Serialize>(header: &Header<H>) -> Result<Vec<u8>, serde_json::Error> {
    // I don't think RegisteredHeader can fail to serialize,
    // but the private header fields are user controlled and might
    serde_json::to_vec(header)
}

// Warning: pay attention to parameter order
// Note: this is valid UTF-8, but gets used as bytes later
pub(crate) fn signing_input(protected_header: &[u8], payload: &[u8]) -> Vec<u8> {
    let hlen = BASE64URL_NOPAD.encode_len(protected_header.len());
    let plen = BASE64URL_NOPAD.encode_len(payload.len());
    let mut r = Vec::with_capacity(hlen + plen + 1);
    r.append(&mut BASE64URL_NOPAD.encode(protected_header).into_bytes());
    r.push(b'.');
    r.append(&mut BASE64URL_NOPAD.encode(payload).into_bytes());
    r
}

pub(crate) fn deserialize_reject<'de, D>(_de: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    Err(serde::de::Error::custom("invalid field"))
}