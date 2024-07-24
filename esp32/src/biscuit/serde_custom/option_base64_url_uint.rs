//! Serialize and Deserialize `num_bigint::BigUint` into `Base64urlUInt` form as described in
//! [RFC 7518](https://tools.ietf.org/html/rfc7518).
//! The integers are first converted into bytes in big-endian form and then base64 encoded.
use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use num_bigint::BigUint;
use serde::de;
use serde::{Deserializer, Serializer};

/// Serialize a `BigUint` into Base64 URL encoded big endian bytes
pub fn serialize<S>(value: &Option<BigUint>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match *value {
        Some(ref value) => {
            let bytes = value.to_bytes_be();
            let base64 = BASE64URL_NOPAD.encode(bytes.as_slice());
            serializer.serialize_some(&base64)
        }
        None => serializer.serialize_none(),
    }
}

/// Deserialize a `BigUint` from Base64 URL encoded big endian bytes
pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<BigUint>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BigUintVisitor;

    impl<'de> de::Visitor<'de> for BigUintVisitor {
        type Value = Option<BigUint>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a Base64urlUInt string")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(self)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = BASE64URL_NOPAD
                .decode(value.as_bytes())
                .map_err(E::custom)?;
            Ok(Some(BigUint::from_bytes_be(&bytes)))
        }
    }

    deserializer.deserialize_option(BigUintVisitor)
}

