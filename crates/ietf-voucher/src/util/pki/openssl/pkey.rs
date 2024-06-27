use std::ops::Deref;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Pkey {
    key: openssl::pkey::PKey<openssl::pkey::Public>,
    pem: Vec<u8>,
    der: Vec<u8>,
}

impl PartialEq for Pkey {
    fn eq(&self, other: &Self) -> bool {
        self.key.public_eq(other) && self.pem == other.pem && self.der == other.der
    }
}

impl Eq for Pkey {}

impl From<openssl::pkey::PKey<openssl::pkey::Public>> for Pkey {
    fn from(pkey: openssl::pkey::PKey<openssl::pkey::Public>) -> Self {
        let der = pkey.public_key_to_der().unwrap();
        let pem = pkey.public_key_to_pem().unwrap();

        Pkey {
            key: pkey,
            pem,
            der,
        }
    }
}

impl Deref for Pkey {
    type Target = openssl::pkey::PKey<openssl::pkey::Public>;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Serialize for Pkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.der)
    }
}

impl<'de> Deserialize<'de> for Pkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let pkey =
            openssl::pkey::PKey::public_key_from_der(&bytes).map_err(serde::de::Error::custom)?;
        let pem = pkey.public_key_to_pem().map_err(serde::de::Error::custom)?;

        Ok(Pkey {
            key: pkey,
            pem,
            der: bytes,
        })
    }
}

impl AsRef<[u8]> for Pkey {
    fn as_ref(&self) -> &[u8] {
        &self.pem
    }
}

impl TryFrom<Vec<u8>> for Pkey {
    type Error = openssl::error::ErrorStack;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let pkey = openssl::pkey::PKey::public_key_from_der(&value)?;
        Ok(Pkey::from(pkey))
    }
}
