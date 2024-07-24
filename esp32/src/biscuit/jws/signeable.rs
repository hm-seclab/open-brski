//! Flattened JWS signatures: see RFC 7515 section 7.2.2
//! Flattened signatures are JSON (unlike compact signatures),
//! and support a single signature protecting a set of headers and a
//! payload.
//!
//! The RFC specifies unprotected headers as well, but this implementation
//! doesn't support them.

use super::flattened::FlattenedRaw;
use super::general::{GeneralRaw, Signature};
use super::util::{serialize_header, signing_input};
use super::{Header, RegisteredHeader, Secret};
use crate::biscuit::errors::{Error, ValidationError};
use crate::biscuit::jwa::SignatureAlgorithm;
use crate::biscuit::serde_custom;

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};


/// Data that can be turned into a JWS
///
/// This struct ensures that the serialized data is stable;
/// [`Signable::protected_header_serialized`] and [`Signable::payload`]
/// will always return the same bytes; [`Signable::protected_header_registered`]
/// will always return a reference to the same [`RegisteredHeader`]
/// struct.
///
/// This allows [`SignedData`] to retain the data as it was signed,
/// carrying a signature that remains verifiable.
///
/// # Examples
/// ```
/// use biscuit::jws::{Header, RegisteredHeader, Signable};
/// use biscuit::jwa::SignatureAlgorithm;
/// use biscuit::Empty;
/// let header = Header::<Empty>::from(RegisteredHeader {
///     algorithm: SignatureAlgorithm::ES256,
///     ..Default::default()
/// });
/// let payload = b"These bytes cannot be altered";
/// let data = Signable::new(header, payload.to_vec())?;
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Signable {
    // We need both fields for the protected header
    // so we can trust that signed data is stable
    protected_header_registered: RegisteredHeader,
    protected_header_serialized: Vec<u8>,
    payload: Vec<u8>,
}

impl Signable {
    /// Build a Signable from a header and a payload
    ///
    /// Header and payload will both be protected by the signature,
    /// we do not make use of unprotected headers
    ///
    /// # Errors
    /// Errors are returned if headers can't be serialized;
    /// this would only happen if the `H` type carrying extension headers
    /// can not be serialized.
    pub fn new<H: Serialize>(
        header: Header<H>,
        payload: Vec<u8>,
    ) -> Result<Self, serde_json::Error> {
        let protected_header_serialized = serialize_header(&header)?;
        let protected_header_registered = header.registered;
        Ok(Self {
            protected_header_registered,
            protected_header_serialized,
            payload,
        })
    }

    /// Convenience function to build a SignedData from this Signable
    /// See [`SignedData::sign`]
    pub fn sign(self, secret: Secret) -> Result<SignedData, Error> {
        SignedData::sign(self, secret)
    }

    /// JWS Signing Input
    fn signing_input(&self) -> Vec<u8> {
        signing_input(&self.protected_header_serialized, &self.payload)
    }

    /// Return a reference to the registered (known to biscuit)
    /// protected headers
    pub fn protected_header_registered(&self) -> &RegisteredHeader {
        &self.protected_header_registered
    }

    /// Return a reference to protected headers as they were serialized
    pub fn protected_header_serialized(&self) -> &[u8] {
        &self.protected_header_serialized
    }

    /// Deserialize protected headers
    ///
    /// This allows access to protected headers beyond those
    /// that are recognized with RegisteredHeader
    pub fn deserialize_protected_header<H: DeserializeOwned>(
        &self,
    ) -> serde_json::Result<Header<H>> {
        serde_json::from_slice(&self.protected_header_serialized)
    }

    /// Return a reference to the payload bytes
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Deserialize a JSON payload
    ///
    /// # Note
    /// JWS does not put any requirement on payload bytes, which
    /// need not be JSON
    pub fn deserialize_json_payload<T: DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_slice(&self.payload)
    }
}

/// Signed data (with a single signature)
///
/// This representation preserves the exact serialisation of
/// the payload and protected headers, but it is independent of how
/// the signature may be serialized (eg, flattened or compact JWS)
///
/// Signed data can be obtained by either deserializing a valid JWS,
/// or by signing a Signable
#[derive(Clone)]
pub struct SignedData {
    data: Signable,
    #[allow(dead_code)]
    secret: Secret,
    signature: Vec<u8>,
}

impl SignedData {
    /// Sign using a secret
    ///
    /// # Example
    /// ```
    /// use biscuit::jwa::SignatureAlgorithm;
    /// use biscuit::jws::{Header, RegisteredHeader, Secret, Signable, SignedData};
    /// use biscuit::Empty;
    /// use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    /// use std::sync::Arc;
    ///
    /// let header = Header::<Empty>::from(RegisteredHeader {
    ///     algorithm: SignatureAlgorithm::ES256,
    ///     ..Default::default()
    /// });
    /// let payload = b"These bytes cannot be altered";
    /// let data = Signable::new(header, payload.to_vec())?;
    /// let pkcs8 = EcdsaKeyPair::generate_pkcs8(
    ///     &ECDSA_P256_SHA256_FIXED_SIGNING,
    ///     &ring::rand::SystemRandom::new())?;
    /// let keypair = EcdsaKeyPair::from_pkcs8(
    ///     &ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(),
    ///     &ring::rand::SystemRandom::new())?;
    /// let secret = Secret::EcdsaKeyPair(Arc::new(keypair));
    /// let signed = SignedData::sign(data, secret)?;
    /// # Ok::<(), biscuit::errors::Error>(())
    /// ```
    pub fn sign(data: Signable, secret: Secret) -> Result<Self, Error> {
        let signature = data
            .protected_header_registered
            .algorithm
            .sign(&data.signing_input(), &secret)?;

        Ok(Self {
            data,
            secret,
            signature,
        })
    }

    /// Serialize using Flattened JWS JSON Serialization
    ///
    /// See [RFC 7515 section 7.2.2](https://tools.ietf.org/html/rfc7515#section-7.2.2)
    pub fn serialize_flattened(&self) -> String {
        let payload = self.data.payload.clone();
        let protected_header = self.data.protected_header_serialized.clone();
        let signature = self.signature.clone();
        let s = FlattenedRaw {
            payload,
            protected_header,
            signature,
            signatures: (),
            unprotected_header: (),
        };
        // This shouldn't fail, because FlattenedRaw strucs are
        // always representable in JSON
        serde_json::to_string(&s).expect("Failed to serialize FlattenedRaw to JSON")
    }

    /// Serialize using General JWS JSON Serialization
    ///
    /// See [RFC 7515 section 7.2.1](https://tools.ietf.org/html/rfc7515#section-7.2.1)
    pub fn serialize_general(&self) -> String {
        let payload = self.data.payload.clone();
        let protected_header = self.data.protected_header_serialized.clone();
        let signature = self.signature.clone();

        let sig = Signature {
            protected_header,
            signature,
            unprotected_header: (),
        };

        let s = GeneralRaw {
            payload,
            signatures: vec![sig],
        };
        // This shouldn't fail, because General strucs are
        // always representable in JSON
        serde_json::to_string(&s).expect("Failed to serialize GeneralRaw to JSON")
    }

    /// Verify a Flattened JWS JSON Serialization carries a valid signature
    ///
    /// # Example
    /// ```
    /// use biscuit::jwa::SignatureAlgorithm;
    /// use biscuit::jws::{Secret, SignedData};
    /// use data_encoding::HEXUPPER;
    /// let public_key =
    ///     "043727F96AAD416887DD75CC2E333C3D8E06DCDF968B6024579449A2B802EFC891F638C75\
    ///     1CF687E6FF9A280E11B7036585E60CA32BB469C3E57998A289E0860A6";
    /// let jwt = "{\
    ///     \"payload\":\"eyJ0b2tlbl90eXBlIjoic2VydmljZSIsImlhdCI6MTQ5MjkzODU4OH0\",\
    ///     \"protected\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9\",\
    ///     \"signature\":\"do_XppIOFthPWlTXL95CIBfgRdyAxbcIsUfM0YxMjCjqvp4ehHFA3I-JasABKzC8CAy4ndhCHsZdpAtKkqZMEA\"}";
    /// let secret = Secret::PublicKey(HEXUPPER.decode(public_key.as_bytes()).unwrap());
    /// let signed = SignedData::verify_flattened(
    ///     jwt.as_bytes(),
    ///     secret,
    ///     SignatureAlgorithm::ES256
    /// )?;
    /// # Ok::<(), biscuit::errors::Error>(())
    /// ```
    pub fn verify_flattened(
        data: &[u8],
        secret: Secret,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, Error> {
        let raw: FlattenedRaw = serde_json::from_slice(data)?;
        algorithm
            .verify(&raw.signature, &raw.signing_input(), &secret)
            .map_err(|_| ValidationError::InvalidSignature)?;
        let protected_header_registered: RegisteredHeader =
            serde_json::from_slice(&raw.protected_header)?;
        if protected_header_registered.algorithm != algorithm {
            Err(ValidationError::WrongAlgorithmHeader)?;
        }
        let data = Signable {
            protected_header_registered,
            protected_header_serialized: raw.protected_header,
            payload: raw.payload,
        };
        Ok(Self {
            data,
            secret,
            signature: raw.signature,
        })
    }

    /// Access the data protected by the signature
    pub fn data(&self) -> &Signable {
        &self.data
    }
}
