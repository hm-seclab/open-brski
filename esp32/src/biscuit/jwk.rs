//! JSON Web Key
//!
//! This module implements code for JWK as described in [RFC7517](https://tools.ietf.org/html/rfc7517).

use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use num_bigint::BigUint;
use serde::de::{self, DeserializeOwned};
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

use crate::biscuit::errors::Error;
use crate::biscuit::jwa::Algorithm;
use crate::biscuit::jws;
use crate::biscuit::serde_custom;
use crate::biscuit::Empty;

/// Type of Key as specified in RFC 7518.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Copy, Clone)]
pub enum KeyType {
    /// Elliptic curve (EC) key
    EllipticCurve,
    /// RSA key
    RSA,
    /// Octet symmetric key
    #[serde(rename = "oct")]
    Octet,
    /// Octet key pair
    #[serde(rename = "OKP")]
    OctetKeyPair,
}

impl KeyType {
    /// Description of the type of key
    pub fn description(self) -> &'static str {
        match self {
            KeyType::EllipticCurve => "Elliptic curve (EC) key",
            KeyType::RSA => "RSA key",
            KeyType::Octet => "Octet symmetric key",
            KeyType::OctetKeyPair => "Octet key pair",
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// The intended usage of the public `KeyType`. This enum is serialized `untagged`
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicKeyUse {
    /// Indicates a public key is meant for signature verification
    Signature,
    /// Indicates a public key is meant for encryption
    Encryption,
    /// Other usage
    Other(String),
}

impl Serialize for PublicKeyUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = match *self {
            PublicKeyUse::Signature => "sig",
            PublicKeyUse::Encryption => "enc",
            PublicKeyUse::Other(ref other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for PublicKeyUse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyUseVisitor;
        impl<'de> de::Visitor<'de> for PublicKeyUseVisitor {
            type Value = PublicKeyUse;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(match v {
                    "sig" => PublicKeyUse::Signature,
                    "enc" => PublicKeyUse::Encryption,
                    other => PublicKeyUse::Other(other.to_string()),
                })
            }
        }

        deserializer.deserialize_string(PublicKeyUseVisitor)
    }
}

/// Operations that the key is intended to be used for. This enum is serialized `untagged`
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyOperations {
    /// Compute digital signature or MAC
    Sign,
    /// Verify digital signature or MAC
    Verify,
    /// Encrypt content
    Encrypt,
    /// Decrypt content and validate decryption, if applicable
    Decrypt,
    /// Encrypt key
    WrapKey,
    /// Decrypt key and validate decryption, if applicable
    UnwrapKey,
    /// Derive key
    DeriveKey,
    /// Derive bits not to be used as a key
    DeriveBits,
    /// Other operation
    Other(String),
}

impl Serialize for KeyOperations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = match *self {
            KeyOperations::Sign => "sign",
            KeyOperations::Verify => "verify",
            KeyOperations::Encrypt => "encrypt",
            KeyOperations::Decrypt => "decrypt",
            KeyOperations::WrapKey => "wrapKey",
            KeyOperations::UnwrapKey => "unwrapKey",
            KeyOperations::DeriveKey => "deriveKey",
            KeyOperations::DeriveBits => "deriveBits",
            KeyOperations::Other(ref other) => other,
        };

        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for KeyOperations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KeyOperationsVisitor;
        impl<'de> de::Visitor<'de> for KeyOperationsVisitor {
            type Value = KeyOperations;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(match v {
                    "sign" => KeyOperations::Sign,
                    "verify" => KeyOperations::Verify,
                    "encrypt" => KeyOperations::Encrypt,
                    "decrypt" => KeyOperations::Decrypt,
                    "wrapKey" => KeyOperations::WrapKey,
                    "unwrapKey" => KeyOperations::UnwrapKey,
                    "deriveKey" => KeyOperations::DeriveKey,
                    "deriveBits" => KeyOperations::DeriveBits,
                    other => KeyOperations::Other(other.to_string()),
                })
            }
        }

        deserializer.deserialize_string(KeyOperationsVisitor)
    }
}

/// Common JWK parameters
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct CommonParameters {
    /// The intended use of the public key. Should not be specified with `key_operations`.
    /// See sections 4.2 and 4.3 of [RFC7517](https://tools.ietf.org/html/rfc7517).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none", default)]
    pub public_key_use: Option<PublicKeyUse>,

    /// The "key_ops" (key operations) parameter identifies the operation(s)
    /// for which the key is intended to be used.  The "key_ops" parameter is
    /// intended for use cases in which public, private, or symmetric keys
    /// may be present.
    /// Should not be specified with `public_key_use`.
    /// See sections 4.2 and 4.3 of [RFC7517](https://tools.ietf.org/html/rfc7517).
    #[serde(rename = "key_ops", skip_serializing_if = "Option::is_none", default)]
    pub key_operations: Option<Vec<KeyOperations>>,

    /// The algorithm intended for use with the key
    #[serde(rename = "alg", skip_serializing_if = "Option::is_none", default)]
    pub algorithm: Option<Algorithm>,

    /// The case sensitive Key ID for the key
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none", default)]
    pub key_id: Option<String>,

    /// X.509 Public key cerfificate URL. This is currently not implemented (correctly).
    /// Serialized to `x5u`.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    /// X.509 public key certificate chain. This is currently not implemented (correctly).
    /// Serialized to `x5c`.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,

    /// X.509 Certificate thumbprint. This is currently not implemented (correctly).
    /// Also not implemented, is the SHA-256 thumbprint variant of this header.
    /// Serialized to `x5t`.
    // TODO: How to make sure the headers are mutually exclusive?
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_fingerprint: Option<String>,
}

/// Algorithm specific parameters
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AlgorithmParameters {
    /// Elliptic curve (EC) key
    EllipticCurve(EllipticCurveKeyParameters),

    /// RSA key
    RSA(RSAKeyParameters),

    /// Octet symmetric key
    OctetKey(OctetKeyParameters),

    /// Octet key pair
    OctetKeyPair(OctetKeyPairParameters),
}

impl fmt::Debug for AlgorithmParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let algo_type = match *self {
            AlgorithmParameters::EllipticCurve(_) => "EllipticCurve",
            AlgorithmParameters::RSA(_) => "RSA",
            AlgorithmParameters::OctetKey(_) => "OctetKey",
            AlgorithmParameters::OctetKeyPair(_) => "OctetKeyPair",
        };
        write!(f, "{} {{ .. }}", algo_type)
    }
}

impl AlgorithmParameters {
    /// Returns the type of key represented by this set of algorithm parameters
    pub fn key_type(&self) -> KeyType {
        match *self {
            AlgorithmParameters::EllipticCurve(_) => KeyType::EllipticCurve,
            AlgorithmParameters::RSA(_) => KeyType::RSA,
            AlgorithmParameters::OctetKey(_) => KeyType::Octet,
            AlgorithmParameters::OctetKeyPair(_) => KeyType::OctetKeyPair,
        }
    }

    /// Return the byte sequence of an octet key
    pub fn octet_key(&self) -> Result<&[u8], Error> {
        match *self {
            AlgorithmParameters::OctetKey(ref oct) => Ok(oct.value.as_slice()),
            _ => Err(unexpected_key_type_error!(KeyType::Octet, self.key_type())),
        }
    }

    /// JWK thumbprints are digests for identifying key material.
    /// Their computation is specified in
    /// [RFC 7638](https://tools.ietf.org/html/rfc7638).
    ///
    /// This can be used to identify a public key; when the underlying digest algorithm
    /// is collision-resistant (currently, the SHA-2 family is provided), it is infeasible
    /// to build two keys sharing a thumbprint.
    ///
    /// As mentioned in the RFC's security considerations, it remains possible to build
    /// related keys with distinct parameters and thumbprints.
    ///
    /// ```
    /// // Example from https://tools.ietf.org/html/rfc7638#section-3.1
    /// let jwk: biscuit::jwk::JWK<biscuit::Empty> = serde_json::from_str(
    /// r#"{
    ///   "kty": "RSA",
    ///   "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    ///   "e": "AQAB",
    ///   "alg": "RS256",
    ///   "kid": "2011-04-29"
    ///   }"#,
    /// ).unwrap();
    /// assert_eq!(
    ///   jwk.algorithm.thumbprint(&biscuit::digest::SHA256).unwrap(),
    ///   "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    /// );
    /// ```
    pub fn thumbprint(
        &self,
        algorithm: &'static crate::biscuit::digest::Algorithm,
    ) -> Result<String, serde_json::error::Error> {
        use serde::ser::SerializeMap;

        use crate::biscuit::serde_custom::{base64_url_uint, byte_sequence};

        let mut serializer = serde_json::Serializer::new(Vec::new());
        let mut map = serializer.serialize_map(None)?;
        // https://tools.ietf.org/html/rfc7638#section-3.2
        // Write required public key parameters in lexicographic order
        match self {
            AlgorithmParameters::EllipticCurve(params) => {
                map.serialize_entry("crv", &params.curve)?;
                map.serialize_entry("kty", &params.key_type)?;
                map.serialize_entry("x", &byte_sequence::wrap(&params.x))?;
                map.serialize_entry("y", &byte_sequence::wrap(&params.y))?;
            }
            AlgorithmParameters::RSA(params) => {
                map.serialize_entry("e", &base64_url_uint::wrap(&params.e))?;
                map.serialize_entry("kty", &params.key_type)?;
                map.serialize_entry("n", &base64_url_uint::wrap(&params.n))?;
            }
            AlgorithmParameters::OctetKey(params) => {
                map.serialize_entry("k", &byte_sequence::wrap(&params.value))?;
                map.serialize_entry("kty", &params.key_type)?;
            }
            AlgorithmParameters::OctetKeyPair(params) => {
                map.serialize_entry("crv", &params.curve)?;
                map.serialize_entry("kty", &params.key_type)?;
                map.serialize_entry("x", &byte_sequence::wrap(&params.x))?;
            }
        }
        map.end()?;
        let json_u8 = serializer.into_inner();
        Ok(BASE64URL_NOPAD.encode(ring::digest::digest(algorithm.0, &json_u8).as_ref()))
    }
}

/// Parameters for an Elliptic Curve Key
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct EllipticCurveKeyParameters {
    /// Key type value for an Elliptic Curve Key.
    #[serde(rename = "kty")]
    pub key_type: EllipticCurveKeyType,
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    /// The "x" (x coordinate) parameter contains the x coordinate for the
    /// Elliptic Curve point. Serialized to base64 URL encoded
    #[serde(with = "serde_custom::byte_sequence")]
    pub x: Vec<u8>,
    /// The "y" (y coordinate) parameter contains the y coordinate for the
    /// Elliptic Curve point. Serialized to base64 URL encoded
    #[serde(with = "serde_custom::byte_sequence")]
    pub y: Vec<u8>,
    /// The "d" (ECC private key) parameter contains the Elliptic Curve
    /// private key value.
    #[serde(
        with = "serde_custom::option_byte_sequence",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<Vec<u8>>,
}

impl EllipticCurveKeyParameters {
    /// Construct a `jws::Secret` EC public key for signature verification
    pub fn jws_public_key_secret(&self) -> jws::Secret {
        let mut vec = Vec::with_capacity(self.x.len() + self.y.len() + 1);
        // to sec1 uncompressed
        vec.push(0x04);
        vec.extend(self.x.iter().copied());
        vec.extend(self.y.iter().copied());
        jws::Secret::PublicKey(vec)
    }
}

/// Parameters for a RSA Key
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct RSAKeyParameters {
    /// Key type value for a RSA Key
    #[serde(rename = "kty")]
    pub key_type: RSAKeyType,

    /// The "n" (modulus) parameter contains the modulus value for the RSA
    /// public key.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub n: BigUint,

    /// The "e" (exponent) parameter contains the exponent value for the RSA
    /// public key.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub e: BigUint,

    /// The "d" (private exponent) parameter contains the private exponent
    /// value for the RSA private key.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<BigUint>,

    /// The "p" (first prime factor) parameter contains the first prime
    /// factor.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub p: Option<BigUint>,

    /// The "q" (second prime factor) parameter contains the second prime
    /// factor.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub q: Option<BigUint>,

    /// The "dp" (first factor CRT exponent) parameter contains the Chinese
    /// Remainder Theorem (CRT) exponent of the first factor.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dp: Option<BigUint>,

    /// The "dq" (second factor CRT exponent) parameter contains the CRT
    /// exponent of the second factor.
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dq: Option<BigUint>,

    /// The "qi" (first CRT coefficient) parameter contains the CRT
    /// coefficient of the second factor
    /// It is serialized as a `Base64urlUInt`-encoded value.
    #[serde(
        with = "serde_custom::option_base64_url_uint",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub qi: Option<BigUint>,

    /// The "oth" (other primes info) parameter contains an array of
    /// information about any third and subsequent primes, should they exist.
    #[serde(rename = "oth", skip_serializing_if = "Option::is_none", default)]
    pub other_primes_info: Option<Vec<OtherPrimesInfo>>,
}

impl RSAKeyParameters {
    /// Construct a `jws::Secret` RSA public key for signature verification
    pub fn jws_public_key_secret(&self) -> jws::Secret {
        jws::Secret::RSAModulusExponent {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }
}

/// The "oth" (other primes info) parameter contains an array of
/// information about any third and subsequent primes, should they exist.
/// When only two primes have been used (the normal case), this parameter
/// MUST be omitted.  When three or more primes have been used, the
/// number of array elements MUST be the number of primes used minus two.
/// For more information on this case, see the description of the
/// `OtherPrimeInfo` parameters in [Appendix A.1.2 of RFC 3447](https://tools.ietf.org/html/rfc3447#appendix-A.1.2),
/// upon which the following parameters are modeled.  If the consumer of
/// a JWK does not support private keys with more than two primes and it
/// encounters a private key that includes the "oth" parameter, then it
/// MUST NOT use the key.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OtherPrimesInfo {
    /// The "r" (prime factor) parameter
    /// represents the value of a subsequent prime factor.
    /// It is serialized as a Base64urlUInt-encoded value.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub r: BigUint,

    /// The "d" (factor CRT exponent) parameter
    /// represents the CRT exponent of the corresponding prime factor.
    /// It is serialized as a Base64urlUInt-encoded value.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub d: BigUint,

    /// The "t" (factor CRT coefficient) parameter
    /// member represents the CRT coefficient of the corresponding prime
    /// factor.
    #[serde(with = "serde_custom::base64_url_uint")]
    pub t: BigUint,
}

/// Parameters for an Octet Key
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct OctetKeyParameters {
    /// Key type value for an Octet Key
    #[serde(rename = "kty")]
    pub key_type: OctetKeyType,
    /// The octet key value
    #[serde(rename = "k", with = "serde_custom::byte_sequence")]
    pub value: Vec<u8>,
}

/// Parameters for an Octet Key Pair
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct OctetKeyPairParameters {
    /// Key type value for an Octet Key Pair
    #[serde(rename = "kty")]
    pub key_type: OctetKeyPairType,
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    /// The "x" parameter contains the base64 encoded public key
    #[serde(with = "serde_custom::byte_sequence")]
    pub x: Vec<u8>,
    /// The "d" parameter contains the base64 encoded private key
    #[serde(
        with = "serde_custom::option_byte_sequence",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<Vec<u8>>,
}

/// Key type value for an Elliptic Curve Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum EllipticCurveKeyType {
    /// Key type value for an Elliptic Curve Key.
    #[default]
    EC,
}

/// Key type value for an RSA Key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum RSAKeyType {
    /// Key type value for an RSA Key.
    #[default]
    RSA,
}

/// Key type value for an Octet symmetric key.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum OctetKeyType {
    /// Key type value for an Octet symmetric key.
    #[serde(rename = "oct")]
    #[default]
    Octet,
}

/// Key type value for an Octet Key Pair.
/// This single value enum is a workaround for Rust not supporting associated constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum OctetKeyPairType {
    /// Key type value for an Octet Key Pair.
    #[serde(rename = "OKP")]
    #[default]
    OctetKeyPair,
}

/// Type of cryptographic curve used by a key. This is defined in
/// [RFC 7518 #7.6](https://tools.ietf.org/html/rfc7518#section-7.6)
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum EllipticCurve {
    /// P-256 curve
    #[serde(rename = "P-256")]
    #[default]
    P256,
    /// P-384 curve
    #[serde(rename = "P-384")]
    P384,
    /// P-521 curve -- unsupported by `ring`.
    #[serde(rename = "P-521")]
    P521,
    /// Curve25519
    #[serde(rename = "Ed25519")]
    Curve25519,
    /// Curve448
    #[serde(rename = "Ed448")]
    Curve448,
}

/// A JSON object that represents a cryptographic key.
/// The members of the object represent properties of the key, including its value.
/// Type `T` is a struct representing additional JWK properties
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JWK<T> {
    /// Common JWK parameters
    #[serde(flatten)]
    pub common: CommonParameters,
    /// Key algorithm specific parameters
    #[serde(flatten)]
    pub algorithm: AlgorithmParameters,
    /// Additional JWK parameters
    #[serde(flatten)]
    pub additional: T,
}

impl<T: Serialize + DeserializeOwned> JWK<T> {
    /// Convenience to create a new bare-bones Octet key
    pub fn new_octet_key(key: &[u8], additional: T) -> Self {
        Self {
            algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                value: key.to_vec(),
                key_type: Default::default(),
            }),
            common: Default::default(),
            additional,
        }
    }

    /// Convenience function to strip out the additional fields
    pub fn clone_without_additional(&self) -> JWK<Empty> {
        JWK {
            common: self.common.clone(),
            algorithm: self.algorithm.clone(),
            additional: Default::default(),
        }
    }

    /// Returns the type of key represented by this key
    pub fn key_type(&self) -> KeyType {
        self.algorithm.key_type()
    }

    /// Return the byte sequence of an octet key
    pub fn octet_key(&self) -> Result<&[u8], Error> {
        self.algorithm.octet_key()
    }
}

/// A JSON object that represents a set of JWKs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JWKSet<T> {
    /// Contained JWKs
    pub keys: Vec<JWK<T>>,
}

impl<T> JWKSet<T> {
    /// Find the key in the set that matches the given key id, if any.
    pub fn find(&self, kid: &str) -> Option<&JWK<T>> {
        self.keys
            .iter()
            .find(|jwk| jwk.common.key_id.is_some() && jwk.common.key_id.as_ref().unwrap() == kid)
    }
}
