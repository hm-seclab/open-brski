//! Flattened JWS signatures: see RFC 7515 section 7.2.2
//! Flattened signatures are JSON (unlike compact signatures),
//! and support a single signature protecting a set of headers and a
//! payload.
//!
//! The RFC specifies unprotected headers as well, but this implementation
//! doesn't support them.

use super::util::{serialize_header, signing_input, deserialize_reject};
use super::{Header, RegisteredHeader, Secret};
use crate::biscuit::errors::{Error, ValidationError};
use crate::biscuit::jwa::SignatureAlgorithm;
use crate::biscuit::serde_custom;

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};

/// This is for serialization, and deserialisation when the signature
/// hasn't been verified, not exposed externally
#[derive(Serialize, Deserialize)]
pub(crate) struct FlattenedRaw {
    #[serde(rename = "protected", with = "serde_custom::byte_sequence")]
    pub(crate) protected_header: Vec<u8>,

    #[serde(with = "serde_custom::byte_sequence")]
    pub(crate) payload: Vec<u8>,

    #[serde(with = "serde_custom::byte_sequence")]
    pub(crate) signature: Vec<u8>,

    // These fields must be understood and rejected
    // (unlike unknown fields, which must be ignored)
    // This member indicates non-flattened, generalized signatures
    #[serde(default, deserialize_with = "deserialize_reject", skip_serializing)]
    #[allow(dead_code)]
    pub(crate) signatures: (),

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

impl FlattenedRaw {
    /// JWS Signing Input
    pub(crate) fn signing_input(&self) -> Vec<u8> {
        signing_input(&self.protected_header, &self.payload)
    }
}

#[cfg(test)]
mod tests {
    use std::str::{self, FromStr};

    use serde::{Deserialize, Serialize};

    use super::{Header, Secret};
    use crate::biscuit::jwa::SignatureAlgorithm;
    use crate::biscuit::jws::RegisteredHeader;
    use crate::biscuit::{ClaimsSet, CompactJson, CompactPart, Empty, RegisteredClaims, SingleOrMultiple};

    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    struct PrivateClaims {
        company: String,
        department: String,
    }

    impl CompactJson for PrivateClaims {}

    // HS256 key - "secret"
    static HS256_PAYLOAD: &str = "{\"protected\":\"eyJhbGciOiJIUz\
    I1NiIsInR5cCI6IkpXVCJ9\",\"payload\":\"eyJpc3MiOiJodHRwczovL3\
    d3dy5hY21lLmNvbS8iLCJzdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZ\
    S1jdXN0b21lci5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFy\
    dG1lbnQiOiJUb2lsZXQgQ2xlYW5pbmcifQ\",\"signature\":\"VFCl2un1Kc17odzOe2Ehf4DVrW\
    ddu3U4Ux3GFpOZHtc\"}";

    #[test]
    fn flattened_jws_round_trip_none() {
        let expected_value = not_err!(serde_json::to_value(
            "{\"protected\":\"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0\",\
            \"payload\":\"eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJz\
            dWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZS1jdXN0b21lci5j\
            b20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lbnQi\
            OiJUb2lsZXQgQ2xlYW5pbmcifQ\",\
            \"signature\":\"\"}"
        ));

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = not_err!(SignedData::sign(
            not_err!(Signable::new::<Empty>(
                From::from(RegisteredHeader {
                    algorithm: SignatureAlgorithm::None,
                    ..Default::default()
                }),
                expected_claims.to_bytes().unwrap(),
            )),
            Secret::None,
        ));
        let token = expected_jwt.serialize_flattened();
        assert_eq!(expected_value, not_err!(serde_json::to_value(&token)));

        let biscuit: SignedData = not_err!(SignedData::verify_flattened(
            token.as_bytes(),
            Secret::None,
            SignatureAlgorithm::None,
        ));
        let actual_claims: ClaimsSet<PrivateClaims> =
            not_err!(biscuit.data().deserialize_json_payload());
        assert_eq!(&expected_claims, &actual_claims);
    }

    #[test]
    fn flattened_jws_round_trip_hs256() {
        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let expected_jwt = not_err!(SignedData::sign(
            not_err!(Signable::new(
                From::from(RegisteredHeader {
                    algorithm: SignatureAlgorithm::HS256,
                    ..Default::default()
                }),
                expected_claims.to_bytes().unwrap(),
            )),
            Secret::Bytes("secret".to_string().into_bytes())
        ));
        let token = expected_jwt.serialize_flattened();
        assert_eq!(
            not_err!(serde_json::to_value(HS256_PAYLOAD)),
            not_err!(serde_json::to_value(&token))
        );

        let biscuit = not_err!(SignedData::verify_flattened(
            token.as_bytes(),
            Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256
        ));
        assert_eq!(
            &expected_claims,
            &not_err!(biscuit.data().deserialize_json_payload())
        );
    }

    #[test]
    fn flattened_jws_round_trip_rs256() {
        let expected_value = not_err!(serde_json::to_value(
            "{\"protected\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\",\
            \"payload\":\"eyJpc3MiOiJodHRwczovL3d3dy5hY21lLmNvbS8iLCJ\
            zdWIiOiJKb2huIERvZSIsImF1ZCI6Imh0dHBzOi8vYWNtZS1jdXN0b21lci\
            5jb20vIiwibmJmIjoxMjM0LCJjb21wYW55IjoiQUNNRSIsImRlcGFydG1lb\
            nQiOiJUb2lsZXQgQ2xlYW5pbmcifQ\",\
            \"signature\":\"Gat3NBUTaCyvroil66U0nId4-l6VqbtJYIsM9wRbWo4\
            5oYoN-NxYIyl8M-9AlEPseg-4SIuo-A-jccJOWGeWWwy-Een_92wg18II58\
            luHz7vAyclw1maJBKHmuj8f2wE_Ky8ir3iTpTGkJQ3IUU9SuU9Fkvajm4jg\
            WUtRPpjHm_IqyxV8NkHNyN0p5CqeuRC8sZkOSFkm9b0WnWYRVls1QOjBnN9\
            w9zW9wg9DGwj10pqg8hQ5sy-C3J-9q1zJgGDXInkhPLjitO9wzWg4yfVt-C\
            JNiHsJT7RY_EN2VmbG8UOjHp8xUPpfqUKyoQttKaQkJHdjP_b47LO4ZKI4U\
            ivlA\"}"
        ));

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };
        let private_key =
            Secret::rsa_keypair_from_file("test/fixtures/rsa_private_key.der").unwrap();

        let expected_jwt = not_err!(SignedData::sign(
            not_err!(Signable::new(
                From::from(RegisteredHeader {
                    algorithm: SignatureAlgorithm::RS256,
                    ..Default::default()
                }),
                expected_claims.to_bytes().unwrap(),
            )),
            private_key,
        ));
        let token = expected_jwt.serialize_flattened();
        assert_eq!(expected_value, not_err!(serde_json::to_value(&token)));

        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let biscuit = not_err!(SignedData::verify_flattened(
            token.as_bytes(),
            public_key,
            SignatureAlgorithm::RS256,
        ));
        assert_eq!(
            expected_claims,
            not_err!(biscuit.data().deserialize_json_payload())
        );
    }

    #[test]
    fn flattened_jws_verify_es256() {
        use data_encoding::HEXUPPER;

        // This is a ECDSA Public key in `SubjectPublicKey` form.
        // Conversion is not available in `ring` yet.
        // See https://github.com/lawliet89/biscuit/issues/71#issuecomment-296445140 for a
        // way to retrieve it from `SubjectPublicKeyInfo`.
        let public_key =
            "043727F96AAD416887DD75CC2E333C3D8E06DCDF968B6024579449A2B802EFC891F638C75\
             1CF687E6FF9A280E11B7036585E60CA32BB469C3E57998A289E0860A6";
        let jwt = "{\
            \"payload\":\"eyJ0b2tlbl90eXBlIjoic2VydmljZSIsImlhdCI6MTQ5MjkzODU4OH0\",\
            \"protected\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9\",\
            \"signature\":\"do_XppIOFthPWlTXL95CIBfgRdyAxbcIsUfM0YxMjCjqvp4ehHFA3I-JasABKzC8CAy4ndhCHsZdpAtKkqZMEA\"}";
        let signing_secret = Secret::PublicKey(not_err!(HEXUPPER.decode(public_key.as_bytes())));

        let token = not_err!(SignedData::verify_flattened(
            jwt.as_bytes(),
            signing_secret,
            SignatureAlgorithm::ES256
        ));
        let jwt_val: super::FlattenedRaw = not_err!(serde_json::from_str(jwt));
        assert_eq!(jwt_val.payload.as_slice(), token.data().payload());
        assert_eq!(
            jwt_val.protected_header.as_slice(),
            token.data().protected_header_serialized()
        );
        assert_eq!(&jwt_val.signature, &token.signature);
    }

    #[test]
    fn flattened_jws_encode_with_additional_header_fields() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct CustomHeader {
            something: String,
        }

        let expected_claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(not_err!(FromStr::from_str("https://www.acme.com/"))),
                subject: Some(not_err!(FromStr::from_str("John Doe"))),
                audience: Some(SingleOrMultiple::Single(not_err!(FromStr::from_str(
                    "https://acme-customer.com/"
                )))),
                not_before: Some(1234.into()),
                ..Default::default()
            },
            private: PrivateClaims {
                department: "Toilet Cleaning".to_string(),
                company: "ACME".to_string(),
            },
        };

        let header = Header {
            registered: Default::default(),
            private: CustomHeader {
                something: "foobar".to_string(),
            },
        };

        let expected_jwt = not_err!(SignedData::sign(
            not_err!(Signable::new(
                header.clone(),
                expected_claims.to_bytes().unwrap()
            )),
            Secret::Bytes("secret".to_string().into_bytes())
        ));
        let token = expected_jwt.serialize_flattened();
        let biscuit = not_err!(SignedData::verify_flattened(
            token.as_bytes(),
            Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        ));
        assert_eq!(
            &header,
            &not_err!(biscuit
                .data()
                .deserialize_protected_header::<CustomHeader>())
        );
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn flattened_jws_decode_token_invalid_signature_hs256() {
        let claims = SignedData::verify_flattened(
            "{\"protected\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\",\
             \"payload\":\"eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ\",\
             \"signature\":\"pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI\"}"
                .as_bytes(),
            Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn flattened_jws_decode_token_invalid_signature_rs256() {
        let public_key = Secret::public_key_from_file("test/fixtures/rsa_public_key.der").unwrap();
        let claims = SignedData::verify_flattened(
            "{\"protected\":\"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9\",\
             \"payload\":\"eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ\",\
             \"signature\":\"pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI\"}"
                .as_bytes(),
            public_key,
            SignatureAlgorithm::RS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "WrongAlgorithmHeader")]
    fn flattened_jws_decode_token_wrong_algorithm() {
        let claims = SignedData::verify_flattened(
            "{\"protected\":\"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9\",\
             \"payload\":\"eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ\",\
             \"signature\":\"pKscJVk7-aHxfmQKlaZxh5uhuKhGMAa-1F5IX5mfUwI\"}"
                .as_bytes(),
            Secret::Bytes("secret".to_string().into_bytes()),
            SignatureAlgorithm::HS256,
        );
        let _ = claims.unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid field")]
    fn flattened_jws_verify_reject_multiple_signatures() {
        let _ = SignedData::verify_flattened(
            br#"{"signatures": [], "protected": "", "payload": "", "signature: ""}"#,
            Secret::None,
            SignatureAlgorithm::None,
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid field")]
    fn flattened_jws_verify_reject_unprotected_headers() {
        let _ = SignedData::verify_flattened(
            br#"{"header": "", "protected": "", "payload": "", "signature: ""}"#,
            Secret::None,
            SignatureAlgorithm::None,
        )
        .unwrap();
    }
}
