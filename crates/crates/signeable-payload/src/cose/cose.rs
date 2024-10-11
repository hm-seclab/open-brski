// use crate::{
//     signeable::{BasicSigneable, Signeable},
//     signing_context::SigningContext,
//     verifying_context,
// };
use anyhow::anyhow;
use core::fmt;
use coset::{CborSerializable, CoseError};
use ring::signature::{EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm};
// use josekit::{jwk::Jwk, jws::*, JoseError};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{cell::OnceCell, fmt::Debug};
use strum::EnumIs;
use tracing::{debug, error, info, span};
use x509_cert::der::Decode;

use crate::{
    error::{CoseErrorWrapper, SigneableError},
    header::HeaderSet,
    signeable::{
        signer_verifyer::{SignerVerifyer, VerifyResult},
        signing_context::SigningContext,
        verifying_context::VerifyingContext,
    },
    signer_verifyer::{MultipleSignerVerifyer, SignatureAdder},
};

use super::alg::{match_algorithm, match_cose_algorithm_to_ring};

#[derive(Debug, Clone)]
pub struct CoseSignerVerifyer {}

impl Default for CoseSignerVerifyer {
    fn default() -> Self {
        CoseSignerVerifyer {}
    }
}

impl CoseSignerVerifyer {
    pub fn new() -> Self {
        CoseSignerVerifyer {}
    }
}

impl<T: Serialize + DeserializeOwned> SignerVerifyer<T> for CoseSignerVerifyer {
    fn sign(
        &self,
        payload: T,
        header: crate::header::HeaderSet,
        privkey: &[u8],
        ctx: crate::signeable::signing_context::BasicSigningContext,
    ) -> Result<Vec<u8>, crate::error::SigneableError> {
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf)
            .map_err(|_| CoseErrorWrapper(CoseError::EncodeFailed))?;

        let (unprotected, protected): (coset::Header, coset::Header) = header.into();

        let aad = b"";

        let rng = ring::rand::SystemRandom::new();
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(
            match_algorithm(ctx.get_algorithm()),
            privkey.as_ref(),
            &rng,
        )
        .map_err(|e| anyhow!("Failed to create key pair, reason: {}", e.to_string()))?;

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(buf)
            .create_signature(aad, |pts| {
                let signature = key.sign(&rng, pts).unwrap();

                signature.as_ref().to_vec()
            })
            .build();

        let sign1_data = sign1
            .to_vec()
            .map_err(|e| CoseErrorWrapper(CoseError::EncodeFailed))?;

        Ok(sign1_data)
    }

    fn verify(
        &self,
        signed_data: &[u8],
        ctx: Option<crate::signeable::verifying_context::BasicVeryingContext>,
    ) -> Result<crate::signeable::signer_verifyer::VerifyResult<T>, crate::error::SigneableError>
    {
        // let public_key = match ctx.unwrap_or_default().get_public_key() {
        //     Some(key) => key,
        //     None => {
        //         return Err(crate::error::SigneableError::VerifyingError(
        //             "Public key is required for verification".to_string(),
        //         ))
        //     }
        // };

        let aad = b"";

        let mut sign1 =
            coset::CoseSign1::from_slice(&signed_data).map_err(|e| CoseErrorWrapper(e))?;

        let mut algorithm: &EcdsaVerificationAlgorithm;

        if let Some(ref alg) = sign1.unprotected.alg {
            algorithm = match_cose_algorithm_to_ring(alg.clone());
        } else if let Some(ref alg) = sign1.protected.header.alg {
            algorithm = match_cose_algorithm_to_ring(alg.clone());
        } else {
            return Err(crate::error::SigneableError::VerifyingError(
                "Algorithm not found".to_string(),
            ));
        };

        let s = sign1.clone();

        let header_set: HeaderSet = (s.unprotected, s.protected.header).into();
        let x5c = header_set.x509_certificate_chain().unwrap();
        let chain_end = x5c.get(0).unwrap();
        let cert = x509_cert::Certificate::from_der(&chain_end).unwrap();
        let pubkey = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap();

        let result: Result<(), ring::error::Unspecified> =
            sign1.verify_signature(aad, |sig, pts| {
                let public_key_rn = ring::signature::UnparsedPublicKey::new(algorithm, pubkey);

                public_key_rn.verify(pts, sig)?;
                Ok(())
            });

        if let Err(e) = result {
            return Err(crate::error::SigneableError::VerifyingError(e.to_string()));
        }

        let payload = sign1.payload.unwrap();
        let data: T = ciborium::from_reader(&payload[..]).unwrap();

        Ok(VerifyResult {
            payload: data,
            headers: header_set,
        })
    }
}

impl SignatureAdder for CoseSignerVerifyer {
    fn add_signature(
        &self,
        signed_data: &[u8],
        header: crate::header::HeaderSet,
        privkey: &[u8],
        ctx: crate::BasicSigningContext,
    ) -> Result<Vec<u8>, crate::error::SigneableError> {
        Ok(signed_data.to_vec())
    }
    // fn add_signature(
    //     &self,
    //     signed_data: &[u8],
    //     signature: &[u8],
    // ) -> Result<Vec<u8>, crate::error::SigneableError> {
    //     let mut sign1 = coset::CoseSign1::from_slice(&signed_data).unwrap();

    //     sign1.signature = Some(signature.to_vec());

    //     let sign1_data = sign1.to_vec().unwrap();

    //     Ok(sign1_data)
    // }
}

impl<T: Serialize + DeserializeOwned> MultipleSignerVerifyer<T> for CoseSignerVerifyer {}

#[cfg(test)]
mod tests {
    use ring::signature::KeyPair;

    use super::*;

    #[test]
    fn test_basic_coset_functionality() {
        let rng = ring::rand::SystemRandom::new();

        let certs = example_certs::generate_certs();
        let (cert, key) = certs.pledge;

        let key = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            key.serialize_der().as_ref(),
            &rng,
        )
        .unwrap();

        let protected = coset::HeaderBuilder::new().build();

        let unprotected = coset::HeaderBuilder::new().build();

        let payload = "Hello, world!".to_string().bytes().collect::<Vec<u8>>();

        let aad = b"";

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .create_signature(aad, |pts| {
                let signature = key.sign(&rng, pts).unwrap();

                signature.as_ref().to_vec()
            })
            .build();

        let result: Result<(), ring::error::Unspecified> =
            sign1.verify_signature(aad, |sig, pts| {
                let public_key = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ECDSA_P256_SHA256_ASN1,
                    key.public_key().as_ref(),
                );

                public_key.verify(pts, sig).unwrap();
                Ok(())
            });

        assert!(result.is_ok());
    }

    #[test]
    fn it_signs_and_verifies() {
        let signer = CoseSignerVerifyer::new();
        let payload = "Hello, world!".to_string();
        let mut header = HeaderSet::new();

        let certs = example_certs::generate_certs();
        let (cert, key) = certs.pledge;

        header.set_algorithm("ES256", false);
        header.set_x509_certificate_chain(&vec![cert.der()], false);

        let privkey = key.serialize_der();
        let ctx = crate::signeable::signing_context::BasicSigningContext::new();

        let signed_data = signer.sign(payload, header, &privkey, ctx).unwrap();

        let result: String = signer.verify(&signed_data, None).unwrap().payload;

        assert_eq!(result, "Hello, world!");
    }
}
