use std::cell::OnceCell;

use anyhow::bail;
use josekit::{jws::*, JoseError};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    error::SigneableError,
    header::HeaderSet,
    signeable::{
        signer_verifyer::{SignatureAdder, SignerVerifyer, VerifyResult},
        signing_context::{BasicSigningContext, SigningContext},
        verifying_context::BasicVeryingContext,
    },
    signer_verifyer::MultipleSignerVerifyer,
};

use super::alg::match_algorithm;

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    General,
    Compact,
    Flattened,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Signature {
    protected: String,
    signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SignedJWS {
    payload: String,
    signatures: Vec<Signature>,
}

#[derive(Clone, Debug)]
pub struct JoseSignerVerifyer {
    mode: Mode,
}

impl Default for JoseSignerVerifyer {
    fn default() -> Self {
        JoseSignerVerifyer {
            mode: Mode::General,
        }
    }
}

impl JoseSignerVerifyer {
    pub fn new(mode: Mode) -> Self {
        JoseSignerVerifyer { mode }
    }

    fn get_jws_verifier(
        &self,
        der: impl AsRef<[u8]>,
        header: &JwsHeader,
    ) -> Result<Option<Box<dyn JwsVerifier>>, JoseError> {
        match header.algorithm() {
            Some("RS256") => Ok(Some(Box::new(RS256.verifier_from_der(der)?))),
            Some("RS384") => Ok(Some(Box::new(RS384.verifier_from_der(der)?))),
            Some("RS512") => Ok(Some(Box::new(RS512.verifier_from_der(der)?))),
            Some("ES256") => Ok(Some(Box::new(ES256.verifier_from_der(der)?))),
            Some("ES256K") => Ok(Some(Box::new(ES256K.verifier_from_der(der)?))),
            Some("ES384") => Ok(Some(Box::new(ES384.verifier_from_der(der)?))),
            Some("ES512") => Ok(Some(Box::new(ES512.verifier_from_der(der)?))),
            Some("EdDSA") => Ok(Some(Box::new(EdDSA.verifier_from_der(der)?))),
            _ => Ok(None),
        }
    }

    fn sign_general(
        &self,
        payload: impl AsRef<[u8]>,
        header: HeaderSet,
        key: impl AsRef<[u8]>,
        ctx: BasicSigningContext,
    ) -> Result<Vec<u8>, SigneableError> {
        let signer = match_algorithm(ctx.get_algorithm()).signer_from_der(key)?;

        let header_set: josekit::jws::JwsHeaderSet = header.into();

        let serialized_jws =
            josekit::jws::serialize_general_json(payload.as_ref(), &[(&header_set, &signer)])?;

        let serialized = serialized_jws.into_bytes();

        Ok(serialized)
    }

    fn verify_general(
        &self,
        data: impl AsRef<[u8]>,
        ctx: Option<BasicVeryingContext>,
    ) -> Result<(Vec<u8>, JwsHeader), SigneableError> {
        let mut jws_context = josekit::jws::JwsContext::new();

        jws_context.add_acceptable_critical("created-on");

        let cell: OnceCell<Box<dyn josekit::jws::JwsVerifier>> = OnceCell::new();

        // TODO insert logic if x5c header is not present
        let (data, header) = jws_context.deserialize_json_with_selector(data, |header| {
            let cert_chain_raw =
                header
                    .x509_certificate_chain()
                    .ok_or(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                        "Could not get x509 certificate chain"
                    )))?;
            let cert_chain_end = openssl::x509::X509::from_der(&cert_chain_raw[0].clone())
                .map_err(|_| {
                    josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                        "Could not parse x509 end of certificate chain"
                    ))
                })?;
            let pub_key = cert_chain_end
                .public_key()
                .map_err(|_| {
                    josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                        "Could not get public key from certificate"
                    ))
                })?
                .public_key_to_der()
                .map_err(|_| {
                    josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                        "Could not serialize public key to DER"
                    ))
                })?;

            let verifier = self.get_jws_verifier(&pub_key, header)?.ok_or(
                josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not get verifier")),
            )?;

            Ok(Some(cell.get_or_init(|| verifier).as_ref()))
        })?;

        Ok((data, header))
    }
}

impl<T: Serialize + DeserializeOwned> SignerVerifyer<T> for JoseSignerVerifyer {
    fn sign(
        &self,
        payload: T,
        header: crate::header::HeaderSet,
        privkey: &[u8],
        ctx: crate::signeable::signing_context::BasicSigningContext,
    ) -> Result<Vec<u8>, crate::error::SigneableError> {
        let serialized = serde_json::to_string(&payload).map_err(|_| {
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not serialize JWS"))
        })?;

        match self.mode {
            Mode::General => self.sign_general(serialized, header, privkey, ctx),
            _ => todo!(),
        }
    }

    fn verify(
        &self,
        signed_data: &[u8],
        ctx: Option<BasicVeryingContext>,
    ) -> Result<VerifyResult<T>, crate::error::SigneableError> {
        let (verified, header) = match self.mode {
            Mode::General => self.verify_general(signed_data, ctx),
            _ => todo!(),
        }?;

        let deserialized: T = serde_json::from_slice(verified.as_slice()).map_err(|_| {
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not deserialize JWS"))
        })?;
        Ok(VerifyResult {
            payload: deserialized,
            headers: header.into(),
        })
    }
}

impl SignatureAdder for JoseSignerVerifyer {
    fn add_signature(
        &self,
        signed_data: &[u8],
        header: HeaderSet,
        privkey: &[u8],
        ctx: BasicSigningContext,
    ) -> Result<Vec<u8>, SigneableError> {
        if !matches!(self.mode, Mode::General) {
            return Err(JoseError::InvalidJwsFormat(anyhow::anyhow!(
                "Only General mode is supported for adding signatures"
            ))
            .into());
        }

        let mut deserialized_jws: SignedJWS =
            serde_json::from_slice(signed_data).map_err(|_| {
                josekit::JoseError::InvalidJson(anyhow::anyhow!(
                    "Could not deserialize JWS from General Syntax"
                ))
            })?;

        let payload = deserialized_jws.payload.clone();

        let dummy = self.sign_general(payload, header, privkey, ctx)?;

        let deserialized_dummy: SignedJWS =
            serde_json::from_slice(dummy.as_slice()).map_err(|_| {
                josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not deserialize JWS"))
            })?;

        deserialized_jws
            .signatures
            .push(deserialized_dummy.signatures[0].clone());

        let serialized_dummy = serde_json::to_string(&deserialized_jws).map_err(|_| {
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not serialize JWS"))
        })?;

        Ok(serialized_dummy.into_bytes())
    }
}

impl<T: Serialize + DeserializeOwned> MultipleSignerVerifyer<T> for JoseSignerVerifyer {}
