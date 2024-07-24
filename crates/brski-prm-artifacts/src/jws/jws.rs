use crate::content_type;
use anyhow::Context;
use ietf_voucher::VoucherRequest;
#[cfg(feature = "json")]
use josekit::{jwk::Jwk, jws::*, JoseError};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use strum::Display;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::span;
use core::fmt;
use std::cell::OnceCell;
use std::fmt::Debug;
use strum::EnumIs;
use super::decoded_jws::DecodedJWS;


#[derive(Serialize, Deserialize, Clone, Debug)]
struct Signature {
    protected: String,
    signature: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct EncodedJWS {
    payload: String,
    signatures: Vec<Signature>
}

#[derive(EnumIs, Debug, Clone)]
pub enum JWS<T: Serialize + DeserializeOwned + std::clone::Clone> {
    Encoded(String),
    Decoded(DecodedJWS<T>),
}

impl<T: Serialize + DeserializeOwned + std::clone::Clone + fmt::Debug> std::fmt::Display for JWS<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JWS::Encoded(data) => write!(f, "{}", data),
            JWS::Decoded(data) => write!(f, "{:?}", data),
        }
    }

}

#[cfg(feature = "json")]
impl<T: Serialize + DeserializeOwned + std::clone::Clone + Debug> JWS<T> {

    #[tracing::instrument(skip(self, keypair))]
    pub fn encode_compact(self, keypair: impl AsRef<[u8]>) -> Result<JWS<T>, josekit::JoseError> {
        // Noop if already encoded
        if let JWS::Encoded(_) = self {
            info!("JWS is already encoded");
            return Ok(self);
        }

        let data = match self {
            JWS::Decoded(data) => data,
            JWS::Encoded(_) => unreachable!(),
        };

        let payload = data.payload;

        info!("Gathering EcdsaSigner from keypair");
        let signer = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256.signer_from_der(keypair)?;

        // this is NOT base64 encoded! It is a compact JWS! We must encode it later!
        info!("Serializing payload into bytes");
        let serialized = serde_json::to_vec(&payload).map_err(|_| {
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not serialize payload"))
        })?;

        info!("Creating JWS Header from header_set");
        let header = josekit::jws::JwsHeader::from_map(data.header_set.unwrap().to_map())?;

        info!("Serializing JWS into compact format");
        let serialized_jws = josekit::jws::serialize_compact(&serialized,&header, &signer)?;

        Ok(JWS::Encoded(serialized_jws))
    }

    #[tracing::instrument(skip(self, keypair))]
    pub fn encode(self, keypair: impl AsRef<[u8]>) -> Result<JWS<T>, josekit::JoseError> {
        // Noop if already encoded
        if let JWS::Encoded(_) = self {
            info!("JWS is already encoded");
            return Ok(self);
        }

        let data = match self {
            JWS::Decoded(data) => data,
            JWS::Encoded(_) => unreachable!(),
        };

        let payload = data.payload;

        info!("Gathering EcdsaSigner from keypair");
        let signer = josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256.signer_from_der(keypair)?;

        // this is NOT base64 encoded! It is a compact JWS! We must encode it later!
        info!("Serializing payload into bytes");
        let serialized = serde_json::to_vec(&payload).map_err(|_| {
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not serialize payload"))
        })?;

        let header_set = data.header_set.unwrap();

        info!("Serializing JWS into general JSON format");
        let serialized_jws = josekit::jws::serialize_general_json(&serialized, &[(&header_set, &signer)])?;

        Ok(JWS::Encoded(serialized_jws))
    }

    #[tracing::instrument(skip(self, keypair, header_set))]
    pub(crate) fn add_signature(self, keypair: impl AsRef<[u8]>, header_set: josekit::jws::JwsHeaderSet)  -> Result<JWS<T>, josekit::JoseError> {

        info!("Deserializing JWS");
        let mut deserialized_jws: EncodedJWS = serde_json::from_str(&self.try_encoded_data()?).map_err(|_| josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not deserialize JWS")))?;
        

        let payload = deserialized_jws.payload.clone();

        info!("Generating dummy jws");
        let dummy_jws = JWS::Decoded(DecodedJWS {
            payload,
            header_set: Some(header_set),
            header: None
        });

        info!("Encoding dummy jws");
        let encoded_jws = dummy_jws.encode(keypair)?;

        info!("Deserializing dummy jws");
        let deserialized_dummy: EncodedJWS = serde_json::from_str(&encoded_jws.try_encoded_data()?).map_err(|_| josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not deserialize JWS")))?;

        info!("Adding signature from dummy to original JWS");
        deserialized_jws.signatures.push(deserialized_dummy.signatures[0].clone());
        
        info!("Serializing JWS");
        let encoded_jws = serde_json::to_string(&deserialized_jws).map_err(|_| josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not serialize JWS")))?;

        debug!("Encoded JWS: {}", encoded_jws);

        Ok(JWS::Encoded(encoded_jws))
    }


    #[tracing::instrument(skip(self))]
    pub fn try_encoded_data(self) -> Result<String, josekit::JoseError> {
        match self {
            JWS::Encoded(data) => Ok(data),
            JWS::Decoded(_) => Err(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                "Expected encoded data"
            ))),
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn try_decoded_data(self) -> Result<DecodedJWS<T>, josekit::JoseError> {
        match self {
            JWS::Decoded(data) => Ok(data),
            JWS::Encoded(_) => Err(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                "Expected decoded data"
            ))),
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn decode(self) -> Result<JWS<T>, josekit::JoseError> {
        if let JWS::Decoded(_) = self {
            return Ok(self);
        }

        let data = match self {
            JWS::Encoded(data) => data,
            JWS::Decoded(_) => unreachable!(),
        };

        debug!("Extracted data from JWS: {}", data);

        let mut jws_context = josekit::jws::JwsContext::new();
        info!("Adding 'created-on' to acceptable critical headers");
        jws_context.add_acceptable_critical("created-on");

        let cell: OnceCell<Box<dyn josekit::jws::JwsVerifier>> = OnceCell::new();

        info!("Trying to deserialize JWS");
        let (data, header) = jws_context
            .deserialize_json_with_selector(data, |header| {
                let span = span!(tracing::Level::DEBUG, "Deserializing JWS with Selector").entered();
                let public_keys = header.x509_certificate_chain().ok_or(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not get x509 certificate chain")))?;
                let cert_chain_end =
                    openssl::x509::X509::from_der(&public_keys[0].clone()).map_err(|_| josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not parse x509 end of certificate chain")))?;
                debug!("Certificate chain end: {:?}", cert_chain_end);
                let pub_key = cert_chain_end
                    .public_key()
                    .map_err(|_| josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not get public key from certificate")))?
                    .public_key_to_der()
                    .map_err(|_| josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not serialize public key to DER")))?;
                debug!("Public key: {:?}", pub_key);
                let verifier = get_jws_verifier(&pub_key, header)?.ok_or(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not get verifier")))?;
                span.exit();
                Ok(Some(cell.get_or_init(|| verifier).as_ref()))
            })?;

        info!("Deserializing payload");

        let payload: T = serde_json::from_slice(&data).map_err(|err| {
            
            error!("Could not deserialize payload: {:?} with err: {}", data, err);
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not deserialize payload"))
        })?;

        let jws_options = DecodedJWS {
            payload,
            header_set: None,
            header: Some(header),
        };

        Ok(JWS::Decoded(jws_options))
    }

    #[tracing::instrument(skip(self))]
    pub fn verify(&self) -> Result<(), josekit::JoseError> {

        if let JWS::Decoded(_) = self {
            error!("JWS is in invalid decoded state. Can't verify.");
            return Err(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                "Expected encoded data"
            )));
        } 

        let data = match self {
            JWS::Encoded(data) => data,
            JWS::Decoded(_) => unreachable!(),
        };


        let mut jws_context = josekit::jws::JwsContext::new();
        info!("Adding 'created-on' to acceptable critical headers");
        jws_context.add_acceptable_critical("created-on");

        let cell: OnceCell<Box<dyn josekit::jws::JwsVerifier>> = OnceCell::new();

        info!("Trying to deserialize JWS");
        let (_data, _header) = jws_context
            .deserialize_json_with_selector(data, |header| {

                let span = span!(tracing::Level::DEBUG, "Deserializing JWS with Selector").entered();
                let public_keys = header.x509_certificate_chain().ok_or(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not get x509 certificate chain")))?;
                let cert_chain_end =
                    openssl::x509::X509::from_der(&public_keys[0].clone()).map_err(|_| josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not parse x509 end of certificate chain")))?;
                debug!("Certificate chain end: {:?}", cert_chain_end);
                let pub_key = cert_chain_end
                    .public_key()
                    .map_err(|_| josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not get public key from certificate")))?
                    .public_key_to_der()
                    .map_err(|_| josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not serialize public key to DER")))?;
                debug!("Public key: {:?}", pub_key);
                let verifier = get_jws_verifier(&pub_key, header)?.ok_or(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!("Could not get verifier")))?;
                span.exit();
                Ok(Some(cell.get_or_init(|| verifier).as_ref()))
            })?;

        Ok(())
    }

}

#[cfg(feature = "json")]
fn get_jws_verifier(der: impl AsRef<[u8]>, header: &JwsHeader) -> Result<Option<Box<dyn JwsVerifier>>, JoseError> {
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

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for JWS<VoucherRequest> {
    fn into_response(self) -> axum::response::Response {
        match self {
            JWS::Encoded(encoded) => axum::response::Response::builder()
                .header(axum::http::header::CONTENT_TYPE, content_type::JWS_VOUCHER)
                .body(encoded.into())
                .unwrap(),
            JWS::Decoded(_decoded) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Server attempted to send a JWS that was not encoded".to_string(),
            )
                .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    pub fn test_add_inflight_signature() {
        let certs: example_certs::OpensslTestCerts = example_certs::generate_certs().into();

        let (vendor_cert, vendor_key) = certs.vendor;
        let (registrar_cert, registrar_key) = certs.registrar;

        let payload = "Hello, World!";

        let mut header_one = josekit::jws::JwsHeaderSet::new();
        header_one.set_x509_certificate_chain(&vec![vendor_cert.to_der().unwrap()], true);
        header_one.set_algorithm(josekit::jws::ES256.to_string(), true);

        let jws = JWS::Decoded(DecodedJWS {
            payload: payload.to_string(),
            header_set: Some(header_one),
            header: None
        });

        let jws = jws.encode(vendor_key.private_key_to_der().unwrap()).unwrap();

        let mut header_two = josekit::jws::JwsHeaderSet::new();
        header_two.set_x509_certificate_chain(&vec![registrar_cert.to_der().unwrap()], true);
        header_two.set_algorithm(josekit::jws::ES256.to_string(), true);        

        let jws = jws.add_signature(registrar_key.private_key_to_der().unwrap(), header_two).unwrap();

        let decoded_jws = jws.decode().unwrap();

        assert_eq!(decoded_jws.try_decoded_data().unwrap().payload, payload.to_string());
    }
}