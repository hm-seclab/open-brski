use crate::content_type;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use ietf_voucher::artifact::VoucherArtifact;
use ietf_voucher::VoucherRequest;
use josekit::jws::JwsHeader;
use josekit::jws::JwsHeaderSet;
use josekit::jws::ES256;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use strum::Display;
use std::cell::OnceCell;
use strum::EnumIs;
use josekit::jws::{JwsContext, JwsVerifier};

#[derive(Debug, Clone)]
pub struct DecodedJWS<T: Serialize + DeserializeOwned + std::clone::Clone> {
    pub payload: T,
    pub(crate) header_set: Option<JwsHeaderSet>,
    pub header: Option<JwsHeader>,
}

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

#[derive(EnumIs, Debug, Clone, Display)]
pub enum JWS<T: Serialize + DeserializeOwned + std::clone::Clone> {
    Encoded(String),
    Decoded(DecodedJWS<T>),
}

impl<T: Serialize + DeserializeOwned + std::clone::Clone> JWS<T> {

    #[cfg(feature = "json")]
    pub fn encode_compact(self, keypair: impl AsRef<[u8]>) -> Result<JWS<T>, josekit::JoseError> {
        // Noop if already encoded
        if let JWS::Encoded(_) = self {
            return Ok(self);
        }

        let data = match self {
            JWS::Decoded(data) => data,
            JWS::Encoded(_) => unreachable!(),
        };

        let payload = data.payload;

        let signer = ES256.signer_from_der(keypair)?;

        // this is NOT base64 encoded! It is a compact JWS! We must encode it later!
        let serialized = serde_json::to_vec(&payload).map_err(|_| {
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not serialize payload"))
        })?;

        let header = JwsHeader::from_map(data.header_set.unwrap().to_map()).unwrap();

        let serialized_jws = josekit::jws::serialize_compact(&serialized,&header, &signer)?;

        Ok(JWS::Encoded(serialized_jws))
    }

    #[cfg(feature = "json")]
    pub fn encode(self, keypair: impl AsRef<[u8]>) -> Result<JWS<T>, josekit::JoseError> {
        // Noop if already encoded
        if let JWS::Encoded(_) = self {
            return Ok(self);
        }

        let data = match self {
            JWS::Decoded(data) => data,
            JWS::Encoded(_) => unreachable!(),
        };

        let payload = data.payload;

        let signer = ES256.signer_from_der(keypair)?;

        // this is NOT base64 encoded! It is a compact JWS! We must encode it later!
        let serialized = serde_json::to_vec(&payload).map_err(|_| {
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not serialize payload"))
        })?;

        let header_set = data.header_set.unwrap();

        let serialized_jws = josekit::jws::serialize_general_json(&serialized, &[(&header_set, &signer)])?;

        Ok(JWS::Encoded(serialized_jws))
    }

    #[cfg(feature = "json")]
    pub(crate) fn add_signature(self, keypair: impl AsRef<[u8]>, header_set: JwsHeaderSet)  -> Result<JWS<T>, josekit::JoseError> {

        let mut deserialized_jws: EncodedJWS = serde_json::from_str(&self.try_encoded_data()?).map_err(|_| josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not deserialize JWS")))?;
        
        let payload = deserialized_jws.payload.clone();

        let dummy_jws = JWS::Decoded(DecodedJWS {
            payload,
            header_set: Some(header_set),
            header: None
        });

        let encoded_jws = dummy_jws.encode(keypair)?;

        let deserialized_dummy: EncodedJWS = serde_json::from_str(&encoded_jws.try_encoded_data()?).map_err(|_| josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not deserialize JWS")))?;

        deserialized_jws.signatures.push(deserialized_dummy.signatures[0].clone());
        
        let encoded_jws = serde_json::to_string(&deserialized_jws).map_err(|_| josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not serialize JWS")))?;

        println!("Encoded JWS: {}", encoded_jws);

        Ok(JWS::Encoded(encoded_jws))
    }


    pub fn try_encoded_data(self) -> Result<String, josekit::JoseError> {
        match self {
            JWS::Encoded(data) => Ok(data),
            JWS::Decoded(_) => Err(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                "Expected encoded data"
            ))),
        }
    }

    pub fn try_decoded_data(self) -> Result<DecodedJWS<T>, josekit::JoseError> {
        match self {
            JWS::Decoded(data) => Ok(data),
            JWS::Encoded(_) => Err(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                "Expected decoded data"
            ))),
        }
    }

    #[cfg(feature = "json")]
    pub fn decode(self) -> Result<JWS<T>, josekit::JoseError> {
        if let JWS::Decoded(_) = self {
            return Ok(self);
        }

        let data = match self {
            JWS::Encoded(data) => data,
            JWS::Decoded(_) => unreachable!(),
        };

        let mut jws_context = JwsContext::new();
        jws_context.add_acceptable_critical("created-on");

        let cell: OnceCell<Box<dyn JwsVerifier>> = OnceCell::new();

        let (data, header) = jws_context
            .deserialize_json_with_selector(data, |header| {
                let public_keys = header.x509_certificate_chain().unwrap();
                let cert_chain_end =
                    openssl::x509::X509::from_der(&public_keys[0].clone()).unwrap();
                let pub_key = cert_chain_end
                    .public_key()
                    .unwrap()
                    .public_key_to_der()
                    .unwrap();
                let verifier = ES256.verifier_from_der(pub_key).unwrap();
                Ok(Some(cell.get_or_init(|| Box::new(verifier)).as_ref()))
            })?;

        let payload: T = serde_json::from_slice(&data).map_err(|_| {
            josekit::JoseError::InvalidJson(anyhow::anyhow!("Could not deserialize payload"))
        })?;

        let jws_options = DecodedJWS {
            payload,
            header_set: None,
            header: Some(header),
        };

        Ok(JWS::Decoded(jws_options))
    }

    #[cfg(feature = "json")]
    pub fn verify(&self) -> Result<(), josekit::JoseError> {

        if let JWS::Decoded(_) = self {
            return Err(josekit::JoseError::InvalidJwsFormat(anyhow::anyhow!(
                "Expected encoded data"
            )));
        } 

        let data = match self {
            JWS::Encoded(data) => data,
            JWS::Decoded(_) => unreachable!(),
        };

        let mut jws_context = JwsContext::new();
        jws_context.add_acceptable_critical("created-on");

        let cell: OnceCell<Box<dyn JwsVerifier>> = OnceCell::new();

        let (_data, _header) = jws_context
            .deserialize_json_with_selector(data, |header| {
                let public_keys = header.x509_certificate_chain().unwrap();
                let cert_chain_end =
                    openssl::x509::X509::from_der(&public_keys[0].clone()).unwrap();
                let pub_key = cert_chain_end
                    .public_key()
                    .unwrap()
                    .public_key_to_der()
                    .unwrap();
                let verifier = ES256.verifier_from_der(pub_key).unwrap();
                Ok(Some(cell.get_or_init(|| Box::new(verifier)).as_ref()))
            })?;

        Ok(())
    }

}

impl IntoResponse for JWS<VoucherRequest> {
    fn into_response(self) -> axum::response::Response {
        match self {
            JWS::Encoded(encoded) => axum::response::Response::builder()
                .header(CONTENT_TYPE, content_type::JWS_VOUCHER)
                .body(encoded.into())
                .unwrap(),
            JWS::Decoded(_decoded) => (
                StatusCode::INTERNAL_SERVER_ERROR,
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