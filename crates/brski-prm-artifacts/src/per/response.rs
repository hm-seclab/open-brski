
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use ietf_voucher::pki::X509;

use crate::content_type;
use crate::jws::{DecodedJWS, JWS};
use crate::per::response_payload::ResponsePayload;
use josekit::jws::{self, JwsHeaderSet};

#[derive(Debug)]
pub struct Response {
    payload: ResponsePayload,
    pledge_idevid_certs: Vec<X509>,
}

pub type PER_JWS = JWS<ResponsePayload>;

impl IntoResponse for PER_JWS {
    fn into_response(self) -> axum::response::Response {
        match self {
            JWS::Encoded(encoded) => axum::response::Response::builder()
                .header(CONTENT_TYPE, content_type::JOSE)
                .body(encoded.into())
                .unwrap(),
            JWS::Decoded(decoded) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server attempted to send a JWS that was not encoded".to_string(),
            )
                .into_response(),
        }
    }
}

impl TryFrom<Response> for PER_JWS {
    type Error = josekit::JoseError;

    fn try_from(value: Response) -> Result<Self, Self::Error> {
        let mut header_set = JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.pledge_idevid_certs, true);
        header_set.set_algorithm(jws::ES256.to_string(), true);
        header_set.set_critical(&["created-on"].to_vec());
        header_set.set_claim(
            "created-on",
            Some(josekit::Value::String(chrono::Utc::now().to_string())),
            true,
        )?;

        let jws = JWS::Decoded(DecodedJWS {
            payload: value.payload,
            header_set: Some(header_set),
            header: None,
        });

        Ok(jws)
    }
}

impl Response {
    pub fn new(
        payload: ResponsePayload,
        pledge_idevid_certs: impl IntoIterator<Item = impl Into<X509>>,
    ) -> Self {
        Self {
            payload,
            pledge_idevid_certs: pledge_idevid_certs.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {

    use base64::{Engine};
    
    use serde_json::json;

    use crate::{
        per::{
            response::{Response, PER_JWS},
            response_payload::ResponsePayload,
        },
    };

    #[test]
    pub fn test_response_payload_creation() {
        let certs: example_certs::OpensslTestCerts = example_certs::generate_certs().into();

        let (pledge_cert, pledge_key) = certs.pledge;

        let response_payload = ResponsePayload::try_new(&pledge_key);

        assert!(response_payload.is_ok());

        let response_payload = response_payload.unwrap();

        assert!(response_payload
            .csr
            .p10_csr
            .public_key()
            .unwrap()
            .public_eq(&pledge_cert.public_key().unwrap()));
        assert!(&pledge_key.public_eq(&response_payload.csr.p10_csr.public_key().unwrap()));
    }

    #[test]
    pub fn test_response_payload_serialization() {
        let certs: example_certs::OpensslTestCerts = example_certs::generate_certs().into();

        let (pledge_cert, pledge_key) = certs.pledge;

        let csr = ResponsePayload::try_new(&pledge_key);

        assert!(csr.is_ok());

        let csr = csr.unwrap();

        let serialized = serde_json::to_string(&csr);
        assert!(serialized.is_ok());
    }

    #[test]
    pub fn test_response_payload() {
        let json = json!({
            "ietf-ztp-types":{ "p10-csr": "MIIBWzCCAQICAQAwgZ8xFDASBgNVBAMMC2NvbW1vbl9uYW1lMQswCQYDVQQGEwJERTEQMA4GA1UECAwHQmF2YXJpYTEPMA0GA1UEBwwGTXVuaWNoMS4wLAYDVQQKDCVVbml2ZXJzaXR5IG9mIEFwcGxpZWQgU2NpZW5jZXMgTXVuaWNoMScwJQYDVQQLDB5EZXBhcnRtZW50IG9mIENvbXB1dGVyIFNjaWVuY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQMJsyFnfXanjWCNimECrucESP0W7NVHhLHDqZntHhAY2f3ZVGMrXRsAzNt+kRoBXOg6PCGV3tsHrxyCaMs2Ja3oAAwCgYIKoZIzj0EAwIDRwAwRAIgTMtHRzt0zIzbjW5lBFGBlutvm7O+MGPuLWTNJR2ZIDcCICkQ9Ytnp8CuxyT58BhL/TrX44Z3elZiU9uWqWr1Fz7E"}
        });
        let deserialized = serde_json::from_value::<ResponsePayload>(json);

        assert!(deserialized.is_ok())
    }

    #[test]
    pub fn test_jws_implementation() {
        let certs: example_certs::OpensslTestCerts = example_certs::generate_certs().into();

        let (pledge_cert, pledge_key) = certs.pledge;

        let payload = ResponsePayload::try_new(&pledge_key).unwrap();

        let response = Response::new(payload, [pledge_cert.clone()]);

        let jws: PER_JWS = response.try_into().unwrap();

        let response = jws
            .encode(pledge_key.private_key_to_der().unwrap())
            .unwrap();

        assert!(response.is_encoded());

        let serialized_response = match response {
            super::JWS::Encoded(ref data) => data,
            _ => unreachable!(),
        };

        assert!(!serialized_response.is_empty());

        let decoded_response = response.decode().unwrap();

        assert!(decoded_response.is_decoded());

        let decoded_data = match decoded_response {
            super::JWS::Decoded(data) => data,
            _ => unreachable!(),
        };

        assert!(decoded_data
            .payload
            .csr
            .p10_csr
            .public_key()
            .unwrap()
            .public_eq(&pledge_cert.public_key().unwrap()));
    }
}
