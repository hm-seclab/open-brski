use ietf_voucher::pki::X509;

use crate::content_type;
use crate::jws::JWS;
use crate::cacerts::response_payload::ResponsePayload;

#[derive(Debug, Clone)]
pub struct Response {
    payload: ResponsePayload,
    registrar_ldevid_certs: Vec<X509>,
}

pub type CACERTS_JWS = JWS<ResponsePayload>;

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for CACERTS_JWS {
    fn into_response(self) -> axum::response::Response {
        match self {
            JWS::Encoded(encoded) => axum::response::Response::builder()
                .header(axum::http::header::CONTENT_TYPE, content_type::JOSE)
                .body(encoded.into())
                .unwrap(),
            JWS::Decoded(decoded) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Server attempted to send a JWS that was not encoded".to_string(),
            )
                .into_response(),
        }
    }
}

#[cfg(feature = "json")]
impl TryFrom<Response> for CACERTS_JWS {
    type Error = josekit::JoseError;

    fn try_from(value: Response) -> Result<Self, Self::Error> {
        let mut header_set = josekit::jws::JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.registrar_ldevid_certs, true);
        header_set.set_algorithm(josekit::jws::ES256.to_string(), true);
        header_set.set_critical(&["created-on"].to_vec());
        header_set.set_claim(
            "created-on",
            Some(josekit::Value::String(chrono::Utc::now().to_string())),
            true,
        )?;

        let jws = JWS::Decoded(crate::jws::DecodedJWS {
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
        registrar_ldevid_certs: impl IntoIterator<Item = impl Into<X509>>,
    ) -> Self {
        Self {
            payload,
            registrar_ldevid_certs: registrar_ldevid_certs.into_iter().map(Into::into).collect(),
        }
    }
}