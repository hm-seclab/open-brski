use crate::content_type;
use crate::error::BRSKIPRMError;
use crate::jws::JWS;

use ietf_voucher::pki::X509;

use super::status::Status;

pub struct Response {
    status: Status,
    pledge_idevid_certs: Vec<X509>,
}

pub type vStatus_JWS = JWS<Status>;

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for vStatus_JWS {
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
impl TryFrom<Response> for JWS<Status> {
    type Error = BRSKIPRMError;

    fn try_from(value: Response) -> Result<Self, Self::Error> {
        let mut header_set = josekit::jws::JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.pledge_idevid_certs, true);
        header_set.set_algorithm(josekit::jws::ES256.to_string(), true);
        header_set.set_token_type("voucher-jws+json", false);

        let jws = JWS::Decoded(crate::jws::DecodedJWS {
            payload: value.status,
            header_set: Some(header_set),
            header: None,
        });

        Ok(jws)
    }
}

impl Response {
    pub fn new(
        status: Status,
        pledge_idevid_certs: impl IntoIterator<Item = impl Into<X509>>,
    ) -> Self {
        Self {
            status,
            pledge_idevid_certs: pledge_idevid_certs.into_iter().map(Into::into).collect(),
        }
    }
}
