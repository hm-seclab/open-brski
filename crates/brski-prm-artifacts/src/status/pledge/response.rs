use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use josekit::jws::{self, JwsHeaderSet};

use crate::content_type;
use crate::error::BRSKIPRMError;
use crate::jws::{DecodedJWS, JWS};

use ietf_voucher::pki::X509;

use super::status::{PledgeStatus};

pub struct Response {
    status: PledgeStatus,
    reg_agt_ee_certs: Vec<X509>,
}

pub type PledgeStatusJWS = JWS<PledgeStatus>;

impl IntoResponse for PledgeStatusJWS {
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

impl TryFrom<Response> for JWS<PledgeStatus> {
    type Error = BRSKIPRMError;

    fn try_from(value: Response) -> Result<Self, Self::Error> {
        let mut header_set = JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.reg_agt_ee_certs, true);
        header_set.set_algorithm(jws::ES256.to_string(), true);
        header_set.set_token_type("voucher-jws+json", false);

        let jws = JWS::Decoded(DecodedJWS {
            payload: value.status,
            header_set: Some(header_set),
            header: None,
        });

        Ok(jws)
    }
}

impl Response {
    pub fn new(
        status: PledgeStatus,
        reg_agt_ee_certs: impl IntoIterator<Item = impl Into<X509>>,
    ) -> Self {
        Self {
            status,
            reg_agt_ee_certs: reg_agt_ee_certs.into_iter().map(Into::into).collect(),
        }
    }
}
