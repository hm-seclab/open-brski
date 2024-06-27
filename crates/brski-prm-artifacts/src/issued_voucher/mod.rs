use axum::http::header::{self, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use josekit::jws::{self, JwsHeaderSet};

use crate::content_type;
use crate::error::BRSKIPRMError;
use crate::jws::{DecodedJWS, JWS};

use ietf_voucher::artifact::VoucherArtifact;
use ietf_voucher::pki::X509;

#[derive(Debug, Clone)]
pub struct IssuedVoucher {
    payload: VoucherArtifact,
    masa_sign_certs: Vec<X509>,
}

pub type IssuedVoucherJWS = JWS<VoucherArtifact>;

impl IssuedVoucherJWS {
    /// Adds a signature inflight, does *not* verify the existing signatures first
    pub fn add_inflight_signature(self, cert: impl IntoIterator<Item = impl Into<X509>>, keypair: impl AsRef<[u8]>)  -> Result<IssuedVoucherJWS, josekit::JoseError> {

        let certs: Vec<X509> = cert.into_iter().map(Into::into).collect();

        let mut header_set = JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&certs, true);
        header_set.set_algorithm(jws::ES256.to_string(), true);

        JWS::add_signature(self, keypair, header_set)
    }
}

impl IntoResponse for IssuedVoucherJWS {
    fn into_response(self) -> axum::response::Response {
        match self {
            JWS::Encoded(encoded) => axum::response::Response::builder()
                .header(CONTENT_TYPE, content_type::JWS_VOUCHER)
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

impl TryFrom<IssuedVoucher> for JWS<VoucherArtifact> {
    type Error = BRSKIPRMError;

    fn try_from(value: IssuedVoucher) -> Result<Self, Self::Error> {
        if value.payload.details.created_on.is_none() {
            return Err(BRSKIPRMError::Malformed(
                "Missing created_on field in issued v oucher".to_string(),
            ));
        }

        if value.payload.details.serial_number.is_empty() {
            return Err(BRSKIPRMError::Malformed(
                "Missing serial number in issued voucher".to_string(),
            ));
        }

        if value.payload.details.pinned_domain_cert.is_none() {
            return Err(BRSKIPRMError::Malformed(
                "Missing pinned_domain_cert field in issued voucher".to_string(),
            ));
        }

        if value.payload.details.nonce.is_none() && value.payload.details.expires_on.is_none() {
            return Err(BRSKIPRMError::Malformed("Voucher c an not be nonceless and without expires_on field at the same time in issued voucher".to_string()));
        }

        let mut header_set = JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.masa_sign_certs, true);
        header_set.set_algorithm(jws::ES256.to_string(), true);
        header_set.set_token_type("voucher-jws+json", false);

        let jws = JWS::Decoded(DecodedJWS {
            payload: value.payload,
            header_set: Some(header_set),
            header: None,
        });

        Ok(jws)
    }
}

impl IssuedVoucher {
    pub fn new(
        payload: VoucherArtifact,
        masa_sign_certs: impl IntoIterator<Item = impl Into<X509>>,
    ) -> Self {
        Self {
            payload,
            masa_sign_certs: masa_sign_certs.into_iter().map(Into::into).collect(),
        }
    }
}
