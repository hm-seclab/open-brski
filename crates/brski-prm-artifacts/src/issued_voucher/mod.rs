use crate::content_type;
use crate::error::BRSKIPRMError;
use crate::jws::JWS;


use ietf_voucher::artifact::VoucherArtifact;
use ietf_voucher::pki::X509;
use tracing::info;

#[derive(Debug, Clone)]
pub struct IssuedVoucher {
    payload: VoucherArtifact,
    masa_sign_certs: Vec<X509>,
}

pub type IssuedVoucherJWS = JWS<VoucherArtifact>;

#[cfg(feature = "json")]
impl IssuedVoucherJWS {
    /// Adds a signature inflight, does *not* verify the existing signatures first
    #[tracing::instrument(skip(self, cert, keypair))]
    pub fn add_inflight_signature(self, cert: impl IntoIterator<Item = impl Into<X509>>, keypair: impl AsRef<[u8]>)  -> Result<IssuedVoucherJWS, josekit::JoseError> {

        info!("Adding inflight signature to voucher");
        let certs: Vec<X509> = cert.into_iter().map(Into::into).collect();

        let mut header_set = josekit::jws::JwsHeaderSet::new();
        info!("Setting x509 certificate chain");
        header_set.set_x509_certificate_chain(&certs, true);
        info!("Setting algorithm");
        header_set.set_algorithm(josekit::jws::ES256.to_string(), true);

        JWS::add_signature(self, keypair, header_set)
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for IssuedVoucherJWS {
    fn into_response(self) -> axum::response::Response {
        match self {
            JWS::Encoded(encoded) => axum::response::Response::builder()
                .header(axum::http::header::CONTENT_TYPE, content_type::JWS_VOUCHER)
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

        let mut header_set = josekit::jws::JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.masa_sign_certs, true);
        header_set.set_algorithm(josekit::jws::ES256.to_string(), true);
        header_set.set_token_type("voucher-jws+json", false);

        let jws = JWS::Decoded(crate::jws::DecodedJWS {
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
