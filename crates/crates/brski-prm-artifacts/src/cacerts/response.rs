use crate::{
    cacerts::response_payload::CaCerts,
    token_type::{self, PlainTokenType, JOSE, PKCS7},
};
use ietf_voucher::pki::X509;
use signeable_payload::signeable::unsigned::Unsigned;
use std::borrow::ToOwned;

#[derive(Debug, Clone)]
pub struct CaCertsResponse {
    payload: CaCerts,
    registrar_ldevid_certs: Vec<X509>,
    signature_type: PlainTokenType,
}

impl TryFrom<CaCertsResponse> for Unsigned<CaCerts> {
    type Error = signeable_payload::error::SigneableError;

    fn try_from(value: CaCertsResponse) -> Result<Self, Self::Error> {
        let mut header_set = signeable_payload::header::HeaderSet::new();
        header_set.set_x509_certificate_chain(&value.registrar_ldevid_certs, true);
        header_set.set_algorithm(
            signeable_payload::algorithm::Algorithm::ES256.to_string(),
            true,
        );
        header_set.set_critical(&vec!["created-on"]);
        header_set.set_content_type(value.signature_type.as_content_type(), false);
        header_set.set_claim(
            "created-on",
            Some(chrono::Utc::now().to_string().into()),
            true,
        )?;

        Ok(Unsigned::new(value.payload, header_set))
    }
}

impl CaCertsResponse {
    pub fn new(
        payload: CaCerts,
        registrar_ldevid_certs: impl IntoIterator<Item = impl Into<X509>>,
        signature_type: PlainTokenType,
    ) -> Self {
        Self {
            payload,
            registrar_ldevid_certs: registrar_ldevid_certs.into_iter().map(Into::into).collect(),
            signature_type,
        }
    }
}
