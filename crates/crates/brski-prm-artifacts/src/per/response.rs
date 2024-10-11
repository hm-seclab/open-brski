use crate::{
    per::response_payload::PledgeEnrollRequest,
    token_type::{self, PlainTokenType},
};
use ietf_voucher::pki::X509;
use signeable_payload::signeable::unsigned::Unsigned;
#[derive(Debug, Clone)]
pub struct PledgeEnrollRequestResponse {
    payload: PledgeEnrollRequest,
    pledge_idevid_certs: Vec<X509>,
    signature_type: PlainTokenType,
}

impl TryFrom<PledgeEnrollRequestResponse> for Unsigned<PledgeEnrollRequest> {
    type Error = signeable_payload::error::SigneableError;

    fn try_from(value: PledgeEnrollRequestResponse) -> Result<Self, Self::Error> {
        let mut header_set = signeable_payload::header::HeaderSet::new();
        header_set.set_x509_certificate_chain(&value.pledge_idevid_certs, true);
        header_set.set_algorithm(
            signeable_payload::algorithm::Algorithm::ES256.to_string(),
            true,
        );
        header_set.set_critical(&["created-on"].to_vec());
        header_set.set_content_type(value.signature_type.as_content_type(), false);
        header_set.set_claim(
            "created-on",
            Some(chrono::Utc::now().to_string().into()),
            true,
        )?;

        let data = Unsigned::new(value.payload, header_set);

        Ok(data)
    }
}

impl PledgeEnrollRequestResponse {
    pub fn new(
        payload: PledgeEnrollRequest,
        pledge_idevid_certs: impl IntoIterator<Item = impl Into<X509>>,
        signature_type: PlainTokenType,
    ) -> Self {
        Self {
            payload,
            pledge_idevid_certs: pledge_idevid_certs.into_iter().map(Into::into).collect(),
            signature_type,
        }
    }
}
