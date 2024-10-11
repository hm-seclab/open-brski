use crate::{
    error::BRSKIPRMError,
    token_type::{self, PlainTokenType},
};

use ietf_voucher::pki::X509;
use signeable_payload::signeable::unsigned::Unsigned;

use crate::status::enroll::status::PledgeEnrollStatus;

pub struct PledgeEnrollStatusResponse {
    status: PledgeEnrollStatus,
    sign_certs: Vec<X509>,
    signature_type: PlainTokenType,
}

impl TryFrom<PledgeEnrollStatusResponse> for Unsigned<PledgeEnrollStatus> {
    type Error = BRSKIPRMError;

    fn try_from(value: PledgeEnrollStatusResponse) -> Result<Self, Self::Error> {
        let mut header_set = signeable_payload::header::HeaderSet::new();
        header_set.set_x509_certificate_chain(&value.sign_certs, true);
        header_set.set_algorithm(
            signeable_payload::algorithm::Algorithm::ES256.to_string(),
            true,
        );
        header_set.set_token_type(value.signature_type.as_token_type(), false);
        header_set.set_content_type(value.signature_type.as_content_type(), false);

        let data = Unsigned::new(value.status, header_set);

        Ok(data)
    }
}

impl PledgeEnrollStatusResponse {
    pub fn new(
        status: PledgeEnrollStatus,
        sign_certs: impl IntoIterator<Item = impl Into<X509>>,
        signature_type: PlainTokenType,
    ) -> Self {
        Self {
            status,
            sign_certs: sign_certs.into_iter().map(Into::into).collect(),
            signature_type,
        }
    }
}
