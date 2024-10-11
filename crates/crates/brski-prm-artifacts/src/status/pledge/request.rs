use crate::{error::BRSKIPRMError, token_type::PlainTokenType};

use ietf_voucher::pki::X509;
use signeable_payload::{algorithm::Algorithm, header::HeaderSet, signeable::unsigned::Unsigned};

use super::status::PledgeStatusQuery;

pub struct PledgeStatusQueryRequest {
    status: PledgeStatusQuery,
    reg_agt_ee_certs: Vec<X509>,
    signature_type: PlainTokenType,
}

impl TryFrom<PledgeStatusQueryRequest> for Unsigned<PledgeStatusQuery> {
    type Error = BRSKIPRMError;

    fn try_from(value: PledgeStatusQueryRequest) -> Result<Self, Self::Error> {
        let mut header_set = HeaderSet::new();
        header_set.set_x509_certificate_chain(&value.reg_agt_ee_certs, true);
        header_set.set_algorithm(Algorithm::ES256.to_string(), true);
        header_set.set_token_type(value.signature_type.as_token_type(), false);
        header_set.set_content_type(value.signature_type.as_content_type(), false);

        Ok(Unsigned::new(value.status, header_set))
    }
}

impl PledgeStatusQueryRequest {
    pub fn new(
        status: PledgeStatusQuery,
        reg_agt_ee_certs: impl IntoIterator<Item = impl Into<X509>>,
        signature_type: PlainTokenType,
    ) -> Self {
        Self {
            status,
            reg_agt_ee_certs: reg_agt_ee_certs.into_iter().map(Into::into).collect(),
            signature_type,
        }
    }
}
