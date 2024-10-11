use crate::{
    error::BRSKIPRMError,
    token_type::{self, PlainTokenType},
};

use ietf_voucher::pki::X509;
use signeable_payload::{algorithm::Algorithm, header::HeaderSet, signeable::unsigned::Unsigned};

use super::status::VoucherStatus;

pub struct VoucherStatusResponse {
    status: VoucherStatus,
    pledge_idevid_certs: Vec<X509>,
    signature_type: PlainTokenType,
}

impl TryFrom<VoucherStatusResponse> for Unsigned<VoucherStatus> {
    type Error = BRSKIPRMError;

    fn try_from(value: VoucherStatusResponse) -> Result<Self, Self::Error> {
        let mut header_set = HeaderSet::new();
        header_set.set_x509_certificate_chain(&value.pledge_idevid_certs, true);
        header_set.set_algorithm(Algorithm::ES256.to_string(), true);
        header_set.set_token_type(value.signature_type.as_token_type(), false);
        header_set.set_content_type(value.signature_type.as_content_type(), false);

        let data = Unsigned::new(value.status, header_set);
        Ok(data)
    }
}

impl VoucherStatusResponse {
    pub fn new(
        status: VoucherStatus,
        pledge_idevid_certs: impl IntoIterator<Item = impl Into<X509>>,
        signature_type: PlainTokenType,
    ) -> Self {
        Self {
            status,
            pledge_idevid_certs: pledge_idevid_certs.into_iter().map(Into::into).collect(),
            signature_type,
        }
    }
}
