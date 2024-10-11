use crate::{error::BRSKIPRMError, token_type::VoucherTokenType};

use ietf_voucher::{pki::X509, VoucherRequest};
use signeable_payload::signeable::unsigned::Unsigned;

#[derive(Debug, Clone)]
pub struct RegistrarVoucherRequestResponse {
    payload: VoucherRequest,
    registrar_ldevid_certs: Vec<X509>,
    signature_type: VoucherTokenType,
}

impl TryFrom<RegistrarVoucherRequestResponse> for Unsigned<VoucherRequest> {
    type Error = BRSKIPRMError;

    fn try_from(value: RegistrarVoucherRequestResponse) -> Result<Self, Self::Error> {
        if value.payload.details.created_on.is_none() {
            return Err(BRSKIPRMError::Malformed(
                "Missing created_on field in RVR".to_string(),
            ));
        }

        if value.payload.details.agent_sign_cert.is_none() {
            return Err(BRSKIPRMError::Malformed(
                "Missing agent_sign_cert field in RVR".to_string(),
            ));
        }

        if value.payload.details.serial_number.is_empty() {
            return Err(BRSKIPRMError::Malformed(
                "Missing serial number in RVR".to_string(),
            ));
        }

        if matches!(
            value.payload.details.assertion,
            Some(ietf_voucher::assertion::Assertion::AgentProximity)
        ) && value.payload.details.agent_sign_cert.is_none()
        {
            return Err(BRSKIPRMError::Malformed(
                "Missing agent_sign_cert field in RVR while assertion is agent-proximity"
                    .to_string(),
            ));
        }

        let mut header_set = signeable_payload::header::HeaderSet::new();
        header_set.set_x509_certificate_chain(&value.registrar_ldevid_certs, true);
        header_set.set_algorithm(
            signeable_payload::algorithm::Algorithm::ES256.to_string(),
            true,
        );
        header_set.set_token_type(value.signature_type.as_token_type(), false);
        header_set.set_content_type(value.signature_type.as_content_type(), false);

        Ok(Unsigned::new(value.payload, header_set))
    }
}

impl RegistrarVoucherRequestResponse {
    pub fn new(
        payload: VoucherRequest,
        registrar_ldevid_certs: impl IntoIterator<Item = impl Into<X509>>,
        signature_type: VoucherTokenType,
    ) -> Self {
        Self {
            payload,
            registrar_ldevid_certs: registrar_ldevid_certs.into_iter().map(Into::into).collect(),
            signature_type,
        }
    }
}
