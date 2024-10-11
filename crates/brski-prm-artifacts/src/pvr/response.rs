use crate::{error::BRSKIPRMError, token_type::VoucherTokenType};

use ietf_voucher::{pki::X509, VoucherRequest};
use signeable_payload::signeable::unsigned::Unsigned;

/// A PVR Response is a response to a PVR Request. It contains a VoucherRequest and a list of pledge idevid certs.
/// You can conver this Response to a Token using the TryFrom trait. You will need to encode this voucher yourself with a private key that matches the public key in the pledge idevid certificate
#[derive(Debug)]
pub struct PledgeVoucherRequestResponse {
    /// The VoucherRequest object. For conversion to a Token, you will need to fill the fields according to Section 7.1.1 of the BRSKI-PRM document
    voucher_request: VoucherRequest,

    /// The pledge idevid certificate. Optionally, you can include the certificate chain leading up to the trust anchor.
    pledge_idevid_certs: Vec<X509>,
    signature_type: VoucherTokenType,
}

impl TryFrom<PledgeVoucherRequestResponse> for Unsigned<VoucherRequest> {
    type Error = BRSKIPRMError;

    fn try_from(value: PledgeVoucherRequestResponse) -> Result<Self, Self::Error> {
        if value.voucher_request.details.created_on.is_none() {
            return Err(BRSKIPRMError::Malformed(
                "Missing created_on field in PVR Response".to_string(),
            ));
        }

        if value.voucher_request.details.agent_signed_data.is_none() {
            return Err(BRSKIPRMError::Malformed(
                "Missing agent_signed_data field in PVR Response".to_string(),
            ));
        }

        if value
            .voucher_request
            .details
            .agent_provided_proximity_registrar_cert
            .is_none()
        {
            return Err(BRSKIPRMError::Malformed(
                "Missing agent_provided_proximity_registrar_cert field in PVR Response".to_string(),
            ));
        }

        let mut header_set = signeable_payload::header::HeaderSet::new();
        header_set.set_x509_certificate_chain(&value.pledge_idevid_certs, true);
        header_set.set_algorithm(
            signeable_payload::algorithm::Algorithm::ES256.to_string(),
            true,
        );
        header_set.set_content_type(value.signature_type.as_content_type(), false);
        header_set.set_token_type(value.signature_type.as_token_type(), true);

        let data = Unsigned::new(value.voucher_request, header_set);

        Ok(data)
    }
}

impl PledgeVoucherRequestResponse {
    pub fn new(
        voucher_request: VoucherRequest,
        pledge_idevid_certs: impl IntoIterator<Item = impl Into<X509>>,
        signature_type: VoucherTokenType,
    ) -> Self {
        Self {
            voucher_request,
            pledge_idevid_certs: pledge_idevid_certs.into_iter().map(Into::into).collect(),
            signature_type,
        }
    }
}
