use crate::{
    error::BRSKIPRMError,
    token_type::{self, VoucherTokenType},
};

use ietf_voucher::{artifact::VoucherArtifact, pki::X509};
use signeable_payload::{
    algorithm::Algorithm,
    signeable::{signed::Signed, unsigned::Unsigned},
};
use tracing::info;

#[derive(Debug, Clone)]
pub struct IssuedVoucher {
    payload: VoucherArtifact,
    masa_sign_certs: Vec<X509>,
    signature_type: VoucherTokenType,
}

impl TryFrom<IssuedVoucher> for Unsigned<VoucherArtifact> {
    type Error = BRSKIPRMError;

    fn try_from(value: IssuedVoucher) -> Result<Self, Self::Error> {
        if value.payload.details.created_on.is_none() {
            return Err(BRSKIPRMError::Malformed(
                "Missing created_on field in issued voucher".to_string(),
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

        let mut header_set = signeable_payload::header::HeaderSet::new();
        header_set.set_x509_certificate_chain(&value.masa_sign_certs, true);
        header_set.set_algorithm(Algorithm::ES256.to_string(), true);
        header_set.set_token_type(value.signature_type.as_token_type(), false);
        header_set.set_content_type(value.signature_type.as_content_type(), false);

        Ok(Unsigned::new(value.payload, header_set))
    }
}

impl IssuedVoucher {
    pub fn try_new(
        payload: VoucherArtifact,
        masa_sign_certs: impl IntoIterator<Item = impl TryInto<X509>>,
        signature_type: VoucherTokenType,
    ) -> Result<Self, BRSKIPRMError> {
        let result = masa_sign_certs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<X509>, _>>()
            .map_err(|_| {
                BRSKIPRMError::Malformed("Failed to convert masa_sign_certs".to_string())
            })?;

        Ok(Self {
            payload,
            masa_sign_certs: result,
            signature_type,
        })
    }
}
