
use crate::error::BRSKIPRMError;
use crate::jws::JWS;

use ietf_voucher::pki::X509;
use ietf_voucher::VoucherRequest;

#[derive(Debug, Clone)]
pub struct RVR {
    payload: VoucherRequest,
    registrar_ldevid_certs: Vec<X509>,
}

pub type RVR_JWS = JWS<VoucherRequest>;

#[cfg(feature = "json")]
impl TryFrom<RVR> for JWS<VoucherRequest> {
    type Error = BRSKIPRMError;

    fn try_from(value: RVR) -> Result<Self, Self::Error> {
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

        let mut header_set = josekit::jws::JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.registrar_ldevid_certs, true);
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

impl RVR {
    pub fn new(
        payload: VoucherRequest,
        registrar_ldevid_certs: impl IntoIterator<Item = impl Into<X509>>,
    ) -> Self {
        Self {
            payload,
            registrar_ldevid_certs: registrar_ldevid_certs.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {

    use ietf_voucher::{assertion::Assertion, request_artifact::VoucherRequestArtifact};

    use super::*;

    #[test]
    pub fn test_encode_decode_roundtrip() {

        let certs: example_certs::OpensslTestCerts = example_certs::generate_certs().into();

        let (registrar_cert, registrar_key) = certs.registrar;
        let (reg_agt_cert, _) = certs.registrar_agent;

        let mut rvr_vra = VoucherRequestArtifact::default();

        rvr_vra.details.created_on = Some(chrono::Utc::now());
        rvr_vra.details.nonce = Some(b"nonce".to_vec());
        rvr_vra.details.assertion = Some(Assertion::AgentProximity);
        rvr_vra.details.prior_signed_voucher_request = None;
        rvr_vra.details.serial_number = "serial_number".to_string();
        rvr_vra.details.agent_sign_cert = Some(vec![(reg_agt_cert.clone().into())]);

        let rvr = RVR::new(rvr_vra, [registrar_cert.clone()]);

        println!("Generated RVR: {:#?}", rvr);

        let jws: RVR_JWS = rvr.try_into().unwrap();

        let encoded = jws
            .encode(registrar_key.private_key_to_der().unwrap()).unwrap();
        
        let payload: VoucherRequest = encoded.decode().unwrap().try_decoded_data().unwrap().payload;

    }
}