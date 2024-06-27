use josekit::jws::{self, JwsHeaderSet};

use crate::error::BRSKIPRMError;
use crate::jws::{DecodedJWS, JWS};

use ietf_voucher::pki::X509;
use ietf_voucher::VoucherRequest;

/// A PVR Response is a response to a PVR Request. It contains a VoucherRequest and a list of pledge idevid certs.
/// You can conver this Response to a JWS Token using the TryFrom trait. You will need to encode this voucher yourself with a private key that matches the public key in the pledge idevid certificate
#[derive(Debug)]
pub struct Response {
    /// The VoucherRequest object. For conversion to a JWS, you will need to fill the fields according to Section 7.1.1 of the BRSKI-PRM document
    voucher_request: VoucherRequest,

    /// The pledge idevid certificate. Optionally, you can include the certificate chain leading up to the trust anchor.
    pledge_idevid_certs: Vec<X509>,
}

pub type PVR_JWS = JWS<VoucherRequest>;

impl TryFrom<Response> for PVR_JWS {
    type Error = BRSKIPRMError;

    fn try_from(value: Response) -> Result<Self, Self::Error> {
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

        let mut header_set = JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.pledge_idevid_certs, true);
        header_set.set_algorithm(jws::ES256.to_string(), true);
        header_set.set_token_type("voucher-jws+json", true);

        let jws = JWS::Decoded(DecodedJWS {
            payload: value.voucher_request,
            header_set: Some(header_set),
            header: None,
        });

        Ok(jws)
    }
}

impl Response {
    pub fn new(
        voucher_request: VoucherRequest,
        pledge_idevid_certs: impl IntoIterator<Item = impl Into<X509>>,
    ) -> Self {
        Self {
            voucher_request,
            pledge_idevid_certs: pledge_idevid_certs.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ietf_voucher::{agent_signed_data::AgentSignedData, assertion::Assertion, request_artifact::VoucherRequestArtifactDetails, VoucherRequest};

    use crate::jws::JWS;

    use super::Response; 

    #[test]
    fn test_encode_decode_response() {
        let certs: example_certs::OpensslTestCerts = example_certs::generate_certs().into();

        let c = example_certs::generate_certs();

        let created_on = chrono::DateTime::parse_from_rfc3339("2022-04-26T05:16:17.709Z")
            .unwrap()
            .to_utc();
        let serial_number = "0123456789".to_string();

        let agent_signed_data = AgentSignedData::new(created_on, serial_number);

        let keypair = certs.registrar_agent.1.private_key_to_der().unwrap();

        let encoded_data = agent_signed_data.encode("test-skid", keypair).unwrap();

        let mut details: VoucherRequestArtifactDetails = Default::default();
        details.created_on = Some(created_on);
        details.agent_signed_data = Some(encoded_data);
        details.agent_provided_proximity_registrar_cert = Some(certs.registrar.0.into());
        details.assertion = Some(Assertion::AgentProximity);
        details.nonce = Some(b"123456789".to_vec());

        let payload = VoucherRequest { details };

        let pvr_response: Response = Response::new(payload, vec![certs.pledge.0.clone()]);

        let jws: JWS<VoucherRequest> = pvr_response.try_into().unwrap();

        let encoded_pvr_response_jws = jws
            .encode(certs.pledge.1.private_key_to_der().unwrap())
            .unwrap();

        let _json = match encoded_pvr_response_jws {
            JWS::Encoded(json) => json,
            _ => unreachable!(),
        };
    }
}
