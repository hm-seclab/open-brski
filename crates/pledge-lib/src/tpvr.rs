use brski_prm_artifacts::ietf_voucher::VoucherRequest;

pub fn create_pvr(trigger: brski_prm_artifacts::pvr::trigger::Trigger, serial_number: String, ) -> VoucherRequest {

    #[cfg(feature = "clock")]
    let created_on = Some(chrono::Utc::now());
    #[cfg(not(feature = "clock"))]
    let created_on = None;


    let nonce = rand::random::<u32>();


    let requested_assertion =
        brski_prm_artifacts::ietf_voucher::assertion::Assertion::AgentProximity;

    let mut voucher_request_details =
        brski_prm_artifacts::ietf_voucher::request_artifact::VoucherRequestArtifactDetails::default(
        );

    voucher_request_details.created_on = created_on;
    voucher_request_details.nonce = Some(nonce.to_string().into_bytes());
    voucher_request_details.serial_number = serial_number;
    voucher_request_details.assertion = Some(requested_assertion);
    voucher_request_details.agent_provided_proximity_registrar_cert =
        Some(trigger.agent_signed_proximity_cert);
    voucher_request_details.agent_signed_data = Some(trigger.agent_signed_data);

    let voucher_request =
        brski_prm_artifacts::ietf_voucher::request_artifact::VoucherRequestArtifact {
            details: voucher_request_details,
        };

    voucher_request 
}