use brski_prm_artifacts::ietf_voucher::{pki::X509, VoucherRequest};
use signeable_payload::{BasicSigningContext, Signed, Unsigned};
use tracing::info;

pub struct TransformTpvrArgs {
    pub trigger: brski_prm_artifacts::pvr::trigger::VoucherRequestTrigger,
    pub serial_number: String,
    pub requested_token_type: brski_prm_artifacts::token_type::VoucherTokenType,
    pub pledge_idevid_chain: Vec<X509>,
    pub pledge_idevid_key: Vec<u8>,
}

pub fn transform_tpvr(args: TransformTpvrArgs) -> anyhow::Result<Signed<VoucherRequest>> {
    let voucher_request = create_voucher_requst(CreateVoucherRequestArgs {
        serial_number: args.serial_number.clone(),
        trigger: args.trigger.clone(),
    });

    info!("Building tPVR response");
    let pvr_response = brski_prm_artifacts::pvr::response::PledgeVoucherRequestResponse::new(
        voucher_request,
        args.pledge_idevid_chain,
        args.requested_token_type.clone(),
    );

    info!("Built tPVR response");
    info!("PVR Response: {:#?}", pvr_response);

    let pvr: Unsigned<VoucherRequest> = pvr_response.try_into()?;

    let ctx = BasicSigningContext::new();

    let signer = args
        .requested_token_type
        .signature_type()
        .get_sv::<VoucherRequest>()?;
    info!("Signing tPVR response");
    let signed = pvr
        .into_signeable_boxed(signer)
        .sign(args.pledge_idevid_key, ctx)?;
    info!("Sending signed data: {:#?}", signed);
    Ok(signed)
}

struct CreateVoucherRequestArgs {
    pub serial_number: String,
    pub trigger: brski_prm_artifacts::pvr::trigger::VoucherRequestTrigger,
}
fn create_voucher_requst(args: CreateVoucherRequestArgs) -> VoucherRequest {
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
    voucher_request_details.serial_number = args.serial_number.clone();
    voucher_request_details.assertion = Some(requested_assertion);
    voucher_request_details.agent_provided_proximity_registrar_cert =
        Some(args.trigger.agent_signed_proximity_cert);
    voucher_request_details.agent_signed_data = Some(args.trigger.agent_signed_data.into());

    let voucher_request =
        brski_prm_artifacts::ietf_voucher::request_artifact::VoucherRequestArtifact {
            details: voucher_request_details,
        };

    voucher_request
}
