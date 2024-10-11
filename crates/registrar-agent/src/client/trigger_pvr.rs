use base64::Engine;
use brski_prm_artifacts::{
    ietf_voucher::{
        agent_signed_data::{self, AgentSignedData},
        request_artifact::VoucherRequestArtifact,
        VoucherRequest,
    },
    pvr::trigger::VoucherRequestTrigger,
    token_type::DataInterchangeFormat,
};
use common::server_error::ServerError;
use signeable_payload::{
    header::HeaderSet,
    signeable::{
        raw_signed::RawSigned, signeable::Signeable, signed::Signed,
        signing_context::BasicSigningContext, unsigned::Unsigned,
    },
    signing_context::SigningContext,
};
use tracing::{event, info, Level};

use crate::{
    parsed_config::ParsedConfig, pledge_communicator::PledgeCtx, server::server::ServerState,
};

const SERVICE_GLOB: &'static str = "_brski-pledge._tcp.local";

#[tracing::instrument(skip(parsed_config), target = "RegistrarAgent")]
fn get_agent_signed_data(
    parsed_config: &ParsedConfig,
    ctx: &PledgeCtx,
) -> Result<Signed<AgentSignedData>, ServerError> {
    let created_on = chrono::Utc::now();

    info!("Created-On: {}", created_on);

    let skid = parsed_config
        .ee_certificate
        .subject_key_id()
        .ok_or(ServerError::BadResponse(
            "No SKID in EE certificate".to_string(),
        ))?;

    let skid = skid.as_slice();

    let skid_str = base64::engine::general_purpose::URL_SAFE.encode(skid);

    info!("SKID: {}", skid_str);

    let signer = ctx
        .pledge_info
        .supported_token_type
        .signature_type()
        .get_sv::<AgentSignedData>()?;

    let mut header = HeaderSet::new();

    header.set_key_id(skid_str.clone(), true);

    info!("Header: {:#?}", header);
    let agent_data = Unsigned::new(
        agent_signed_data::AgentSignedData::new(created_on, ctx.pledge_serial.clone()),
        header,
    );
    info!("Creating unsigned ASD: {:?}", agent_data);

    let signeable_asd = agent_data.into_signeable_boxed(signer);

    let mut ctx = BasicSigningContext::new();
    ctx.set_skid(Some(skid_str));

    let signed_asd = signeable_asd.sign(parsed_config.ee_key.clone(), ctx)?;

    Ok(signed_asd)
}

#[tracing::instrument(
    skip(parsed_config),
    target = "RegistrarAgent",
    name = "get_pvr_trigger"
)]
pub fn get_pvr_trigger(
    parsed_config: &ParsedConfig,
    ctx: &PledgeCtx,
) -> Result<brski_prm_artifacts::pvr::trigger::VoucherRequestTrigger, ServerError> {
    let agent_provided_proximity_registrar_cert = parsed_config.registrar_certificate.clone();

    let agent_signed_data = get_agent_signed_data(parsed_config, ctx)?;

    let trigger = VoucherRequestTrigger {
        agent_signed_proximity_cert: agent_provided_proximity_registrar_cert.into(),
        agent_signed_data: agent_signed_data.into_raw(),
    };

    Ok(trigger)
}

#[tracing::instrument(skip(state), target = "RegistrarAgent")]
pub async fn trigger_pvr(
    state: &ServerState,
    ctx: &PledgeCtx,
) -> Result<RawSigned<VoucherRequest>, ServerError> {
    let pvr = get_pvr_trigger(&state.config, ctx)?;

    let serialized = match ctx.pledge_info.data_interchance_format {
        DataInterchangeFormat::JSON => {
            info!("Serializing tPVR to JSON");
            serde_json::to_vec(&pvr)?
        }
        DataInterchangeFormat::CBOR => {
            info!("Serializing tPVR to CBOR");
            let mut buf = vec![];
            ciborium::into_writer(&pvr, &mut buf).map_err(|e| anyhow::anyhow!(e))?;
            buf
        }
        _ => return Err(ServerError::UnsupportedMediaType),
    };

    let response = state
        .communicator
        .send_pvr_trigger(serialized, ctx.clone())
        .await?;

    event!(tracing::Level::INFO, "Received tPVR response");
    //event!(tracing::Level::DEBUG, "tPVR Response: {}", response);

    let encoded_pvr = RawSigned::new(response);

    event!(tracing::Level::INFO, "Parsed PVR");

    Ok(encoded_pvr)
}
