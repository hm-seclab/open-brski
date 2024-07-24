use brski_prm_artifacts::ietf_voucher::agent_signed_data;
use brski_prm_artifacts::ietf_voucher::request_artifact::VoucherRequestArtifact;
use brski_prm_artifacts::pvr::response::PVR_JWS;
use common::server_error::ServerError;
use tracing::{event, Level};

use crate::parsed_config::ParsedConfig;
use crate::pledge_communicator::PledgeCtx;
use crate::server::server::ServerState;



const SERVICE_GLOB: &'static str = "_brski-pledge._tcp.local";

#[tracing::instrument(skip(parsed_config), target = "RegistrarAgent", name="get_pvr_trigger")]
pub fn get_pvr_trigger(parsed_config: &ParsedConfig, serial_number: String) -> Result<brski_prm_artifacts::pvr::trigger::Trigger, ServerError>{
    let agent_provided_proximity_registrar_cert = parsed_config.registrar_certificate.clone();

    let created_on = chrono::Utc::now();

    let agent_signed_data = agent_signed_data::AgentSignedData::new(created_on, serial_number);

    let skid = parsed_config.ee_certificate.subject_key_id().ok_or(ServerError::BadResponse("No SKID in EE certificate".to_string()))?;

    let skid = skid.as_slice();

    let reg_agt_private_key = parsed_config.ee_key.private_key_to_der()?;

    let trigger_options = brski_prm_artifacts::pvr::trigger::TriggerOptions::new(
        agent_provided_proximity_registrar_cert,
        &reg_agt_private_key,
        &skid,
        agent_signed_data,
    );

    let pvr: brski_prm_artifacts::pvr::trigger::Trigger = trigger_options.try_into()?;

    event!(tracing::Level::INFO, "Built PVR");
    event!(tracing::Level::DEBUG, "PVR: {}", pvr); 

    Ok(pvr)
} 

#[tracing::instrument(skip(state), target = "RegistrarAgent")]
pub async fn trigger_pvr(
    state: &ServerState,
    pledge: &PledgeCtx,
) -> Result<PVR_JWS, ServerError> {

   
    let pvr = get_pvr_trigger(&state.config, pledge.pledge_serial.to_string())?;


    let pvr_str = serde_json::to_string(&pvr)?;

    let response = state.communicator.send_pvr_trigger(pvr_str, pledge.clone()).await?;

    event!(tracing::Level::INFO, "Received tPVR response");
    event!(tracing::Level::DEBUG, "tPVR Response: {}", response);


    let encoded_pvr = PVR_JWS::Encoded(response);

    event!(tracing::Level::INFO, "Parsed PVR JWS");
    event!(tracing::Level::DEBUG, "Parsed PVR JWS: {}", encoded_pvr);

    if tracing::enabled!(Level::DEBUG) {
        event!(tracing::Level::DEBUG, "Trying to decode JWS for debug purposes...");
        let decoded_pvr_jws = encoded_pvr.clone().decode()?.try_decoded_data()?;
        let decoded_pvr = decoded_pvr_jws.payload;
        event!(tracing::Level::DEBUG, "Decoded PVR Payload: {:?}", decoded_pvr);
    }

    Ok(encoded_pvr)

}