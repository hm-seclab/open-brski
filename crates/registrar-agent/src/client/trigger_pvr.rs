use brski_prm_artifacts::cacerts::response::CACERTS_JWS;
use brski_prm_artifacts::content_type::{JOSE, JWS_VOUCHER};
use brski_prm_artifacts::ietf_voucher::agent_signed_data;
use brski_prm_artifacts::ietf_voucher::request_artifact::VoucherRequestArtifact;
use brski_prm_artifacts::issued_voucher::IssuedVoucherJWS;
use brski_prm_artifacts::jws::JWS;
use brski_prm_artifacts::per::response::PER_JWS;
use brski_prm_artifacts::per::response_payload::ResponsePayload;
use brski_prm_artifacts::pvr::response::PVR_JWS;
use brski_prm_artifacts::rer;
use common::server_error::ServerError;
use tracing::{event, Level};

use crate::parsed_config::ParsedConfig;


use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;

const SERVICE_GLOB: &'static str = "_brski-pledge._tcp.local";

#[tracing::instrument(skip(client, parsed_config), target = "RegistrarAgent")]
pub async fn trigger_pvr(
    parsed_config: &ParsedConfig,
    pledge: &(&str, &str),
    client: &Client,
) -> Result<PVR_JWS, ServerError> {

    event!(tracing::Level::INFO, "Building PVR");

    let agent_provided_proximity_registrar_cert = parsed_config.registrar_certificate.clone();

    let created_on = chrono::Utc::now();

    let serial_number = pledge.1;

    let agent_signed_data = agent_signed_data::AgentSignedData::new(created_on, serial_number);

    let skid = parsed_config.ee_certificate.subject_key_id().unwrap();

    let skid = skid.as_slice();

    let reg_agt_private_key = parsed_config.ee_key.private_key_to_der().unwrap();

    let trigger_options = brski_prm_artifacts::pvr::trigger::TriggerOptions::new(
        agent_provided_proximity_registrar_cert,
        &reg_agt_private_key,
        &skid,
        agent_signed_data,
    );

    let pvr: brski_prm_artifacts::pvr::trigger::Trigger = trigger_options.try_into().unwrap();

    event!(tracing::Level::INFO, "Built PVR");
    event!(tracing::Level::DEBUG, "PVR: {}", pvr);

    let tpvr_url = format!("{}/.well-known/brski/tpvr", pledge.0);

    event!(tracing::Level::INFO, "Sending PVR to pledge at: {}", tpvr_url);

    let response = client
        .post(tpvr_url)
        .header(ACCEPT, "application/jose+json")
        .json(&pvr)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(ServerError::BadResponse(format!("{}, {}", "Sending TPVR to pledge failed", response.status())))
    }

    if let None = response.headers().get(CONTENT_TYPE) {
        return Err(ServerError::BadResponse("No content type in response".to_string()))
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != JWS_VOUCHER {
            return Err(ServerError::BadResponse("Wrong content type in response".to_string()))
        }
    }

    let response_data = response.text().await?;

    event!(tracing::Level::INFO, "Received tPVR response");
    event!(tracing::Level::DEBUG, "tPVR Response: {}", response_data);


    let encoded_pvr = PVR_JWS::Encoded(response_data);

    event!(tracing::Level::INFO, "Parsed PVR JWS");
    event!(tracing::Level::DEBUG, "Parsed PVR JWS: {}", encoded_pvr);

    if tracing::enabled!(Level::DEBUG) {
        let decoded_pvr = encoded_pvr.clone().decode().unwrap().try_decoded_data().unwrap().payload;
        event!(tracing::Level::DEBUG, "Decoded PVR Payload: {:#?}", decoded_pvr);
    }

    Ok(encoded_pvr)

}