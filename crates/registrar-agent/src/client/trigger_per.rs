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
use tracing::event;

use crate::parsed_config::ParsedConfig;


use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;

#[tracing::instrument(skip(client), target = "RegistrarAgent")]
pub async fn trigger_per(
    pledge: &(&str, &str),
    client: &Client,
) -> Result<PER_JWS, ServerError> {
    let per = brski_prm_artifacts::per::trigger::Trigger::default();

    event!(tracing::Level::INFO, "Built tPER to send to pledge: {}", per);

    let tpver_url = format!("{}/.well-known/brski/tper", pledge.0);
    
    event!(tracing::Level::INFO, "Sending tPER to pledge at {}", tpver_url);

    let response = client
        .post(tpver_url)
        .header(ACCEPT, "application/jose+json")
        .json(&per)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received tPER response");

    event!(tracing::Level::INFO, "Verifying tPER response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse("Sending PER to pledge failed".to_string()))
    }

    if response.headers().get(CONTENT_TYPE).is_none() {
        return Err(ServerError::BadResponse("No content type in response".to_string()))
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != JOSE {
            return Err(ServerError::BadResponse("Wrong content type in response".to_string()))
        }
    }

    let response_data = response.text().await?;

    event!(tracing::Level::INFO, "Parsed tPer response data");
    event!(tracing::Level::DEBUG, "tPER Response Data: {}", response_data);

    let encoded_per = brski_prm_artifacts::jws::JWS::<ResponsePayload>::Encoded(response_data);

    event!(tracing::Level::INFO, "Parsed tPER Response JWS");
    event!(tracing::Level::DEBUG, "tPER Response JWS: {}", encoded_per);

    if tracing::enabled!(tracing::Level::DEBUG) {
        let decoded_per = encoded_per.clone().decode().unwrap().try_decoded_data().unwrap().payload;
        event!(tracing::Level::DEBUG, "Decoded PER Payload: {:#?}", decoded_per);
    }

    Ok(encoded_per)
}