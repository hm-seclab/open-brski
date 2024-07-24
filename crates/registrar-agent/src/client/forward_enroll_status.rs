use brski_prm_artifacts::content_type::JOSE;
use brski_prm_artifacts::status::enroll::response::EnrollStatusJWS;
use common::server_error::ServerError;
use tracing::event;

use crate::parsed_config::{ParsedConfig};


use reqwest::header::CONTENT_TYPE;
use reqwest::Client;


#[tracing::instrument(skip(client, parsed_config, enroll_status), target = "RegistrarAgent", name="send_enroll_status_to_registrar")]
pub async fn send_enroll_status_to_registrar(
    parsed_config: &ParsedConfig,
    enroll_status: EnrollStatusJWS,
    client: &Client,
) -> Result<(), ServerError> {

    let data = enroll_status.try_encoded_data()?;
    
    let enroll_status_registrar_url = format!(
        "{}/.well-known/brski/enrollstatus",
        parsed_config.config.registrar_url
    );

    event!(tracing::Level::INFO, "Sending Enroll Status to registrar at: {}", enroll_status_registrar_url);

    let response = client
        .post(enroll_status_registrar_url)
        .header(CONTENT_TYPE, JOSE)
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received enroll_status response");

    event!(tracing::Level::INFO, "Verifying enroll_status response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse("Sending enroll_status to registrar failed".to_string()))
    }

    
    Ok(())
}