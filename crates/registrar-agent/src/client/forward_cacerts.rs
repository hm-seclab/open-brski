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
use brski_prm_artifacts::status::voucher::response::vStatus_JWS;
use common::server_error::ServerError;
use tracing::event;

use crate::parsed_config::{ParsedConfig};


use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;

#[tracing::instrument(skip(client, parsed_config, cacerts), target = "RegistrarAgent")]
pub async fn send_cacerts_to_pledge(
    parsed_config: &ParsedConfig,
    cacerts: CACERTS_JWS,
    pledge: &(&str, &str),
    client: &Client,
) -> Result<(), ServerError> {
    let forward_cacerts_pledge_url = format!(
        "{}/.well-known/brski/scac",
        pledge.0
    );

    event!(tracing::Level::INFO, "Sending Wrapped CA Certs to pledge at: {}", forward_cacerts_pledge_url);
    event!(tracing::Level::DEBUG, "Wrapped CA Certs: {}", cacerts);

    let data = cacerts.try_encoded_data()?;

    let response = client
        .post(forward_cacerts_pledge_url)
        .header(CONTENT_TYPE, JOSE)
        .header(ACCEPT, JOSE)
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse("Sending CA Certs to pledge failed".to_string()))
    }

    Ok(())
}