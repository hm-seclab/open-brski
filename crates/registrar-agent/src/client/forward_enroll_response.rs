use brski_prm_artifacts::cacerts::response::CACERTS_JWS;
use brski_prm_artifacts::content_type::{JOSE, JWS_VOUCHER, PKCS7};
use brski_prm_artifacts::ietf_voucher::agent_signed_data;
use brski_prm_artifacts::ietf_voucher::request_artifact::VoucherRequestArtifact;
use brski_prm_artifacts::issued_voucher::IssuedVoucherJWS;
use brski_prm_artifacts::jws::JWS;
use brski_prm_artifacts::per::response::PER_JWS;
use brski_prm_artifacts::per::response_payload::ResponsePayload;
use brski_prm_artifacts::pvr::response::PVR_JWS;
use brski_prm_artifacts::rer;
use brski_prm_artifacts::status::enroll::response::EnrollStatusJWS;
use brski_prm_artifacts::status::voucher::response::vStatus_JWS;
use common::server_error::ServerError;
use tracing::event;

use crate::parsed_config::{ParsedConfig};


use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;

#[tracing::instrument(skip(client, parsed_config, response), target = "RegistrarAgent")]
pub async fn send_enroll_response_to_pledge(
    parsed_config: &ParsedConfig,
    response: rer::response::Response,
    pledge: &(&str, &str),
    client: &Client,
) -> Result<EnrollStatusJWS, ServerError> {
    let forward_cacerts_pledge_url = format!(
        "{}/.well-known/brski/ser",
        pledge.0
    );

    event!(tracing::Level::INFO, "Sending Registrar Enroll-Response to pledge at: {}", forward_cacerts_pledge_url);
    event!(tracing::Level::DEBUG, "Registrar-Enroll-Response: {:?}", response);

    let data = response.0.to_der()?;

    let response = client
        .post(forward_cacerts_pledge_url)
        .header(CONTENT_TYPE, PKCS7)
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse("Sending registrar enroll response to pledge failed".to_string()))
    }

    let response_body = response.text().await?;

    let jws = EnrollStatusJWS::Encoded(response_body);

    Ok(jws)
}