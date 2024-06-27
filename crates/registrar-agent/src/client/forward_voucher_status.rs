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
use brski_prm_artifacts::status::voucher::response::vStatus_JWS;
use common::server_error::ServerError;
use tracing::event;

use crate::parsed_config::{ParsedConfig};


use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;


#[tracing::instrument(skip(client, parsed_config), target = "RegistrarAgent")]
pub async fn send_voucher_status_to_registrar(
    parsed_config: &ParsedConfig,
    voucher_status: vStatus_JWS,
    client: &Client,
) -> Result<(), ServerError> {

    let data = voucher_status.try_encoded_data()?;
    
    let voucher_status_registrar_url = format!(
        "{}/.well-known/brski/voucher_status",
        parsed_config.config.registrar_url
    );

    event!(tracing::Level::INFO, "Sending Voucher Status to registrar at: {}", voucher_status_registrar_url);

    let response = client
        .post(voucher_status_registrar_url)
        .header(CONTENT_TYPE, JOSE)
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received voucher_status response");

    event!(tracing::Level::INFO, "Verifying voucher_status response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse("Sending voucher_status to registrar failed".to_string()))
    }

    
    Ok(())
}