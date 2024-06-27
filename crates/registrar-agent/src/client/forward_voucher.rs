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

#[tracing::instrument(skip(client, parsed_config, voucher), target = "RegistrarAgent")]
pub async fn send_voucher_to_pledge(
    parsed_config: &ParsedConfig,
    voucher: IssuedVoucherJWS,
    pledge: &(&str, &str),
    client: &Client,
) -> Result<vStatus_JWS, ServerError> {
    let forward_voucher_pledge_url = format!(
        "{}/.well-known/brski/svr",
        pledge.0
    );

    event!(tracing::Level::INFO, "Sending Voucher to pledge at: {}", forward_voucher_pledge_url);
    event!(tracing::Level::DEBUG, "Voucher: {}", voucher);

    let data = voucher.try_encoded_data()?;

    let response = client
        .post(forward_voucher_pledge_url)
        .header(CONTENT_TYPE, JWS_VOUCHER)
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse(format!("Sending Voucher to pledge failed - Status: {}", response.status().to_string())))
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
    event!(tracing::Level::INFO, "Received vStatus response_data");
    event!(tracing::Level::DEBUG, "vStatus Reponse Data: {}", response_data);
    // TODO convert this to jws

    event!(tracing::Level::INFO, "Parsing vStatus response data into JWS");
    let jws = vStatus_JWS::Encoded(response_data);
    event!(tracing::Level::DEBUG, "vStatus JWS{:#?}", jws);

    Ok(jws)
}