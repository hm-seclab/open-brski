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

use crate::parsed_config::{ParsedConfig};


use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;

#[tracing::instrument(skip(client, parsed_config, pvr), target = "RegistrarAgent")]
pub async fn send_pvr_to_registrar(
    parsed_config: &ParsedConfig,
    pvr: PVR_JWS,
    client: &Client,
) -> Result<IssuedVoucherJWS, ServerError> {
    let request_enroll_registrar_url = format!(
        "{}/.well-known/brski/requestvoucher",
        parsed_config.config.registrar_url
    );

    event!(tracing::Level::INFO, "Sending PVR to registrar at: {}", request_enroll_registrar_url);
    event!(tracing::Level::DEBUG, "PVR: {}", pvr);

    let data = pvr.try_encoded_data()?;

    let response = client
        .post(request_enroll_registrar_url)
        .header(ACCEPT, JWS_VOUCHER)
        .header(CONTENT_TYPE, JWS_VOUCHER)
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse("Sending PVR to registrar failed".to_string()))
    }

    if response.headers().get(CONTENT_TYPE).is_none() {
        return Err(ServerError::BadResponse("No content type in response".to_string()))
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != JWS_VOUCHER {
            return Err(ServerError::BadResponse("Wrong content type in response".to_string()))
        }
    }

    let response_data = response.text().await?;
    event!(tracing::Level::INFO, "Received issued voucher response_data");
    event!(tracing::Level::DEBUG, "Issued Voucher Response Data: {}", response_data);
    // TODO convert this to jws

    event!(tracing::Level::INFO, "Parsing IssuedVoucher response data into JWS");
    let jws = IssuedVoucherJWS::Encoded(response_data);
    event!(tracing::Level::DEBUG, "Issued Voucher JWS: {:#?}", jws);

    Ok(jws)
}