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

#[tracing::instrument(skip(client, parsed_config), target = "RegistrarAgent")]
pub async fn get_wrappedcacerts_from_registrar(
    parsed_config: &ParsedConfig,
    client: &Client,
) -> Result<CACERTS_JWS, ServerError> {
    
    let request_wrapped_cacerts_registrar_url = format!(
        "{}/.well-known/brski/wrappedcacerts",
        parsed_config.config.registrar_url
    );

    event!(tracing::Level::INFO, "Sending wrappedcacerts GET to registrar at: {}", request_wrapped_cacerts_registrar_url);

    let response = client
        .get(request_wrapped_cacerts_registrar_url)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received wrappedcacerts response");

    event!(tracing::Level::INFO, "Verifying wrappedcacerts response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse("Requesting wrappedcacerts from registrar failed".to_string()))
    }

    if response.headers().get(CONTENT_TYPE).is_none() {
        return Err(ServerError::BadResponse("No content type in response".to_string()))
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != JOSE {
            return Err(ServerError::BadResponse(format!("Wrong content type in response - Content Type: {}", content_type.to_str().unwrap())))
        }
    }

    let response_data = response.text().await?;

    event!(tracing::Level::INFO, "Received wrapped ca certs response_data");
    event!(tracing::Level::DEBUG, "Wrapped CA Certs Response Data: {}", response_data);

    let jws: CACERTS_JWS = CACERTS_JWS::Encoded(response_data);

    if tracing::enabled!(tracing::Level::DEBUG) {
        let decoded = jws.clone().decode()?;
        event!(tracing::Level::DEBUG, "Decoded CACERTS JWS: {:#?}", decoded);
    }

    Ok(jws)
}