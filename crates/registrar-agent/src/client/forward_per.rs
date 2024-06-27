use brski_prm_artifacts::cacerts::response::CACERTS_JWS;
use brski_prm_artifacts::content_type::{PKCS7, JWS_VOUCHER};
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
pub async fn send_per_to_registrar(
    parsed_config: &ParsedConfig,
    per: PER_JWS,
    client: &Client,
) -> Result<rer::response::Response, ServerError> {

    let data = per.try_encoded_data()?;
    
    let request_enroll_registrar_url = format!(
        "{}/.well-known/brski/requestenroll",
        parsed_config.config.registrar_url
    );

    event!(tracing::Level::INFO, "Sending PER to registrar at: {}", request_enroll_registrar_url);

    let response = client
        .post(request_enroll_registrar_url)
        .header(ACCEPT, JWS_VOUCHER)
        .header(CONTENT_TYPE, JWS_VOUCHER)
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received PER response");

    event!(tracing::Level::INFO, "Verifying PER response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse("Sending PER to registrar failed".to_string()))
    }

    if response.headers().get(CONTENT_TYPE).is_none() {
        return Err(ServerError::BadResponse("No content type in response".to_string()))
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != PKCS7 {
            return Err(ServerError::BadResponse("Wrong content type in response".to_string()))
        }
    }

    let response_data = response.bytes().await?.to_vec();

    event!(tracing::Level::INFO, "Received PER response_data - Issued Certificate");
    event!(tracing::Level::DEBUG, "PER Response Data: Bytes with length {}", response_data.len());

    let certificate = openssl::x509::X509::from_der(&response_data)?;

    event!(tracing::Level::INFO, "Parsed PER Response Data");
    event!(tracing::Level::DEBUG, "PER Response Data: {:?}", certificate);

    let res = rer::response::Response(certificate.into());

    Ok(res)
}