use brski_prm_artifacts::ietf_voucher::VoucherRequest;
use brski_prm_artifacts::issued_voucher::IssuedVoucherJWS;
use reqwest::header::CONTENT_TYPE;
use brski_prm_artifacts::content_type::JWS_VOUCHER;
use brski_prm_artifacts::rvr::RVR_JWS;
use common::server_error::ServerError;
use tracing::{event, Level};

use crate::parsed_config::{ParsedConfig};

use reqwest::header::ACCEPT;
use reqwest::Client;

#[tracing::instrument(target = "Registrar", skip(parsed_config, rvr, client))]
pub async fn get_voucher_from_masa(
    parsed_config: &ParsedConfig,
    rvr: RVR_JWS,
    client: &Client,
) -> Result<IssuedVoucherJWS, ServerError> {

    event!(Level::DEBUG, "PVR to be sent: {:#?}", rvr);

    let requestvoucher_masa_url = format!(
        "{}/.well-known/brski/requestvoucher",
        parsed_config.config.masa_url
    );

    event!(Level::INFO, "Sending RVR to MASA at {:?}", requestvoucher_masa_url);

    let data = rvr.try_encoded_data()?;


    let response = client
        .post(requestvoucher_masa_url)
        .header(ACCEPT, JWS_VOUCHER)
        .header(CONTENT_TYPE, JWS_VOUCHER)
        .body(data)
        .send()
        .await?;

    event!(Level::INFO, "Received response from MASA");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse(format!("Sending RVR to MASA failed with Status: {}", response.status().to_string())))
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
    event!(Level::INFO, "Received issued voucher response data");
    event!(Level::DEBUG, "Issued Voucher Response{:?}", response_data);

    event!(Level::INFO, "Parsing response data as JWS voucher");
    let jws = IssuedVoucherJWS::Encoded(response_data);

    Ok(jws)
}