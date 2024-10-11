use brski_prm_artifacts::{
    ietf_voucher::{artifact::VoucherArtifact, VoucherRequest},
    issued_voucher::IssuedVoucher,
};
use common::server_error::ServerError;
use reqwest::header::CONTENT_TYPE;
use signeable_payload::signeable::{raw_signed::RawSigned, signed::Signed};
use tracing::{event, Level};

use crate::parsed_config::ParsedConfig;

use reqwest::{header::ACCEPT, Client};

#[tracing::instrument(target = "Registrar", skip(parsed_config, rvr, client))]
pub async fn get_voucher_from_masa(
    parsed_config: &ParsedConfig,
    rvr: Signed<VoucherRequest>,
    client: &Client,
) -> Result<RawSigned<VoucherArtifact>, ServerError> {
    event!(Level::DEBUG, "PVR to be sent: {:#?}", rvr);

    let requestvoucher_masa_url = format!(
        "{}/.well-known/brski/requestvoucher",
        parsed_config.config.masa_url
    );

    // from the RVR we signed, we can get the requested content type for for the voucher from the MASA
    let rvr_content_type = rvr
        .header()
        .content_type()
        .ok_or(ServerError::InternalError(anyhow::anyhow!(
            "No content type in RVR"
        )))?;
    let requested_voucher_content_type = rvr_content_type;

    event!(
        Level::INFO,
        "Sending RVR to MASA at {:?}",
        requestvoucher_masa_url
    );

    let response = client
        .post(requestvoucher_masa_url)
        .header(ACCEPT, requested_voucher_content_type)
        .header(CONTENT_TYPE, rvr_content_type)
        .body(rvr.data())
        .send()
        .await?;

    event!(Level::INFO, "Received response from MASA");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse(format!(
            "Sending RVR to MASA failed with Status: {}",
            response.status().to_string()
        )));
    }

    if response.headers().get(CONTENT_TYPE).is_none() {
        return Err(ServerError::BadResponse(
            "No content type in response".to_string(),
        ));
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != requested_voucher_content_type {
            return Err(ServerError::BadResponse(
                "Wrong content type in response".to_string(),
            ));
        }
    }

    let response_data = response.bytes().await?;
    event!(Level::INFO, "Received issued voucher response data");
    event!(Level::INFO, "Parsing response data as raw signed voucher");
    let raw_signed_voucher_artifact: RawSigned<VoucherArtifact> =
        RawSigned::from(response_data.to_vec().to_vec());

    Ok(raw_signed_voucher_artifact)
}
