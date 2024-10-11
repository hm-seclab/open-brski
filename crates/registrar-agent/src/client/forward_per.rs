use anyhow::anyhow;
use brski_prm_artifacts::{
    ietf_voucher::pki::X509, per::response_payload::PledgeEnrollRequest, rer, token_type::PKCS7,
};
use common::server_error::ServerError;
use signeable_payload::signeable::raw_signed::RawSigned;
use tracing::event;

use crate::{parsed_config::ParsedConfig, PledgeCtx};

use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};

#[tracing::instrument(
    skip(client, parsed_config),
    target = "RegistrarAgent",
    name = "send_per_to_registrar"
)]
pub async fn send_per_to_registrar(
    parsed_config: &ParsedConfig,
    per: RawSigned<PledgeEnrollRequest>,
    client: &Client,
    ctx: &PledgeCtx,
) -> Result<rer::response::RegistrarEnrollRequestResponse, ServerError> {
    let data = per.data();

    let request_enroll_registrar_url = format!(
        "{}/.well-known/brski/requestenroll",
        parsed_config.config.registrar_url
    );

    event!(
        tracing::Level::INFO,
        "Sending PER to registrar at: {}",
        request_enroll_registrar_url
    );

    let response = client
        .post(request_enroll_registrar_url)
        .header(ACCEPT, PKCS7)
        .header(
            CONTENT_TYPE,
            ctx.pledge_info.supported_token_type.as_content_type(),
        )
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received PER response");

    event!(tracing::Level::INFO, "Verifying PER response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse(
            "Sending PER to registrar failed".to_string(),
        ));
    }

    if response.headers().get(CONTENT_TYPE).is_none() {
        return Err(ServerError::BadResponse(
            "No content type in response".to_string(),
        ));
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != PKCS7 {
            return Err(ServerError::BadResponse(
                "Wrong content type in response".to_string(),
            ));
        }
    }

    let response_data = response.bytes().await?.to_vec();

    event!(
        tracing::Level::INFO,
        "Received PER response_data - Issued Certificate"
    );
    event!(
        tracing::Level::DEBUG,
        "PER Response Data: Bytes with length {}",
        response_data.len()
    );

    let certificate: X509 = response_data
        .try_into()
        .map_err(|_| anyhow!("Failed parsing per response data into x509"))?;

    event!(tracing::Level::INFO, "Parsed PER Response Data");
    event!(
        tracing::Level::DEBUG,
        "PER Response Data: {:?}",
        certificate
    );

    let res = rer::response::RegistrarEnrollRequestResponse(certificate.into());

    Ok(res)
}
