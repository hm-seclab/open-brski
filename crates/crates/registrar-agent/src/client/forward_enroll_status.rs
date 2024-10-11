use brski_prm_artifacts::status::enroll::status::PledgeEnrollStatus;
use common::server_error::ServerError;
use signeable_payload::signeable::raw_signed::RawSigned;
use tracing::event;

use crate::{parsed_config::ParsedConfig, PledgeCtx};

use reqwest::{header::CONTENT_TYPE, Client};

#[tracing::instrument(
    skip(client, parsed_config),
    target = "RegistrarAgent",
    name = "send_enroll_status_to_registrar"
)]
pub async fn send_enroll_status_to_registrar(
    parsed_config: &ParsedConfig,
    enroll_status: RawSigned<PledgeEnrollStatus>,
    client: &Client,
    ctx: &PledgeCtx,
) -> Result<(), ServerError> {
    let data = enroll_status.data();

    let enroll_status_registrar_url = format!(
        "{}/.well-known/brski/enrollstatus",
        parsed_config.config.registrar_url
    );

    event!(
        tracing::Level::INFO,
        "Sending Enroll Status to registrar at: {}",
        enroll_status_registrar_url
    );

    let response = client
        .post(enroll_status_registrar_url)
        .header(
            CONTENT_TYPE,
            ctx.pledge_info.supported_token_type.as_content_type(),
        )
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received enroll_status response");

    event!(tracing::Level::INFO, "Verifying enroll_status response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse(
            "Sending enroll_status to registrar failed".to_string(),
        ));
    }

    Ok(())
}
