use brski_prm_artifacts::status::voucher::status::VoucherStatus;
use common::server_error::ServerError;
use signeable_payload::signeable::raw_signed::RawSigned;
use tracing::event;

use crate::{parsed_config::ParsedConfig, PledgeCtx};

use reqwest::{header::CONTENT_TYPE, Client};

#[tracing::instrument(
    skip(client, parsed_config),
    target = "RegistrarAgent",
    name = "send_voucher_status_to_registrar"
)]
pub async fn send_voucher_status_to_registrar(
    parsed_config: &ParsedConfig,
    voucher_status: RawSigned<VoucherStatus>,
    client: &Client,
    ctx: &PledgeCtx,
) -> Result<(), ServerError> {
    let data = voucher_status.data();

    let voucher_status_registrar_url = format!(
        "{}/.well-known/brski/voucher_status",
        parsed_config.config.registrar_url
    );

    event!(
        tracing::Level::INFO,
        "Sending Voucher Status to registrar at: {}",
        voucher_status_registrar_url
    );

    let response = client
        .post(voucher_status_registrar_url)
        .header(
            CONTENT_TYPE,
            ctx.pledge_info.supported_token_type.as_content_type(),
        )
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received voucher_status response");

    event!(tracing::Level::INFO, "Verifying voucher_status response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse(
            "Sending voucher_status to registrar failed".to_string(),
        ));
    }

    Ok(())
}
