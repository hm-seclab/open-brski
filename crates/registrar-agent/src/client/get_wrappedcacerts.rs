use brski_prm_artifacts::cacerts::response_payload::CaCerts;
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
    name = "get_wrappedcacerts_from_registrar"
)]
pub async fn get_wrappedcacerts_from_registrar(
    parsed_config: &ParsedConfig,
    client: &Client,
    ctx: &PledgeCtx,
) -> Result<RawSigned<CaCerts>, ServerError> {
    let request_wrapped_cacerts_registrar_url = format!(
        "{}/.well-known/brski/wrappedcacerts",
        parsed_config.config.registrar_url
    );

    event!(
        tracing::Level::INFO,
        "Sending wrappedcacerts GET to registrar at: {}",
        request_wrapped_cacerts_registrar_url
    );

    let response = client
        .get(request_wrapped_cacerts_registrar_url)
        .header(
            ACCEPT,
            ctx.pledge_info.supported_token_type.as_content_type(),
        )
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received wrappedcacerts response");

    event!(tracing::Level::INFO, "Verifying wrappedcacerts response");

    if !response.status().is_success() {
        return Err(ServerError::BadResponse(
            "Requesting wrappedcacerts from registrar failed".to_string(),
        ));
    }

    if response.headers().get(CONTENT_TYPE).is_none() {
        return Err(ServerError::BadResponse(
            "No content type in response".to_string(),
        ));
    }

    let pledge_supported_content_type = ctx.pledge_info.supported_token_type.as_content_type();
    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != pledge_supported_content_type {
            return Err(ServerError::BadResponse(format!(
                "Wrong content type in response - Expected: {}, Actual: Content Type: {}",
                pledge_supported_content_type,
                content_type
                    .to_str()
                    .unwrap_or("Could not parse Content Type")
            )));
        }
    }

    let response_data = response.bytes().await?;

    event!(
        tracing::Level::INFO,
        "Received wrapped ca certs response_data"
    );

    let rawsigned: RawSigned<CaCerts> = RawSigned::new(response_data.to_vec());

    Ok(rawsigned)
}
