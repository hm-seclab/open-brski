use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{
    cacerts::response_payload::CaCerts,
    token_type::{DataInterchangeFormat, PlainTokenType, CBOR, JSON},
};
use common::server_error::ServerError;
use signeable_payload::{signeable::raw_signed::RawSigned, DefaultSignerVerifyer};
use tracing::{event, info, Level};

use crate::{parsed_config::ParsedConfig, server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers))]
pub async fn handle_dif(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<String, ServerError> {
    event!(Level::INFO, "Received DIF request");
    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    if accept != "text/plain" {
        info!(
            "Unsupported accept type: Expected text/plain, Got {}",
            accept
        );
        return Err(ServerError::UnsupportedMediaType);
    }

    let cloned_state = state.read().await.clone();
    let res = cloned_state
        .config
        .pledge_info
        .data_interchance_format
        .as_content_type();

    Ok(res.to_string())
}
