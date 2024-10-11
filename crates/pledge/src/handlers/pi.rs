use anyhow::anyhow;
use axum::{
    body::{Body, HttpBody},
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    response::{IntoResponse, Response},
};
use brski_prm_artifacts::{
    cacerts::response_payload::CaCerts,
    token_type::{PlainTokenType, CBOR, JSON},
};
use common::server_error::ServerError;
use signeable_payload::{signeable::raw_signed::RawSigned, DefaultSignerVerifyer};
use tracing::{event, info, Level};

use crate::{parsed_config::ParsedConfig, server::ServerState};

use super::ser;

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers))]
pub async fn handle_pi(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    info!("Received PI request");
    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    let pledge_info = state.read().await.config.pledge_info.clone();

    info!("Client has requested PI in format: {}", accept);

    let serialized = match accept {
        JSON => serde_json::to_vec(&pledge_info)?,
        CBOR => {
            let mut buf = vec![];
            ciborium::into_writer(&pledge_info, &mut buf).map_err(|e| anyhow!(e))?;
            buf
        }
        _ => return Err(ServerError::UnsupportedMediaType),
    };

    info!("Returning PI {:?} in format: {}", pledge_info, accept);

    let body = Body::from(serialized);
    let res = Response::builder()
        .header(CONTENT_TYPE, accept)
        .body(body)
        .map_err(|e| anyhow!(e))?;

    info!("PI response built");
    Ok(res)
}
