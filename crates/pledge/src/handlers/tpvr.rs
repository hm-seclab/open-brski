use anyhow::Ok;
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{
    ietf_voucher::VoucherRequest,
    token_type::{DataInterchangeFormat, PlainTokenType, VoucherTokenType, JSON},
};
use common::server_error::ServerError;
use signeable_payload::{
    signeable::{signed::Signed, signing_context::BasicSigningContext, unsigned::Unsigned},
    DefaultSignerVerifyer,
};
use tracing::{debug, error, event, info};

use crate::server::ServerState;
use pledge_lib::tpvr::{transform_tpvr, TransformTpvrArgs};
// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers, bytes))]
pub async fn handle_tpvr(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Signed<VoucherRequest>, ServerError> {
    info!("Received tPVR request");

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()?;

    let cloned_state = state.read().await.clone();

    let expected_content_type = cloned_state
        .config
        .pledge_info
        .data_interchance_format
        .as_content_type();

    if content_type != expected_content_type {
        info!(
            "Unsupported content type: Expected {}, Got {}",
            content_type, expected_content_type
        );
        return Err(ServerError::UnsupportedMediaType);
    }

    let payload = match cloned_state.config.pledge_info.data_interchance_format {
        DataInterchangeFormat::JSON => serde_json::from_slice(&bytes)?,
        DataInterchangeFormat::CBOR => ciborium::from_reader(&bytes[..])
            .map_err(|e| ServerError::InternalError(anyhow::anyhow!(e)))?,
        _ => return Err(ServerError::UnsupportedMediaType),
    };

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()?;

    if accept
        != cloned_state
            .config
            .pledge_info
            .supported_voucher_type
            .as_content_type()
    {
        info!(
            "Unsupported accept type: Expected {}, Got {}",
            accept,
            cloned_state
                .config
                .pledge_info
                .supported_voucher_type
                .as_content_type()
        );
        return Err(ServerError::UnsupportedMediaType);
    }
    // at this point in time, we can not verify the PVR Trigger. We also can not verify the agent-signed-data in the PVR Trigger.

    info!("Building tPVR response");

    let args: TransformTpvrArgs = TransformTpvrArgs {
        trigger: payload,
        serial_number: cloned_state.config.config.idev_id.clone(),
        requested_token_type: VoucherTokenType::from_content_type(accept),
        pledge_idevid_chain: [state.read().await.config.idevid_certificate.clone().into()].to_vec(),
        pledge_idevid_key: cloned_state.config.idevid_privkey.clone(),
    };

    let signed = transform_tpvr(args).map_err(|e| ServerError::InternalError(e));
    signed
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, routing::post, Router};
    use brski_prm_artifacts::{
        ietf_voucher::agent_signed_data,
        token_type::{JOSE, JSON},
    };

    use super::*;
    use crate::{parsed_config::ParsedConfig, server::get_app, util::get_test_app};
    use tower::util::ServiceExt;
}
