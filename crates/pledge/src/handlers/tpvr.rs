use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{ietf_voucher::VoucherRequest, jws::JWS, pvr::response::PVR_JWS};
use common::{
    server_error::ServerError,
    util::{is_jose, is_json},
};
use tracing::event;

use crate::parsed_config::ParsedConfig;
use crate::server::ServerState;

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers, payload))]
#[axum::debug_handler]
pub async fn handle_tpvr(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(payload): Json<brski_prm_artifacts::pvr::trigger::Trigger>,
) -> Result<PVR_JWS, ServerError> {
    
    event!(tracing::Level::INFO, "Received tPVR request");

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()?;

    is_json(content_type)?;

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()?;

    is_jose(ACCEPT, accept)?;

    // at this point in time, we can not verify the PVR Trigger. We also can not verify the agent-signed-data in the PVR Trigger.

    event!(tracing::Level::INFO, "Building tPVR response");

    let created_on = chrono::Utc::now();

    event!(tracing::Level::INFO, "Timestamp: {:?}", created_on);

    let nonce = rand::random::<u32>();

    event!(tracing::Level::INFO, "Nonce: {:?}", nonce);

    let serial_number = state.read().await.config.config.idev_id.clone();

    let requested_assertion =
        brski_prm_artifacts::ietf_voucher::assertion::Assertion::AgentProximity;

    let mut voucher_request_details =
        brski_prm_artifacts::ietf_voucher::request_artifact::VoucherRequestArtifactDetails::default(
        );

    voucher_request_details.created_on = Some(created_on);
    voucher_request_details.nonce = Some(nonce.to_string().into_bytes());
    voucher_request_details.serial_number = serial_number;
    voucher_request_details.assertion = Some(requested_assertion);
    voucher_request_details.agent_provided_proximity_registrar_cert =
        Some(payload.agent_signed_proximity_cert);
    voucher_request_details.agent_signed_data = Some(payload.agent_signed_data);

    let voucher_request =
        brski_prm_artifacts::ietf_voucher::request_artifact::VoucherRequestArtifact {
            details: voucher_request_details,
        };

    event!(tracing::Level::INFO, "Built Voucher Request");
    event!(tracing::Level::DEBUG, "Voucher Request: {:#?}", voucher_request);


    event!(tracing::Level::INFO, "Building tPVR response");
    let pvr_response = brski_prm_artifacts::pvr::response::Response::new(
        voucher_request,
        [state.read().await.config.idevid_certificate.clone()],
    );

    event!(tracing::Level::INFO, "Built tPVR response");
    event!(tracing::Level::DEBUG, "PVR Response: {:#?}", pvr_response);


    let jws: PVR_JWS = pvr_response.try_into()?;

    let private_key = state.read().await.config.idevid_privkey.private_key_to_der()?;

    event!(tracing::Level::INFO, "Encoding tPVR response into JWS");
    let jws = jws.encode(private_key)?;
    jws.verify()?;

    Ok(jws)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use axum::{routing::post, Router};
    use brski_prm_artifacts::content_type::{JOSE, JSON};
    use brski_prm_artifacts::ietf_voucher::agent_signed_data;

    use super::*;
    use crate::util::get_test_app;
    use crate::{parsed_config::ParsedConfig, server::get_app};
    use tower::util::ServiceExt;
}