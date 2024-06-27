use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{cacerts::response::CACERTS_JWS, ietf_voucher::VoucherRequest, issued_voucher::IssuedVoucherJWS, jws::JWS, pvr::response::PVR_JWS, status::voucher::{response::vStatus_JWS, status::ReasonContext}};
use common::{
    server_error::ServerError,
    util::{is_jose, is_json, is_jws_voucher},
};
use tracing::{event, Level};

use crate::parsed_config::ParsedConfig;
use crate::server::ServerState;

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers, body))]
pub async fn handle_scac(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: String
) -> Result<(), ServerError> {
    
    event!(tracing::Level::INFO, "Received scac request");
    event!(tracing::Level::DEBUG, "Headers: {:#?}", headers);
    event!(tracing::Level::DEBUG, "Body: {:#?}", body);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    is_jose(CONTENT_TYPE, content_type)?;

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    is_jose(ACCEPT, accept)?;

    // Verification needs to be taking place later

    let jws = CACERTS_JWS::Encoded(body);
    event!(Level::INFO, "Decoding WrappedCaCerts JWS");
    let decoded = jws.decode()?;

    let ca_certs = decoded.try_decoded_data()?.payload.x5bag;

    // Install the trust anchor, whatever that means...

    state.write().await.cacerts = Some(ca_certs);

    Ok(())
}
