use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{
    ietf_voucher::request_artifact::VoucherRequestArtifact, issued_voucher::IssuedVoucherJWS, jws::JWS, pvr::response::PVR_JWS, rvr::RVR_JWS, status::voucher::response::vStatus_JWS
};
use common::{server_error::ServerError, util::{is_jose, is_jws_voucher}};
use tracing::{event, Level};

use crate::{client, server::server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers, body))]
pub async fn handle_voucher_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: String,
) -> Result<(), ServerError> {

    event!(Level::DEBUG, "Headers: {:#?}", headers);
    event!(Level::DEBUG, "Body: {:#?}", body);

    event!(Level::INFO, "Received voucher_status request");

    let content_type = headers.get(CONTENT_TYPE).ok_or(ServerError::BadRequest)?.to_str().map_err(|_| ServerError::BadRequest)?;

    is_jose(CONTENT_TYPE, content_type)?;


    event!(Level::INFO, "Parsing Voucher Status from body");
    let jws: vStatus_JWS = JWS::Encoded(body.clone());
    event!(Level::DEBUG, "Voucher Status: {:#?}", jws);


    let decoded = jws.decode().unwrap();

    let status = decoded.try_decoded_data().unwrap().payload;

    event!(Level::INFO, "Voucher Status: {:#?}", status);
    
    Ok(())
}
