use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{ietf_voucher::VoucherRequest, issued_voucher::IssuedVoucherJWS, jws::JWS, pvr::response::PVR_JWS, status::voucher::{response::vStatus_JWS, status::ReasonContext}};
use common::{
    server_error::ServerError,
    util::{is_jose, is_json, is_jws_voucher},
};
use tracing::{event, Level};

use crate::parsed_config::ParsedConfig;
use crate::server::ServerState;
// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers, body))]
pub async fn handle_svr(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: String
) -> Result<vStatus_JWS, ServerError> {
    
    event!(tracing::Level::INFO, "Received svr request");
    event!(tracing::Level::DEBUG, "Headers: {:#?}", headers);
    event!(tracing::Level::DEBUG, "Body: {:#?}", body);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    is_jws_voucher(content_type)?;

    // Verification needs to be taking place later

        
    let jws = IssuedVoucherJWS::Encoded(body);

    event!(Level::INFO, "Decoding issued voucher JWS");
    let decoded = jws.decode()?;

    let voucher = decoded.try_decoded_data()?.payload;

    event!(Level::INFO, "Drawing trust anchor from received voucher");
    let trust_anchor = voucher.details.pinned_domain_cert.ok_or(ServerError::BadRequest)?;

    // Install the trust anchor, whatever that means...
    state.write().await.trust_anchor = Some(trust_anchor);

    let pledge_idevid_cert = state.read().await.config.idevid_certificate.clone();
    let pledge_idevid_key = state.read().await.config.idevid_privkey.clone();

    event!(Level::INFO, "Building voucher response");
    let status = brski_prm_artifacts::status::voucher::status::Status {
        reason: Some("Voucher successfully processed".to_string()),
        reason_context: ReasonContext {
            pvs_details: "JSON".to_string(),
        },
        ..Default::default()
    };

    let response = brski_prm_artifacts::status::voucher::response::Response::new(
        status,
        vec![pledge_idevid_cert],
    );

    let jws = vStatus_JWS::try_from(response)?;

    event!(Level::INFO, "Encoding voucher response");
    let encoded = jws.encode(pledge_idevid_key.private_key_to_der()?)?;
    encoded.verify()?;
    Ok(encoded)
}
