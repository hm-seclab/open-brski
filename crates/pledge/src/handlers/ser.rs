use axum::{
    body::Body, extract::State, http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    }, Json
};
use brski_prm_artifacts::{cacerts::response::CACERTS_JWS, ietf_voucher::VoucherRequest, issued_voucher::IssuedVoucherJWS, jws::JWS, pvr::response::PVR_JWS, status::{enroll::response::EnrollStatusJWS, voucher::{response::vStatus_JWS, status::ReasonContext}}};
use common::{
    server_error::ServerError,
    util::{is_jose, is_json, is_jws_voucher, is_pkcs7},
};
use brski_prm_artifacts::ietf_voucher::pki::X509;
use tracing::{event, Level};

use crate::parsed_config::ParsedConfig;
use crate::server::ServerState;
// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers, body))]
pub async fn handle_ser(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: Body
) -> Result<EnrollStatusJWS, ServerError> {
    
    event!(tracing::Level::INFO, "Received ser request");
    event!(tracing::Level::DEBUG, "Headers: {:#?}", headers);
    event!(tracing::Level::DEBUG, "Body: {:#?}", body);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    is_pkcs7(content_type)?;

    // Verification needs to be taking place later

    event!(Level::INFO, "Parsing received LDEVID certificate");

    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.map_err(|_| ServerError::BadRequest)?;

    let pledge_ldevid_cert: X509 = openssl::x509::X509::from_der(&body_bytes.to_vec())?.into();

    state.write().await.ldevid_cert = Some(pledge_ldevid_cert);
    // Install the trust anchor, whatever that means...

    event!(Level::INFO, "Building enroll status");
    let enroll_status = brski_prm_artifacts::status::enroll::status::Status::default();

    let idevid_sign_cert = state.read().await.config.idevid_certificate.clone();
    let idevid_sign_key = state.read().await.config.idevid_privkey.clone();

    let enroll_status_response = brski_prm_artifacts::status::enroll::response::Response::new(enroll_status, [idevid_sign_cert]);

    event!(Level::INFO, "Encoding enroll status");
    let jws: EnrollStatusJWS = enroll_status_response.try_into()?;

    let encoded = jws.encode(idevid_sign_key.private_key_to_der()?)?;
    encoded.verify()?;
    Ok(encoded)
}
