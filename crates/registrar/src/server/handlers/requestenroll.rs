use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{
    ietf_voucher::{pki::X509Req, request_artifact::VoucherRequestArtifact}, issued_voucher::IssuedVoucherJWS, jws::JWS, per::response::PER_JWS, pvr::response::PVR_JWS, rer, rvr::RVR_JWS
};
use common::{server_error::ServerError, util::is_jws_voucher};
use tracing::{event, Level};

use crate::{client, server::server::ServerState, sign_cert};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers, body))]
pub async fn handle_requestenroll(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: String,
) -> Result<rer::response::Response, ServerError> {

    event!(Level::INFO, "Received requestenroll request");
    event!(Level::DEBUG, "Headers: {:#?}", headers);
    event!(Level::DEBUG, "Body: {:#?}", body);    

    let content_type = headers.get(CONTENT_TYPE).ok_or(ServerError::BadRequest)?.to_str().map_err(|_| ServerError::BadRequest)?;

    is_jws_voucher(content_type)?;

    let accept = headers.get(ACCEPT).ok_or(ServerError::BadRequest)?.to_str().map_err(|_| ServerError::BadRequest)?;
    is_jws_voucher(accept)?;

    event!(Level::INFO, "Parsing PER JWS from body");
    let jws: PER_JWS = JWS::Encoded(body.clone());
    
    let decoded = jws.decode()?;
    
    event!(Level::DEBUG, "Decoded PER JWS: {:#?}", decoded);

    let csr: X509Req = decoded.try_decoded_data()?.payload.csr.p10_csr;

    let registrar_ca_cert = state.config.ca_certificate.clone();
    let registrar_ca_key = state.config.ca_key.clone();

    let registrar_sign_cert = state.config.registrar_certificate.clone();
    let registrar_sign_key = state.config.registrar_key.clone();

    let pkey = openssl::pkey::PKey::from_ec_key(state.config.registrar_key.clone()).unwrap();

    event!(Level::INFO, "Signing certificate");
    let (signed_cert, signed_cert_pkey) = crate::sign_cert::mk_ca_signed_cert(&registrar_ca_cert, &pkey, &csr)?;

    event!(Level::INFO, "Created certificate for pledge");
    event!(Level::DEBUG, "Signed certificate: {:#?}", signed_cert);

    let response = rer::response::Response(signed_cert.into());

    event!(Level::INFO, "Returning signed certificate in response");
    event!(Level::DEBUG, "Response: {:#?}", response);

    Ok(response)
}
