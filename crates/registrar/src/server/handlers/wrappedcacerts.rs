use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{
    cacerts::{self, response::CACERTS_JWS}, ietf_voucher::request_artifact::VoucherRequestArtifact, issued_voucher::IssuedVoucherJWS, jws::JWS, pvr::response::PVR_JWS, rvr::RVR_JWS
};
use common::{server_error::ServerError, util::is_jws_voucher};
use tracing::{event, Level};

use crate::{client, server::server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers))]
pub async fn handle_wrappedcacerts(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<CACERTS_JWS, ServerError> {

    event!(Level::DEBUG, "Headers: {:#?}", headers);

    event!(Level::INFO, "Received wrappedcacerts request");
    
    let ca_certificates = &state.config.ca_certificate;
    let registrar_ldevid_certs = &state.config.registrar_certificate;
    let registrar_ldevid_key = &state.config.registrar_key;

    event!(Level::INFO, "Building wrappedcacerts x5bag");
    let response_payload = cacerts::response_payload::ResponsePayload {
        x5bag: vec![ca_certificates.clone().into()],
    };

    let response = cacerts::response::Response::new(response_payload, [registrar_ldevid_certs.clone()]);
    
    let jws: CACERTS_JWS = response.try_into()?;


    event!(Level::INFO, "Encoding wrappedcacerts");
    let encoded = jws.encode(registrar_ldevid_key.private_key_to_der()?)?;

    encoded.verify()?;

    event!(Level::DEBUG, "Encoded wrappedcacerts: {:#?}", encoded);
    event!(Level::DEBUG, "Sending back wrappedcacerts");

    Ok(encoded)
}
