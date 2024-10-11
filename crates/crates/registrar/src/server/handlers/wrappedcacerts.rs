use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{
    cacerts::{response::CaCertsResponse, response_payload::CaCerts},
    token_type::PlainTokenType,
};
use common::server_error::ServerError;
use signeable_payload::{
    signeable::{signed::Signed, signing_context::BasicSigningContext, unsigned::Unsigned},
    DefaultSignerVerifyer,
};
use tracing::{event, Level};

use crate::{client, server::server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers))]
pub async fn handle_wrappedcacerts(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Signed<CaCerts>, ServerError> {
    event!(Level::DEBUG, "Headers: {:#?}", headers);

    event!(Level::INFO, "Received wrappedcacerts request");

    let ca_certificates = &state.config.ca_certificate;
    let registrar_ldevid_certs = &state.config.registrar_certificate;
    let registrar_ldevid_key = &state.config.registrar_key;

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    event!(Level::INFO, "Building wrappedcacerts x5bag");

    let response_payload = CaCerts {
        x5bag: vec![ca_certificates.clone().into()],
    };

    let requested_signature_type = PlainTokenType::from_content_type(accept);
    let response = CaCertsResponse::new(
        response_payload,
        [registrar_ldevid_certs.clone()],
        requested_signature_type,
    );

    let unsigned_response: Unsigned<CaCerts> = response.try_into()?;

    let requested_token_type = PlainTokenType::from_content_type(accept);

    let signer = requested_token_type.signature_type().get_sv::<CaCerts>()?;

    let signed = unsigned_response
        .into_signeable_boxed(signer)
        .sign(registrar_ldevid_key, BasicSigningContext::new())?;

    event!(Level::DEBUG, "Encoded wrappedcacerts: {:#?}", signed.data());
    event!(Level::DEBUG, "Sending back wrappedcacerts");

    Ok(signed)
}
