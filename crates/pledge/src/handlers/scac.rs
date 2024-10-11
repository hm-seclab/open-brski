use axum::{
    body::Bytes,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{cacerts::response_payload::CaCerts, token_type::PlainTokenType};
use common::server_error::ServerError;
use signeable_payload::{signeable::raw_signed::RawSigned, DefaultSignerVerifyer};
use tracing::{event, Level};

use crate::{parsed_config::ParsedConfig, server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers, bytes))]
pub async fn handle_scac(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<(), ServerError> {
    event!(tracing::Level::INFO, "Received scac request");
    event!(tracing::Level::DEBUG, "Headers: {:#?}", headers);

    // TODO make sure content type and accept match
    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    // Verification needs to be taking place later

    let token_type = PlainTokenType::from_content_type(content_type);

    let signed_cacerts: RawSigned<CaCerts> = RawSigned::new(bytes.to_vec());
    event!(Level::INFO, "Decoding WrappedCaCerts");

    let verifier = token_type.signature_type().get_sv::<CaCerts>()?;

    let decoded = signed_cacerts
        .into_verifyable_boxed(verifier)
        .verify(Default::default())?;

    let ca_certs = decoded.payload().clone().x5bag;

    // Install the trust anchor, whatever that means...

    state.write().await.cacerts = Some(ca_certs);

    Ok(())
}
