use axum::{
    body::Bytes,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{
    status::enroll::status::PledgeEnrollStatus,
    token_type::{PlainTokenType, TokenType},
};
use common::server_error::ServerError;
use signeable_payload::{signeable::raw_signed::RawSigned, DefaultSignerVerifyer};
use tracing::{event, Level};

use crate::{client, server::server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers, bytes))]
pub async fn handle_enrollstatus(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<(), ServerError> {
    event!(Level::DEBUG, "Headers: {:#?}", headers);

    event!(Level::INFO, "Received enrollstatus request");

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    let token_type = PlainTokenType::from_content_type(content_type);

    let verifier = token_type.signature_type().get_sv::<PledgeEnrollStatus>()?;

    event!(Level::INFO, "Parsing Enroll Status from body");
    let enroll_status: RawSigned<PledgeEnrollStatus> = RawSigned::new(bytes.to_vec());

    let decoded = enroll_status.into_verifyable_boxed(verifier).verify(None)?;

    let status = decoded.payload();

    event!(Level::INFO, "Enroll Status from Voucher: {:#?}", status);

    Ok(())
}
