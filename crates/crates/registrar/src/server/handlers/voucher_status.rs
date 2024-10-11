use axum::{
    body::Bytes,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{status::voucher::status::VoucherStatus, token_type::PlainTokenType};
use common::server_error::ServerError;
use signeable_payload::signeable::raw_signed::RawSigned;
use tracing::{event, Level};

use crate::{client, server::server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers))]
pub async fn handle_voucher_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<(), ServerError> {
    event!(Level::DEBUG, "Headers: {:#?}", headers);

    event!(Level::INFO, "Received voucher_status request");

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    event!(Level::INFO, "Parsing Voucher Status from body");

    let signed_vstatus: RawSigned<VoucherStatus> = RawSigned::new(bytes.to_vec());

    let token_type = PlainTokenType::from_content_type(content_type);

    let verifier = token_type.signature_type().get_sv::<VoucherStatus>()?;

    let decoded = signed_vstatus
        .into_verifyable_boxed(verifier)
        .verify(None)?;

    let status = decoded.payload();

    event!(Level::INFO, "Voucher Status: {:#?}", status);

    Ok(())
}
