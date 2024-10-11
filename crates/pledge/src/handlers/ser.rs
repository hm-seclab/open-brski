use axum::{
    body::Body,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{
    ietf_voucher::pki::X509, status::enroll::status::PledgeEnrollStatus, token_type::PlainTokenType,
};
use common::{server_error::ServerError, util::is_pkcs7};
use pledge_lib::ser::{transform_ser, TransformSerArgs};
use signeable_payload::{
    signeable::{signed::Signed, signing_context::BasicSigningContext, unsigned::Unsigned},
    DefaultSignerVerifyer,
};
use tracing::{event, Level};

use crate::{parsed_config::ParsedConfig, server::ServerState};
// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers, body))]
pub async fn handle_ser(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Signed<PledgeEnrollStatus>, ServerError> {
    event!(tracing::Level::INFO, "Received ser request");
    event!(tracing::Level::DEBUG, "Headers: {:#?}", headers);
    event!(tracing::Level::DEBUG, "Body: {:#?}", body);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    is_pkcs7(content_type)?;

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;
    // Verification needs to be taking place later

    let requested_token_type = PlainTokenType::from_content_type(accept);

    event!(Level::INFO, "Parsing received LDEVID certificate");

    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| ServerError::BadRequest)?;

    // Install the trust anchor, whatever that means...

    event!(Level::INFO, "Building enroll status");
    let enroll_status = brski_prm_artifacts::status::enroll::status::PledgeEnrollStatus::default();

    let idevid_sign_cert = state.read().await.config.idevid_certificate.clone();
    let idevid_sign_key = state.read().await.config.idevid_privkey.clone();

    let args: TransformSerArgs = TransformSerArgs {
        requested_token_type: requested_token_type.clone(),
        raw_ldevid_cert: body_bytes.to_vec(),
        enroll_status: enroll_status.clone(),
        pledge_idevid_chain: vec![idevid_sign_cert.clone().into()],
        pledge_idevid_key: idevid_sign_key.clone(),
    };

    let transformed = transform_ser(args)?;
    state.write().await.ldevid_cert = Some(transformed.ldevid_cert);

    Ok(transformed.signed_enroll_status)
}
