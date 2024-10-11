use axum::{
    body::Bytes,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{
    ietf_voucher::{artifact::VoucherArtifact, pki::X509},
    issued_voucher::IssuedVoucher,
    status::voucher::status::{ReasonContext, VoucherStatus},
    token_type::{PlainTokenType, VoucherTokenType},
};
use common::server_error::ServerError;
use pledge_lib::svr::{TransformSvrArgs, TransformVoucherStatusArgs};
use signeable_payload::{
    signeable::{
        raw_signed::RawSigned, signed::Signed, signing_context::BasicSigningContext,
        unsigned::Unsigned,
    },
    DefaultSignerVerifyer,
};
use tracing::{event, Level};

use crate::{parsed_config::ParsedConfig, server::ServerState};
// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Pledge", skip(state, headers, bytes))]
pub async fn handle_svr(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Signed<VoucherStatus>, ServerError> {
    event!(tracing::Level::INFO, "Received svr request");
    event!(tracing::Level::DEBUG, "Headers: {:#?}", headers);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    let token_type = VoucherTokenType::from_content_type(content_type);

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    // Verification needs to be taking place later

    let args: TransformSvrArgs = TransformSvrArgs {
        token_type: token_type.clone(),
        raw_issued_voucher: bytes.to_vec(),
    };

    let voucher: VoucherArtifact = pledge_lib::svr::transform_svr(args)?;

    event!(Level::INFO, "Drawing trust anchor from received voucher");
    let trust_anchor = voucher
        .details
        .pinned_domain_cert
        .ok_or(ServerError::BadRequest)?;

    // Install the trust anchor, whatever that means...
    state.write().await.trust_anchor = Some(trust_anchor);

    let pledge_idevid_cert = state.read().await.config.idevid_certificate.clone();
    let pledge_idevid_key = state.read().await.config.idevid_privkey.clone();

    event!(Level::INFO, "Building voucher response");
    let status = brski_prm_artifacts::status::voucher::status::VoucherStatus {
        reason: Some("Voucher successfully processed".to_string()),
        reason_context: ReasonContext {
            pvs_details: "JSON".to_string(),
        },
        ..Default::default()
    };

    let requested_token_type = PlainTokenType::from_content_type(accept);

    let converted: X509 = pledge_idevid_cert.into();

    let args: TransformVoucherStatusArgs = TransformVoucherStatusArgs {
        status: status.clone(),
        pledge_idevid_chain: vec![converted],
        pledge_idevid_key: pledge_idevid_key.clone(),
        requested_token_type: requested_token_type.clone(),
    };

    let transformed = pledge_lib::svr::transform_voucher_status(args)?;

    Ok(transformed)
}
