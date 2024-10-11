use axum::{
    body::Bytes,
    extract::State,
    http::{header::ACCEPT, HeaderMap},
};
use brski_prm_artifacts::{
    ietf_voucher::{
        artifact::{VoucherArtifact, VoucherArtifactDetails},
        VoucherRequest,
    },
    issued_voucher::IssuedVoucher,
    token_type::{TokenType, VoucherTokenType},
};
use common::server_error::ServerError;
use signeable_payload::signeable::{
    raw_signed::RawSigned, signed::Signed, signing_context::BasicSigningContext,
    unsigned::Unsigned, verifyable::Verifyable,
};
use tracing::{event, Level};

use crate::server::server::ServerState;

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "MASA", skip(state, headers, bytes))]
pub async fn handle_requestvoucher(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Signed<VoucherArtifact>, ServerError> {
    event!(Level::DEBUG, "Headers: {:#?}", headers);
    event!(Level::INFO, "Received requestvoucher request");

    // we do not confirm the content type of the request, as it is not required by the spec

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;
    // parse the rvr

    let token_type = TokenType::from_content_type(accept);

    let verifyer = token_type.signature_type().get_sv::<VoucherRequest>()?;

    event!(Level::INFO, "Parsing signed RVR from body");
    let verifyable_rvr: Verifyable<VoucherRequest> =
        RawSigned::new(bytes.to_vec()).into_verifyable_boxed(verifyer);

    event!(Level::INFO, "Verifying signed RVR");
    let verified = verifyable_rvr.verify(None)?;
    let rvr = verified.payload().clone();

    event!(Level::DEBUG, "RVR: {:#?}", rvr);

    let cert_to_pin = rvr.details.agent_provided_proximity_registrar_cert.ok_or(
        ServerError::BadRequestWithReason(
            "Registrar did not provide certificate to pin".to_string(),
        ),
    )?;
    event!(
        Level::DEBUG,
        "Registrar requested cert to pin: {:#?}",
        cert_to_pin
    );

    event!(Level::INFO, "Building voucher");
    let mut voucher_details = VoucherArtifactDetails::default();

    // skip verification for now
    voucher_details.assertion = rvr.details.assertion;
    voucher_details.serial_number = rvr.details.serial_number;
    voucher_details.nonce = rvr.details.nonce;
    voucher_details.created_on = Some(chrono::Utc::now());
    voucher_details.pinned_domain_cert = Some(cert_to_pin);

    let voucher_artifact = VoucherArtifact {
        details: voucher_details,
    };

    let requested_voucher_token_type = VoucherTokenType::from_content_type(accept);

    let issued_voucher = IssuedVoucher::try_new(
        voucher_artifact,
        [state.config.masa_certificate.clone().to_der()?],
        requested_voucher_token_type.clone(),
    )?;

    event!(Level::INFO, "Built Voucher");
    event!(Level::DEBUG, "Issued Voucher: {:#?}", issued_voucher);

    let unsigned_va: Unsigned<VoucherArtifact> = issued_voucher.try_into()?;

    let signer = requested_voucher_token_type
        .signature_type()
        .get_sv::<VoucherArtifact>()?;

    let signeable_va = unsigned_va.into_signeable_boxed(signer);

    let ctx = BasicSigningContext::new();

    event!(Level::INFO, "Signing voucher");
    let signed = signeable_va.sign(state.config.masa_key.clone(), ctx)?;

    event!(Level::INFO, "Issued voucher!");
    Ok(signed)
}
