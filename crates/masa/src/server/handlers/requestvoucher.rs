use axum::{
    extract::State,
    http::{
        header::{ACCEPT},
        HeaderMap,
    },
};
use brski_prm_artifacts::{ietf_voucher::artifact::{VoucherArtifact, VoucherArtifactDetails}, issued_voucher::{IssuedVoucher, IssuedVoucherJWS}, rvr::RVR_JWS};
use common::{server_error::ServerError, util::is_jws_voucher};
use tracing::{event, Level};

use crate::{server::server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "MASA", skip(state, headers, body))]
pub async fn handle_requestvoucher(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: String,
) -> Result<IssuedVoucherJWS, ServerError> {

    event!(Level::DEBUG, "Headers: {:#?}", headers);
    event!(Level::DEBUG, "Body: {:#?}", body);
    event!(Level::INFO, "Received requestvoucher request");

    // we do not confirm the content type of the request, as it is not required by the spec

    let accept = headers.get(ACCEPT).ok_or(ServerError::BadRequest)?.to_str().map_err(|_| ServerError::BadRequest)?;
    is_jws_voucher(accept)?;

    // parse the rvr

    event!(Level::INFO, "Parsing RVR JWS from body");
    let RVR_JWS = RVR_JWS::Encoded(body);
    event!(Level::DEBUG, "RVR_JWS: {:#?}", RVR_JWS);

    event!(Level::INFO, "Decoding RVR JWS");
    let rvr = RVR_JWS.decode()?.try_decoded_data()?;

    event!(Level::DEBUG, "RVR: {:#?}", rvr);

    let cert_to_pin = rvr.payload.details.agent_provided_proximity_registrar_cert.ok_or(ServerError::BadRequestWithReason("Registrar did not provide certificate to pin".to_string()))?;
    event!(Level::DEBUG, "Registrar requested cert to pin: {:#?}", cert_to_pin);

    event!(Level::INFO, "Building voucher");
    let mut voucher_details = VoucherArtifactDetails::default();

    // skip verification for now
    voucher_details.assertion = rvr.payload.details.assertion;
    voucher_details.serial_number = rvr.payload.details.serial_number;
    voucher_details.nonce = rvr.payload.details.nonce;
    voucher_details.created_on = Some(chrono::Utc::now());
    voucher_details.pinned_domain_cert = Some(cert_to_pin);

    let voucher_artifact = VoucherArtifact {
        details: voucher_details
    };

    let issued_voucher = IssuedVoucher::new(voucher_artifact, [state.config.masa_certificate.clone()]);

    event!(Level::INFO, "Built Voucher");
    event!(Level::DEBUG, "Issued Voucher: {:#?}", issued_voucher);

    event!(Level::INFO, "Encoding Voucher as JWS");
    let jws: IssuedVoucherJWS = issued_voucher.try_into()?;

    let jws = jws.encode(state.config.masa_key.private_key_to_der().unwrap())?;
    jws.verify()?;
    event!(Level::DEBUG, "IssuedVoucherJWS: {:#?}", jws);

    event!(Level::INFO, "Issued voucher!");
    Ok(jws)
}
