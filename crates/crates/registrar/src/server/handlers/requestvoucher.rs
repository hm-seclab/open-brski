use axum::{
    body::Bytes,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{
    ietf_voucher::{
        artifact::VoucherArtifact, pki::X509, request_artifact::VoucherRequestArtifact,
        VoucherRequest,
    },
    issued_voucher::IssuedVoucher,
    pvr::response::PledgeVoucherRequestResponse,
    rvr::response::RegistrarVoucherRequestResponse,
    token_type::{self, VoucherTokenType},
};
use common::server_error::ServerError;
use signeable_payload::{
    algorithm::Algorithm,
    header::HeaderSet,
    signeable::{
        raw_signed::RawSigned, signed::Signed, signing_context::BasicSigningContext,
        unsigned::Unsigned,
    },
    DefaultSignerVerifyer,
};
use tracing::{event, info, Level};

use crate::{client, server::server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers, bytes))]
pub async fn handle_requestvoucher(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Signed<VoucherArtifact>, ServerError> {
    event!(Level::DEBUG, "Headers: {:#?}", headers);

    event!(Level::INFO, "Received requestvoucher request");

    // TODO check if content_type and accept match
    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequestWithReason("Can not parse content type".to_string()))?;

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| {
            ServerError::BadRequestWithReason("Can not parse accept header".to_string())
        })?;

    event!(Level::INFO, "Parsing signed PVR from body");
    let signed_pvr: RawSigned<VoucherRequest> = RawSigned::from(bytes.to_vec());

    let token_type = VoucherTokenType::from_content_type(content_type);
    info!("Token Type from content type: {:#?}", token_type);

    let verifyer = token_type.signature_type().get_sv::<VoucherRequest>()?;

    info!("Verifying signed PVR");
    let decoded = signed_pvr.into_verifyable_boxed(verifyer).verify(None)?;

    let pvr = decoded.payload();

    let headers = decoded.headers();

    let pledge_idevid_cert = headers
        .x509_certificate_chain()
        .ok_or(ServerError::BadRequest)?
        .get(0)
        .ok_or(ServerError::BadRequestWithReason(
            "Can not get x509 certificate chain from header set".to_string(),
        ))?
        .clone();

    let pledge_idevid_cert = openssl::x509::X509::from_der(&pledge_idevid_cert).map_err(|_| {
        ServerError::BadRequestWithReason("Can not parse pledge idevid cert".to_string())
    })?;

    event!(Level::INFO, "Pledge IDEVID Cert: {:#?}", pledge_idevid_cert);

    let signature_number_entry = pledge_idevid_cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::SERIALNUMBER)
        .next()
        .ok_or(ServerError::BadRequestWithReason(
            "Can not parse subject serial number from pledge idevid cert".to_string(),
        ))?;
    let pvr_signature_pledge_serial_number = signature_number_entry
        .data()
        .as_utf8()
        .map_err(|_| {
            ServerError::BadRequestWithReason("Can not parse serial number to utf8".to_string())
        })?
        .to_string();

    event!(
        Level::INFO,
        "Serial Number from Pledge IDEVID cert from Signature: {:#?}",
        pvr_signature_pledge_serial_number
    );

    let pvr_vra = pvr.clone();

    if pvr_vra.details.serial_number != pvr_signature_pledge_serial_number {
        event!(
            Level::ERROR,
            "PVR Serial Number does not match serial number in pledge certificate!"
        );
        // TODO this could be forbidden
        return Err(ServerError::BadRequest);
    }

    event!(
        Level::INFO,
        "PVR Serial Number matches serial number in pledge certificate!"
    );

    event!(Level::DEBUG, "PVR VoucherRequestArtifact: {:#?}", pvr_vra);

    let mut rvr_vra = VoucherRequestArtifact::default();

    event!(Level::INFO, "Building RVR from PVR");
    rvr_vra.details.created_on = Some(chrono::Utc::now());
    rvr_vra.details.nonce = pvr_vra.details.nonce;
    rvr_vra.details.assertion = pvr_vra.details.assertion;
    rvr_vra.details.prior_signed_voucher_request = Some(bytes.to_vec());
    rvr_vra.details.serial_number = pvr_vra.details.serial_number;
    rvr_vra.details.agent_sign_cert = Some(vec![(state.config.reg_agt_ee_cert.clone().into())]);
    // In this implementation, we pin the registrar cert from the PVR
    rvr_vra.details.agent_provided_proximity_registrar_cert =
        pvr_vra.details.agent_provided_proximity_registrar_cert;

    let requested_token_type = VoucherTokenType::from_content_type(accept);

    let rvr = RegistrarVoucherRequestResponse::new(
        rvr_vra,
        [state.config.registrar_certificate.clone()],
        requested_token_type.clone(),
    );

    event!(Level::INFO, "Built RVR");
    event!(Level::DEBUG, "RVR: {:#?}", rvr);
    let unsigned_rvr: Unsigned<VoucherRequest> = rvr.try_into()?;

    let signer = requested_token_type
        .signature_type()
        .get_sv::<VoucherRequest>()?;

    let signed_rvr = unsigned_rvr.into_signeable_boxed(signer).sign(
        state.config.registrar_key.clone(),
        signeable_payload::signeable::signing_context::BasicSigningContext::new(),
    )?;

    event!(Level::INFO, "Sending raw signed RVR to MASA");
    let issued_voucher =
        client::get_voucher_from_masa(&state.config, signed_rvr, &state.client).await?;

    let reg_cert_x509: X509 = state.config.registrar_certificate.clone().into();
    let mut headers = HeaderSet::new();
    headers.set_algorithm(Algorithm::ES256.to_string(), true);

    headers.set_x509_certificate_chain(&vec![reg_cert_x509], true);
    headers.set_content_type(accept, false);

    let sig_adder = requested_token_type.signature_type().get_sigadder()?;

    let issued_voucher = issued_voucher.add_signature_boxed(
        headers,
        state.config.registrar_key.clone(),
        sig_adder,
        BasicSigningContext::new(),
    )?;
    event!(Level::INFO, "Returning issued voucher");

    Ok(issued_voucher)
}
