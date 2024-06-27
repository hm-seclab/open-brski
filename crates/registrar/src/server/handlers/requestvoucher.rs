use axum::{
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{
    ietf_voucher::request_artifact::VoucherRequestArtifact, issued_voucher::IssuedVoucherJWS, jws::JWS, pvr::response::PVR_JWS, rvr::RVR_JWS
};
use common::{server_error::ServerError, util::is_jws_voucher};
use tracing::{event, Level};

use crate::{client, server::server::ServerState};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers, body))]
pub async fn handle_requestvoucher(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: String,
) -> Result<IssuedVoucherJWS, ServerError> {

    event!(Level::DEBUG, "Headers: {:#?}", headers);
    event!(Level::DEBUG, "Body: {:#?}", body);

    event!(Level::INFO, "Received requestvoucher request");
    

    let content_type = headers.get(CONTENT_TYPE).ok_or(ServerError::BadRequest)?.to_str().map_err(|_| ServerError::BadRequest)?;

    is_jws_voucher(content_type)?;


    let accept = headers.get(ACCEPT).ok_or(ServerError::BadRequest)?.to_str().map_err(|_| ServerError::BadRequest)?;
    is_jws_voucher(accept)?;


    event!(Level::INFO, "Parsing PVR JWS from body");
    let jws: PVR_JWS = JWS::Encoded(body.clone());
    event!(Level::DEBUG, "RVR JWS: {:#?}", jws);


    event!(Level::INFO, "Decoding PVR JWS");
    let decoded = jws.decode()?;

    let pvr = decoded.try_decoded_data()?;

    let headers = pvr.header.unwrap();

    let pledge_idevid_cert = headers.x509_certificate_chain().ok_or(ServerError::BadRequest)?.get(0).ok_or(ServerError::BadRequest)?.clone();

    let pledge_idevid_cert = openssl::x509::X509::from_der(&pledge_idevid_cert).map_err(|_| ServerError::BadRequest)?;

    event!(Level::INFO, "Pledge IDEVID Cert: {:#?}", pledge_idevid_cert);

    let pvr_signature_pledge_serial_number = pledge_idevid_cert.subject_name().entries_by_nid(openssl::nid::Nid::SERIALNUMBER).next().ok_or(ServerError::BadRequest)?.data().as_utf8().map_err(|_| ServerError::BadRequest)?.to_string();

    event!(Level::INFO, "Serial Number from Pledge IDEVID cert from Signature: {:#?}", pvr_signature_pledge_serial_number);

    let pvr_vra = pvr.payload;

    if pvr_vra.details.serial_number != pvr_signature_pledge_serial_number {
        event!(Level::ERROR, "PVR Serial Number does not match serial number in pledge certificate!");
        // TODO this could be forbidden
        return Err(ServerError::BadRequest);
    }

    event!(Level::INFO, "PVR Serial Number matches serial number in pledge certificate!");
    
    event!(Level::DEBUG, "PVR VoucherRequestArtifact: {:#?}", pvr_vra);

    let mut rvr_vra = VoucherRequestArtifact::default();

    event!(Level::INFO, "Building RVR from PVR");
    rvr_vra.details.created_on = Some(chrono::Utc::now());
    rvr_vra.details.nonce = pvr_vra.details.nonce;
    rvr_vra.details.assertion = pvr_vra.details.assertion;
    rvr_vra.details.prior_signed_voucher_request = Some(body.into_bytes());
    rvr_vra.details.serial_number = pvr_vra.details.serial_number;
    rvr_vra.details.agent_sign_cert = Some(vec![(state.config.reg_agt_ee_cert.clone().into())]);
    // In this implementation, we pin the registrar cert from the PVR
    rvr_vra.details.agent_provided_proximity_registrar_cert = pvr_vra.details.agent_provided_proximity_registrar_cert;

    let rvr = brski_prm_artifacts::rvr::RVR::new(rvr_vra, [state.config.registrar_certificate.clone()]);

    event!(Level::INFO, "Built RVR");
    event!(Level::DEBUG, "RVR: {:#?}", rvr);

    let jws: RVR_JWS = rvr.try_into().unwrap();


    event!(Level::INFO, "Encoding RVR JWS");
    let encoded = jws
        .encode(state.config.registrar_key.private_key_to_der().unwrap())?;

    encoded.verify()?;

    event!(Level::INFO, "Sending RVR JWS to MASA");
    let issued_voucher: IssuedVoucherJWS = client::get_voucher_from_masa(&state.config, encoded, &state.client).await?;

    let issued_voucher = issued_voucher.add_inflight_signature([state.config.registrar_certificate.clone()], state.config.registrar_key.private_key_to_der().unwrap())?; 

    event!(Level::INFO, "Returning issued voucher");

    Ok(issued_voucher)
}
