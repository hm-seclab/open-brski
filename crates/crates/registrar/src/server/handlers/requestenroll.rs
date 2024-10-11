use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap, Response,
    },
};

use brski_prm_artifacts::{
    ietf_voucher::pki::X509Req,
    per::{response::PledgeEnrollRequestResponse, response_payload::PledgeEnrollRequest},
    rer::response::RegistrarEnrollRequestResponse,
    token_type::{PlainTokenType, PKCS7},
};
use signeable_payload::{
    signeable::{raw_signed::RawSigned, verified::Verified},
    DefaultSignerVerifyer,
};

use common::{server_error::ServerError, util::is_pkcs7};
use tracing::{event, Level};

use crate::{client, server::server::ServerState, sign_cert};

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(target = "Registrar", skip(state, headers, bytes))]
pub async fn handle_requestenroll(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response<Body>, ServerError> {
    event!(Level::INFO, "Received requestenroll request");
    event!(Level::DEBUG, "Headers: {:#?}", headers);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    let token_type = PlainTokenType::from_content_type(content_type);

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    is_pkcs7(accept)?;

    // TODO check if accept and content type match

    event!(Level::INFO, "Parsing raw signed PER from body");
    let signed_per = RawSigned::new(bytes.to_vec());

    let verifyer = token_type
        .signature_type()
        .get_sv::<PledgeEnrollRequest>()?;

    let decoded: Verified<PledgeEnrollRequest> =
        signed_per.into_verifyable_boxed(verifyer).verify(None)?;

    let payload = decoded.payload().clone();

    let csr: X509Req = payload.csr.p10_csr;

    let registrar_ca_cert = state.config.ca_certificate.clone();
    let registrar_ca_key = state.config.ca_key.clone();

    let registrar_sign_cert = state.config.registrar_certificate.clone();
    let registrar_sign_key = state.config.registrar_key.clone();

    let pkey = openssl::pkey::PKey::private_key_from_pkcs8(&state.config.registrar_key.clone())?;

    event!(Level::INFO, "Signing certificate");
    let (signed_cert, signed_cert_pkey) =
        crate::sign_cert::mk_ca_signed_cert(&registrar_ca_cert, &pkey, &csr)?;

    event!(Level::INFO, "Created certificate for pledge");
    event!(Level::DEBUG, "Signed certificate: {:#?}", signed_cert);

    let response = RegistrarEnrollRequestResponse(signed_cert.into());

    let res: Response<Body> = axum::response::Response::builder()
        .header(CONTENT_TYPE, PKCS7)
        .body(response.0.to_der().unwrap().into())
        .unwrap();

    event!(Level::INFO, "Returning signed certificate in response");
    event!(Level::DEBUG, "Response: {:#?}", response);

    Ok(res)
}
