use axum::extract::State;
use brski_prm_artifacts::{
    cacerts::response::CACERTS_JWS, issued_voucher::IssuedVoucherJWS, per::response::PER_JWS, pvr::response::PVR_JWS, rer, status::{enroll::response::EnrollStatusJWS, voucher::response::vStatus_JWS}
};
use common::server_error::ServerError;
use tracing::{event, info, Level};

use crate::{client, pledge_communicator::PledgeCtx, server::server::ServerState};

struct BootstrappingObjects {
    issued_voucher: IssuedVoucherJWS,
    signed_cert: rer::response::Response,
    wrapped_cacerts: CACERTS_JWS
}

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(skip(state), target = "RegistrarAgent", name = "init")]
pub async fn init(State(state): State<ServerState>) -> Result<(), ServerError> {
    event!(Level::INFO, "Received init request");

    let pledges = client::discover_pledges(&state.config).await?;

    event!(Level::INFO, "Discovered pledges: {:#?}", pledges);

    let example_pledge = pledges.first().unwrap();

    bootstrap_pledge(&state, example_pledge).await?;

    Ok(())
    // now we need to send the PER to the registrar
}

#[tracing::instrument(skip(state), target = "RegistrarAgent", name = "bootstrap_pledge")]
pub async fn bootstrap_pledge(state: &ServerState, pledge: &PledgeCtx) -> Result<(), ServerError> {
    let bootstrapping_objects = get_bootstrapping_objects(state, pledge).await?;

    // first we send the voucher to the pledge

    let voucher_status: vStatus_JWS = client::send_voucher_to_pledge(state, bootstrapping_objects.issued_voucher, pledge).await?;

    // next we send the cacerts to the pledge

    client::send_cacerts_to_pledge(state, bootstrapping_objects.wrapped_cacerts, pledge).await?;

    // then, we send the signed certificate to the pledge

    let enroll_status: EnrollStatusJWS = client::send_enroll_response_to_pledge(state, bootstrapping_objects.signed_cert, pledge).await?;

    // if all this is successful, we can now send the voucher status to the registrar

    client::send_voucher_status_to_registrar(&state.config, voucher_status, &state.client).await?;

    // we also send the enroll status to the registrar
    client::send_enroll_status_to_registrar(&state.config, enroll_status, &state.client).await?;
    Ok(())
}

#[tracing::instrument(skip(state), target = "RegistrarAgent", name = "get_bootstrapping_objects")]
async fn get_bootstrapping_objects(state: &ServerState, pledge: &PledgeCtx) -> Result<BootstrappingObjects, ServerError> {
    let (pvr, per) = get_pvr_per_pair_for_pledge(&state.clone(), pledge).await?;

    let issued_voucher_jws: IssuedVoucherJWS =
        client::send_pvr_to_registrar(&state.config, pvr, &state.client).await?;

    let signed_cert_jws = client::send_per_to_registrar(&state.config, per, &state.client).await?;

    info!("Received signed certificate from registrar");

    let wrapped_cacerts = client::get_wrappedcacerts_from_registrar(&state.config, &state.client).await?;
    
    Ok(BootstrappingObjects {
        issued_voucher: issued_voucher_jws,
        signed_cert: signed_cert_jws,
        wrapped_cacerts: wrapped_cacerts
    })
}

#[tracing::instrument(skip(state), target = "RegistrarAgent", name="get_pvr_per_pair_for_pledge")]
async fn get_pvr_per_pair_for_pledge(
    state: &ServerState,
    pledge: &PledgeCtx,
) -> Result<(PVR_JWS, PER_JWS), ServerError> {

    let pvr = client::trigger_pvr(state, pledge).await?;

    event!(Level::INFO, "Done receiving PVR");

    let per = client::trigger_per(state, pledge).await?;

    event!(Level::INFO, "Done receiving PER");

    Ok((pvr, per))
}
