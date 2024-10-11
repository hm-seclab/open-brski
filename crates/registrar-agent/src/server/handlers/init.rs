use axum::extract::State;
use brski_prm_artifacts::{
    cacerts::response_payload::CaCerts, ietf_voucher::request_artifact::VoucherRequestArtifact,
    issued_voucher::IssuedVoucher, per::response_payload::PledgeEnrollRequest,
    rer::response::RegistrarEnrollRequestResponse,
};
use common::server_error::ServerError;
use signeable_payload::signeable::raw_signed::RawSigned;
use tracing::{event, Level};

use crate::{client, pledge_communicator::PledgeCtx, server::server::ServerState};

struct BootstrappingObjects {
    issued_voucher: RawSigned<IssuedVoucher>,
    signed_cert: RegistrarEnrollRequestResponse,
    wrapped_cacerts: RawSigned<CaCerts>,
}

// We don't trust client's to supply just any base64 encoded data, so we parse it.
#[tracing::instrument(skip(state), target = "RegistrarAgent", name = "init")]
pub async fn init(State(state): State<ServerState>) -> Result<(), ServerError> {
    event!(Level::INFO, "Received init request");

    let pledges = client::discover_pledges(&state.config).await?;

    event!(Level::INFO, "Discovered pledges: {:#?}", pledges);

    let example_pledge = pledges.first().unwrap();

    let ctx = client::request_pledge_ctx(&state, example_pledge).await?;

    bootstrap_pledge(&state, &ctx).await?;

    Ok(())
    // now we need to send the PER to the registrar
}

#[tracing::instrument(skip(state), target = "RegistrarAgent", name = "bootstrap_pledge")]
pub async fn bootstrap_pledge(state: &ServerState, pledge: &PledgeCtx) -> Result<(), ServerError> {
    let bootstrapping_objects = get_bootstrapping_objects(state, pledge).await?;

    // first we send the voucher to the pledge

    let voucher_status =
        client::send_voucher_to_pledge(state, bootstrapping_objects.issued_voucher, pledge).await?;

    // next we send the cacerts to the pledge

    client::send_cacerts_to_pledge(state, bootstrapping_objects.wrapped_cacerts, pledge).await?;

    // then, we send the signed certificate to the pledge

    let enroll_status =
        client::send_enroll_response_to_pledge(state, bootstrapping_objects.signed_cert, pledge)
            .await?;

    // if all this is successful, we can now send the voucher status to the registrar

    client::send_voucher_status_to_registrar(&state.config, voucher_status, &state.client, pledge)
        .await?;

    // we also send the enroll status to the registrar
    client::send_enroll_status_to_registrar(&state.config, enroll_status, &state.client, pledge)
        .await?;
    Ok(())
}

#[tracing::instrument(
    skip(state),
    target = "RegistrarAgent",
    name = "get_bootstrapping_objects"
)]
async fn get_bootstrapping_objects(
    state: &ServerState,
    pledge: &PledgeCtx,
) -> Result<BootstrappingObjects, ServerError> {
    let (pvr, per) = get_pvr_per_pair_for_pledge(&state.clone(), pledge).await?;

    let issued_voucher =
        client::send_pvr_to_registrar(&state.config, pvr, &state.client, pledge).await?;

    let rer_response =
        client::send_per_to_registrar(&state.config, per, &state.client, pledge).await?;

    event!(
        Level::INFO,
        "Received signed certificate from registrar: {:?}",
        rer_response
    );

    let wrapped_cacerts =
        client::get_wrappedcacerts_from_registrar(&state.config, &state.client, pledge).await?;

    Ok(BootstrappingObjects {
        issued_voucher: issued_voucher,
        signed_cert: rer_response,
        wrapped_cacerts: wrapped_cacerts,
    })
}

#[tracing::instrument(
    skip(state),
    target = "RegistrarAgent",
    name = "get_pvr_per_pair_for_pledge"
)]
async fn get_pvr_per_pair_for_pledge(
    state: &ServerState,
    pledge: &PledgeCtx,
) -> Result<
    (
        RawSigned<VoucherRequestArtifact>,
        RawSigned<PledgeEnrollRequest>,
    ),
    ServerError,
> {
    let pvr = client::trigger_pvr(state, pledge).await?;

    event!(Level::INFO, "Done receiving PVR");

    let per = client::trigger_per(state, pledge).await?;

    event!(Level::INFO, "Done receiving PER");

    Ok((pvr, per))
}
