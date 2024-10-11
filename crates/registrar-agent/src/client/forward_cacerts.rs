use brski_prm_artifacts::cacerts::response_payload::CaCerts;
use common::server_error::ServerError;
use signeable_payload::signeable::raw_signed::RawSigned;
use tracing::event;

use crate::{pledge_communicator::PledgeCtx, server::server::ServerState};

#[tracing::instrument(
    skip(state, cacerts),
    target = "RegistrarAgent",
    name = "send_cacerts_to_pledge"
)]
pub async fn send_cacerts_to_pledge(
    state: &ServerState,
    cacerts: RawSigned<CaCerts>,
    pledge: &PledgeCtx,
) -> Result<(), ServerError> {
    state
        .communicator
        .send_ca_certs(cacerts.data(), pledge.clone())
        .await?;

    Ok(())
}
