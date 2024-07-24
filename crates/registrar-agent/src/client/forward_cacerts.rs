use brski_prm_artifacts::cacerts::response::CACERTS_JWS;
use common::server_error::ServerError;
use tracing::event;

use crate::{pledge_communicator::PledgeCtx, server::server::ServerState};



#[tracing::instrument(skip(state, cacerts), target = "RegistrarAgent", name="send_cacerts_to_pledge")]
pub async fn send_cacerts_to_pledge(
    state: &ServerState,
    cacerts: CACERTS_JWS,
    pledge: &PledgeCtx,
) -> Result<(), ServerError> {


    let cacerts_str = cacerts.try_encoded_data()?;

    state.communicator.send_ca_certs(cacerts_str, pledge.clone()).await?;

    Ok(())
}