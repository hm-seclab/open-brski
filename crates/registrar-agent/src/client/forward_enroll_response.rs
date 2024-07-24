use brski_prm_artifacts::rer;
use brski_prm_artifacts::status::enroll::response::EnrollStatusJWS;
use common::server_error::ServerError;
use tracing::event;

use crate::pledge_communicator::PledgeCtx;
use crate::server::server::ServerState;



#[tracing::instrument(skip(state, response), target = "RegistrarAgent", name="send_enroll_response_to_pledge")]
pub async fn send_enroll_response_to_pledge(
    state: &ServerState,
    response: rer::response::Response,
    pledge: &PledgeCtx,
) -> Result<EnrollStatusJWS, ServerError> {

    let response_str = response.0.to_der()?;

    let response = state.communicator.send_enroll_response(response_str, pledge.clone()).await?;

    let jws = EnrollStatusJWS::Encoded(response);

    Ok(jws)
}