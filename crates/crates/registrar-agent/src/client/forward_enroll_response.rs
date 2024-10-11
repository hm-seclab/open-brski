use brski_prm_artifacts::{rer, status::enroll::status::PledgeEnrollStatus};
use common::server_error::ServerError;
use tracing::event;

use crate::{pledge_communicator::PledgeCtx, server::server::ServerState};
use signeable_payload::signeable::raw_signed::RawSigned;

#[tracing::instrument(
    skip(state, response),
    target = "RegistrarAgent",
    name = "send_enroll_response_to_pledge"
)]
pub async fn send_enroll_response_to_pledge(
    state: &ServerState,
    response: rer::response::RegistrarEnrollRequestResponse,
    pledge: &PledgeCtx,
) -> Result<RawSigned<PledgeEnrollStatus>, ServerError> {
    let response_str = response.0.as_ref();

    let response = state
        .communicator
        .send_enroll_response(response_str.to_vec(), pledge.clone())
        .await?;

    let raw_signed: RawSigned<PledgeEnrollStatus> = RawSigned::new(response.into());

    Ok(raw_signed)
}
