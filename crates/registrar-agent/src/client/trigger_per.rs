use brski_prm_artifacts::per::response::PER_JWS;
use brski_prm_artifacts::per::response_payload::ResponsePayload;
use common::server_error::ServerError;
use tracing::event;

use crate::pledge_communicator::PledgeCtx;
use crate::server::server::ServerState;



pub fn get_per_trigger() -> brski_prm_artifacts::per::trigger::Trigger {
    brski_prm_artifacts::per::trigger::Trigger::default()
}

#[tracing::instrument(skip(state), target = "RegistrarAgent", name="trigger_per")]
pub async fn trigger_per(
    state: &ServerState,
    pledge: &PledgeCtx,
) -> Result<PER_JWS, ServerError> {
    let per = get_per_trigger();

    event!(tracing::Level::INFO, "Built tPER to send to pledge: {}", per);


    let per_str = serde_json::to_string(&per)?;

    let response = state.communicator.send_per_trigger(per_str, pledge.clone()).await?;

    event!(tracing::Level::INFO, "Parsed tPer response data");
    event!(tracing::Level::DEBUG, "tPER Response Data: {}", response);

    let encoded_per = brski_prm_artifacts::jws::JWS::<ResponsePayload>::Encoded(response);

    event!(tracing::Level::INFO, "Parsed tPER Response JWS");
    event!(tracing::Level::DEBUG, "tPER Response JWS: {}", encoded_per);

    if tracing::enabled!(tracing::Level::DEBUG) {
        let decoded_per = encoded_per.clone().decode()?.try_decoded_data()?.payload;
        event!(tracing::Level::DEBUG, "Decoded PER Payload: {:#?}", decoded_per);
    }

    Ok(encoded_per)
}