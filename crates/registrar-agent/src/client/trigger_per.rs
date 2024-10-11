use brski_prm_artifacts::{
    per::response_payload::PledgeEnrollRequest,
    token_type::{DataInterchangeFormat, PlainTokenType},
};
use common::server_error::ServerError;
use tracing::{event, info};

use crate::{pledge_communicator::PledgeCtx, server::server::ServerState};
use signeable_payload::signeable::{raw_signed::RawSigned, signed::Signed};

pub fn get_per_trigger() -> brski_prm_artifacts::per::trigger::EnrollTrigger {
    brski_prm_artifacts::per::trigger::EnrollTrigger::default()
}

#[tracing::instrument(skip(state), target = "RegistrarAgent", name = "trigger_per")]
pub async fn trigger_per(
    state: &ServerState,
    pledge: &PledgeCtx,
) -> Result<RawSigned<PledgeEnrollRequest>, ServerError> {
    let per = get_per_trigger();

    event!(
        tracing::Level::INFO,
        "Built tPER to send to pledge: {}",
        per
    );

    let serialized = match pledge.pledge_info.data_interchance_format {
        DataInterchangeFormat::JSON => {
            info!("Serializing tPER to JSON");
            serde_json::to_vec(&per)?
        }
        DataInterchangeFormat::CBOR => {
            info!("Serializing tPER to CBOR");
            let mut buf = vec![];
            ciborium::into_writer(&per, &mut buf).map_err(|e| anyhow::anyhow!(e))?;
            buf
        }
        _ => return Err(ServerError::UnsupportedMediaType),
    };

    let response = state
        .communicator
        .send_per_trigger(serialized, pledge.clone())
        .await?;

    event!(tracing::Level::INFO, "Parsed tPer response data");
    //event!(tracing::Level::DEBUG, "tPER Response Data: {}", response);

    let encoded: RawSigned<PledgeEnrollRequest> = RawSigned::new(response);

    event!(tracing::Level::INFO, "Parsed tPER Response");

    Ok(encoded)
}
