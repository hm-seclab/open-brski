use anyhow::anyhow;
use brski_prm_artifacts::{
    per::response_payload::PledgeEnrollRequest,
    pledge_info::PledgeInfo,
    token_type::{DataInterchangeFormat, CBOR, JSON},
};
use common::server_error::ServerError;
use tracing::{event, info};

use crate::{
    pledge_communicator::{DiscoveredPledge, PledgeCtx},
    server::server::ServerState,
};
use signeable_payload::signeable::{raw_signed::RawSigned, signed::Signed};

#[tracing::instrument(
    skip(state, pledge),
    target = "RegistrarAgent",
    name = "request_pledge_ctx"
)]
pub async fn request_pledge_ctx(
    state: &ServerState,
    pledge: &DiscoveredPledge,
) -> Result<PledgeCtx, ServerError> {
    info!(
        "Requesting data interchange format for pledge: {}",
        pledge.serial
    );
    let dif_str = state
        .communicator
        .get_data_interchange_format(pledge.clone())
        .await?;
    let dif = match dif_str.as_str() {
        JSON => DataInterchangeFormat::JSON,
        CBOR => DataInterchangeFormat::CBOR,
        _ => {
            return Err(ServerError::InternalError(anyhow!(
                "Invalid Data Interchange Format"
            )))
        }
    };

    info!(
        "Pledge {} has requested data interchange format: {}",
        pledge.serial, dif_str
    );
    info!("Requesting pledge info for pledge: {}", pledge.serial);

    let pledge_info = state
        .communicator
        .get_pledge_info(pledge.clone(), dif.clone())
        .await?;

    let deserialized: PledgeInfo = match dif {
        DataInterchangeFormat::JSON => serde_json::from_slice(&pledge_info)?,
        DataInterchangeFormat::CBOR => {
            ciborium::from_reader(pledge_info.as_slice()).map_err(|e| anyhow!(e))?
        }
    };

    info!("Received pledge info for pledge: {:?}", deserialized);

    let ctx: PledgeCtx = PledgeCtx {
        ctx: "".to_string(),
        pledge_serial: pledge.serial.clone(),
        pledge_url: pledge.url.clone(),
        pledge_info: deserialized,
    };

    Ok(ctx)
}
