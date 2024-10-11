use std::default;

use common::{error::AppError, server_error::ServerError};

use crate::{
    parsed_config::ParsedConfig,
    pledge_communicator::{DiscoveredPledge, PledgeCtx},
};

/// todo add discovery logic
///
///
pub async fn discover_pledges(
    _config: &ParsedConfig,
) -> Result<Vec<DiscoveredPledge>, ServerError> {
    Ok(vec![DiscoveredPledge {
        serial: "00-D0-E5-F2-00-02".to_string(),
        url: "http://0.0.0.0:3002".to_string(),
    }])
}
