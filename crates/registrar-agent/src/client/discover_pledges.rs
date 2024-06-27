use common::error::AppError;

use crate::parsed_config::ParsedConfig;

/// todo add discovery logic
pub async fn discover_pledges(_config: &ParsedConfig) -> Result<Vec<(&str, &str)>, AppError> {
    Ok(vec![("http://0.0.0.0:3002", "00-D0-E5-F2-00-02")])
}
