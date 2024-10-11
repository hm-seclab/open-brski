use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct QueryContext {
    pub pvs_details: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct PledgeStatusQuery {
    pub version: u32,
    pub status: bool,
    pub reason: Option<String>,
    pub reason_context: QueryContext,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PledgeStatusDetails {
    FactoryDefault,
    VoucherSuccess,
    VoucherError,
    EnrollSuccess,
    EnrollError,
    ConnectSuccess,
    ConnectError,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct StatusContext {
    pub pvs_details: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct PledgeStatus {
    pub version: u32,
    pub status: PledgeStatusDetails,
    pub reason: Option<String>,
    pub reason_context: Option<StatusContext>,
}

impl Default for PledgeStatus {
    fn default() -> Self {
        Self {
            version: 1,
            status: PledgeStatusDetails::FactoryDefault,
            reason: None,
            reason_context: None,
        }
    }
}
