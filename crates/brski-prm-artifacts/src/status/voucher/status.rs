use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct ReasonContext {
    pub pvs_details: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct VoucherStatus {
    pub version: u32,
    pub status: bool,
    pub reason: Option<String>,
    pub reason_context: ReasonContext,
}

impl Default for VoucherStatus {
    fn default() -> Self {
        Self {
            version: 1,
            status: true,
            reason: None,
            reason_context: ReasonContext {
                pvs_details: "".to_string(),
            },
        }
    }
}
