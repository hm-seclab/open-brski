use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct ReasonContext {
    pub pes_details: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct Status {
    pub version: u32,
    pub status: bool,
    pub reason: String,
    pub reason_context: ReasonContext,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            version: 1,
            status: true,
            reason: "Enroll-Response successfully processed".to_string(),
            reason_context: ReasonContext {
                pes_details: "JSON".to_string(),
            },
        }
    }
}
