use core::{fmt::Display, ops::Deref};
use std::marker::PhantomData;

use crate::error::VoucherError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIs};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct AgentData {
    /// A value indicating the date this voucher was created.
    /// This node is primarily for human consumption and auditing.
    pub created_on: DateTime<Utc>,

    /// The serial-number of the hardware.
    /// When processing a voucher, a pledge MUST ensure that its serial-number matches this value.
    /// If no match occurs, then the pledge MUST NOT process this voucher.";
    pub serial_number: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AgentSignedData {
    #[serde(rename = "ietf-voucher-request-prm:agent-signed-data")]
    pub data: AgentData,
}

impl AgentSignedData {
    pub fn new(created_on: DateTime<Utc>, serial_number: String) -> Self {
        Self {
            data: AgentData {
                created_on,
                serial_number,
            },
        }
    }
}
