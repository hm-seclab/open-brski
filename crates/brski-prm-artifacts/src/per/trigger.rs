use core::fmt;

use serde::{Deserialize, Serialize};
use strum::Display;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Display)]
pub enum PEREnrollType {
    #[serde(rename = "enroll-generic-cert")]
    EnrollGenericCert,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub struct Trigger {
    enroll_type: PEREnrollType,
}

impl fmt::Display for Trigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Trigger: enroll_type: {}", self.enroll_type)
    }

}

impl Default for Trigger {
    fn default() -> Self {
        Trigger {
            enroll_type: PEREnrollType::EnrollGenericCert,
        }
    }
}
