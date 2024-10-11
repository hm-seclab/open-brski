use std::fmt;

use base64::Engine;
use serde::{Deserialize, Serialize};

use ietf_voucher::agent_signed_data::AgentSignedData;

use ietf_voucher::pki::X509;
use signeable_payload::signeable::{raw_signed::RawSigned, signed::Signed};

use crate::error::BRSKIPRMError;

#[cfg(feature = "json")]
use serde_with::serde_as;

// A pledge voucher request. You can not directly serialize this struct, you must first convert it to a RawPVR.
#[cfg_attr(feature = "json", serde_as)]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]

pub struct VoucherRequestTrigger {
    /// base-64 encoded registrar EE TLS certificate
    #[cfg_attr(feature = "json", serde_as(as = "Base64"))]
    pub agent_signed_proximity_cert: X509,

    #[cfg_attr(feature = "json", serde_as(as = "Base64"))]
    pub agent_signed_data: RawSigned<AgentSignedData>,
}

impl fmt::Display for VoucherRequestTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Trigger: agent_signed_proximity_cert: {}, agent_signed_data: {:?}",
            self.agent_signed_proximity_cert, self.agent_signed_data
        )
    }
}
