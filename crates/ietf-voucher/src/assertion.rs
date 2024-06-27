use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Assertion {
    /// Indicates that the voucher has been issued after minimal verification of ownership or control.
    /// The issuance has been logged for detection of potential security issues (e.g., recipients of vouchers might verify for themselves that unexpected vouchers are not in the log).
    /// This is similar to unsecured trust-on-first-use principles but with the logging providing a basis for detecting unexpected events.
    Logged,

    /// Indicates that the ownership has been positively verified by the MASA (e.g., through sales channel integration).
    Verified,

    /// Indicates that the voucher has been issued after the MASA verified a proximity proof provided by the device and target domain.
    /// The issuance has been logged for detection of potential security issues.
    Proximity,

    /// Mostly identical to proximity, but indicates that the voucher has been issued after the MASA has verified a statement that a registrar agent has made contact with the device.
    AgentProximity,
}
