use std::fmt;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

use ietf_voucher::agent_signed_data::AgentSignedData;

use ietf_voucher::pki::X509;

use crate::error::BRSKIPRMError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerOptions<'a> {
    agent_signed_proximity_cert: X509,
    private_key: &'a [u8],
    registrar_agent_ee_skid: &'a [u8],
    agent_signed_data: AgentSignedData,
}

impl<'a> TriggerOptions<'a> {
    pub fn new(
        agent_signed_proximity_cert: impl Into<X509>,
        private_key: &'a impl AsRef<[u8]>,
        registrar_agent_ee_skid: &'a impl AsRef<[u8]>,
        agent_signed_data: AgentSignedData,
    ) -> TriggerOptions<'a> {
        TriggerOptions {
            agent_signed_proximity_cert: agent_signed_proximity_cert.into(),
            private_key: private_key.as_ref(),
            registrar_agent_ee_skid: registrar_agent_ee_skid.as_ref(),
            agent_signed_data,
        }
    }
}

impl TryFrom<TriggerOptions<'_>> for Trigger {
    type Error = BRSKIPRMError;

    fn try_from(value: TriggerOptions) -> Result<Self, Self::Error> {
        // we need to base64 encode it as per spec
        let skid_str =
            base64::engine::general_purpose::URL_SAFE.encode(value.registrar_agent_ee_skid);

        let encoded_data = value
            .agent_signed_data
            .encode(skid_str, value.private_key)
            .map_err(|e| BRSKIPRMError::Malformed(e.to_string()))?;

        Ok(Self {
            agent_signed_proximity_cert: value.agent_signed_proximity_cert,
            agent_signed_data: encoded_data,
        })
    }
}

// A pledge voucher request. You can not directly serialize this struct, you must first convert it to a RawPVR.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]

pub struct Trigger {
    /// base-64 encoded registrar EE TLS certificate
    #[serde_as(as = "Base64")]
    pub agent_signed_proximity_cert: X509,

    #[serde_as(as = "Base64")]
    pub agent_signed_data: AgentSignedData,
}

impl fmt::Display for Trigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Trigger: agent_signed_proximity_cert: {}, agent_signed_data: {}",
            self.agent_signed_proximity_cert, self.agent_signed_data
        )
    }
}

#[cfg(test)]

mod tests {
    use chrono::Utc;
    use example_certs::OpensslTestCerts;
    

    use super::*;

    #[cfg(feature = "openssl")]
    #[test]
    fn test_serialize_deserialize_rountrip() {
        let certs: OpensslTestCerts = example_certs::generate_certs().into();

        let (registrar_ee_cert, registrar_ee_kp) = certs.registrar;
        let (registrar_agent_ee_cert, _registrar_agent_ee_kp) = certs.registrar_agent;

        let reg_agt_ee_skid = registrar_agent_ee_cert.subject_key_id().unwrap();
        let reg_agt_ee_skid = reg_agt_ee_skid.as_slice();

        let created_on = Utc::now();
        let serial_number = "123456".to_string();

        let agent_signed_data = AgentSignedData::new(created_on, serial_number);

        let registrar_ee_kp = registrar_ee_kp.private_key_to_der().unwrap();

        let trigger_options = TriggerOptions::new(
            registrar_ee_cert,
            &registrar_ee_kp,
            &reg_agt_ee_skid,
            agent_signed_data,
        );

        let pvr: Trigger = trigger_options.try_into().unwrap();

        let serialized = serde_json::to_string(&pvr).unwrap();
        let deserialized: Trigger = serde_json::from_str(&serialized).unwrap();

        assert_eq!(pvr, deserialized);
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn test_validation_roundtrip() {
        let certs: OpensslTestCerts = example_certs::generate_certs().into();

        let (reg_agt_ee_cert, reg_agt_ee_kp) = certs.registrar;
        let (registrar_agent_ee_cert, _registrar_agent_ee_kp) = certs.registrar_agent;

        let reg_agt_ee_skid = registrar_agent_ee_cert.subject_key_id().unwrap();
        let reg_agt_ee_skid = reg_agt_ee_skid.as_slice();
        let created_on = Utc::now();
        let serial_number = "123456".to_string();

        let agent_signed_data = AgentSignedData::new(created_on, serial_number.clone());

        let registrar_ee_kp = reg_agt_ee_kp.private_key_to_der().unwrap();

        let trigger_options = TriggerOptions::new(
            reg_agt_ee_cert.clone(),
            &registrar_ee_kp,
            &reg_agt_ee_skid,
            agent_signed_data,
        );

        let pvr: Trigger = trigger_options.try_into().unwrap();

        let serialized = serde_json::to_string(&pvr).unwrap();

        println!("{}", serialized);
        let deserialized: Trigger = serde_json::from_str(&serialized).unwrap();

        assert_eq!(pvr, deserialized);

        let pubk = reg_agt_ee_cert.public_key().unwrap();

        let decoded_agent_signed_data = pvr
            .agent_signed_data
            .decode(pubk.public_key_to_der().unwrap())
            .unwrap();
        assert!(decoded_agent_signed_data.is_decoded());

        let inner_data = match decoded_agent_signed_data {
            AgentSignedData::Decoded(d) => d,
            _ => panic!("Expected decoded data"),
        };

        assert!(inner_data.data.created_on == created_on);
        assert!(inner_data.data.serial_number == serial_number);
    }
}
