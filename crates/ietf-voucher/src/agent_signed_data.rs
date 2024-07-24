#[cfg(feature = "jws")]
use josekit::jws::{self, JwsHeader, ES256};

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
pub struct Payload {
    #[serde(rename = "ietf-voucher-request-prm:agent-signed-data")]
    pub data: AgentData,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, EnumIs, Display)]
pub enum AgentSignedData {
    // This variant can not be serialized automatically. It can only be returned
    // from the decode API
    #[serde(skip)]
    Unsigned(Payload),
    Signed(String),
}

impl AgentSignedData {
    pub fn new(created_on: DateTime<Utc>, serial_number: impl Into<String>) -> Self {
        AgentSignedData::Unsigned(Payload {
            data: AgentData {
                created_on,
                serial_number: serial_number.into(),
            },
        })
    }
    #[cfg(feature = "jws")]
    // Encode AgentSignedData into String
    // Noop if it already is encoded
    pub fn sign(
        self,
        skid: impl Into<String>,
        keypair: impl AsRef<[u8]>,
    ) -> Result<AgentSignedData, VoucherError> {
        // noop if already encoded
        if let AgentSignedData::Signed(_) = self {
            return Ok(self);
        }

        let data = match self {
            AgentSignedData::Unsigned(data) => data,
            AgentSignedData::Signed(_) => unreachable!(),
        };

        let mut header = JwsHeader::new();
        header.set_token_type("JWT");

        let mut signer = ES256.signer_from_der(keypair)?;

        signer.set_key_id(skid);

        // this is NOT base64 encoded! It is a compact JWS! We must encode it later!
        let serialized = serde_json::to_vec(&data).map_err(|_| {
            VoucherError::MalformedAgentSignedData(
                "Could not serialize AgentSignedData".to_string(),
            )
        })?;

        let serialized_jws = jws::serialize_compact(&serialized, &header, &signer)?;

        Ok(AgentSignedData::Signed(serialized_jws))
    }

    #[cfg(feature = "jws")]
    // Decode into AgentSignedData if encoded. Noop if already decoded.
    pub fn verify(self, public_key: impl AsRef<[u8]>) -> Result<AgentSignedData, VoucherError> {
        // noop if already decoded
        if let AgentSignedData::Unsigned(_) = self {
            return Ok(self);
        }

        let data = match self {
            AgentSignedData::Signed(data) => data,
            AgentSignedData::Unsigned(_) => unreachable!(),
        };

        let verifier = ES256.verifier_from_der(public_key)?;

        let (data, _header) = jws::deserialize_compact(data, &verifier)?;

        let data: Payload = serde_json::from_slice(&data).map_err(|_| {
            VoucherError::MalformedAgentSignedData(
                "Could not deserialize AgentSignedData".to_string(),
            )
        })?;

        Ok(AgentSignedData::Unsigned(data))
    }
}

impl AsRef<[u8]> for AgentSignedData {
    fn as_ref(&self) -> &[u8] {
        match self {
            AgentSignedData::Unsigned(_) => unreachable!(), // Serde skips this variant, so it should never be reachable.
            AgentSignedData::Signed(data) => data.as_bytes(),
        }
    }
}

impl From<Vec<u8>> for AgentSignedData {
    fn from(data: Vec<u8>) -> Self {
        AgentSignedData::Signed(String::from_utf8_lossy(&data).to_string())
    }
}

#[cfg(test)]
#[cfg(feature = "openssl")]
#[cfg(feature = "jws")]
mod tests {
    use crate::error::VoucherError;

    use super::*;
    use example_certs::OpensslTestCerts;

    #[test]
    fn test_agent_signed_data_encode_decode_roundtrip() {
        use example_certs::generate_certs;

        let certs: OpensslTestCerts = generate_certs().into();

        let created_on = Utc::now();
        let serial_number = "123456".to_string();

        let data = AgentData {
            created_on,
            serial_number: serial_number.clone(),
        };

        let asd = AgentSignedData::Unsigned(Payload { data });

        let (reg_agt_ee_cert, reg_agt_ee_kp) = certs.registrar_agent.clone();

        let encoded_key = reg_agt_ee_kp.private_key_to_der().unwrap();

        let encoded = asd.sign("test".to_string(), encoded_key).unwrap();

        let _encoded_data = match encoded.clone() {
            AgentSignedData::Signed(data) => data,
            _ => unreachable!(),
        };

        // this should only work if the signature holds
        let decoded = encoded
            .verify(
                reg_agt_ee_cert
                    .public_key()
                    .unwrap()
                    .public_key_to_der()
                    .unwrap(),
            )
            .unwrap();

        assert!(matches!(decoded, AgentSignedData::Unsigned(_)));

        if let AgentSignedData::Unsigned(decoded_data) = decoded {
            assert_eq!(decoded_data.data.created_on, created_on);
            assert_eq!(decoded_data.data.serial_number, serial_number);
        }
    }

    #[test]
    fn test_invalid_encode_from_empty_keypair() {
        let created_on = Utc::now();
        let serial_number = "123456".to_string();

        let data = AgentData {
            created_on,
            serial_number: serial_number.clone(),
        };

        let asd = AgentSignedData::Unsigned(Payload { data });

        let encoded_key = vec![];

        let encoded = asd.sign("test".to_string(), encoded_key);

        assert!(matches!(encoded, Err(VoucherError::JWSError(_))));
    }

    #[test]
    fn test_decode_invalid_signature() {
        use example_certs::generate_certs;

        let certs: OpensslTestCerts = generate_certs().into();

        let created_on = Utc::now();
        let serial_number = "123456".to_string();

        let data = AgentData {
            created_on,
            serial_number: serial_number.clone(),
        };

        let asd = AgentSignedData::Unsigned(Payload { data });

        let (_reg_agt_ee_cert, reg_agt_ee_kp) = certs.registrar_agent.clone();

        let encoded_key = reg_agt_ee_kp.private_key_to_der().unwrap();

        let encoded = asd.sign("test".to_string(), encoded_key).unwrap();

        // this should only work if the signature holds
        let decoded = encoded
            .verify(
                certs
                    .pledge
                    .0
                    .public_key()
                    .unwrap()
                    .public_key_to_der()
                    .unwrap(),
            )
            .unwrap_err();

        assert!(matches!(decoded, VoucherError::JWSError(_)));
    }
}
