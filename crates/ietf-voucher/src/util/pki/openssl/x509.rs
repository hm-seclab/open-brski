use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// A wrapper around an X.509 certificate.
/// It will always be serialized by serde as a DER-encoded X.509 certificate.
/// To serialize it as a PEM-encoded X.509 certificate, use serde_as base64. This will convert the certificate to a PEM-encoded string and then base64 encode it.
#[derive(Clone, Eq)]
pub struct X509 {
    certificate: openssl::x509::X509,
    der: Vec<u8>,
}

impl std::fmt::Display for X509 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            String::from_utf8(self.certificate.to_pem().unwrap()).unwrap()
        )
    }
}

impl std::fmt::Debug for X509 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509")
            .field(
                "pem",
                &String::from_utf8(self.certificate.to_pem().unwrap())
                    .unwrap()
                    .replace("\n", ""),
            )
            .field(
                "der",
                &format!(
                    "DER-encoded X.509 certificate with length {}",
                    self.der.len()
                ),
            )
            .finish()
    }
}

impl From<openssl::x509::X509> for X509 {
    fn from(x509: openssl::x509::X509) -> Self {
        let der = x509.to_der().unwrap();

        X509 {
            certificate: x509,
            der,
        }
    }
}

impl Deref for X509 {
    type Target = openssl::x509::X509;

    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl Serialize for X509 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.der)
    }
}

impl<'de> Deserialize<'de> for X509 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let x509 = openssl::x509::X509::from_der(&bytes).map_err(serde::de::Error::custom)?;

        Ok(X509 {
            certificate: x509,
            der: bytes,
        })
    }
}

impl AsRef<[u8]> for X509 {
    fn as_ref(&self) -> &[u8] {
        &self.der
    }
}

impl TryFrom<Vec<u8>> for X509 {
    type Error = openssl::error::ErrorStack;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let x509 = openssl::x509::X509::from_der(&value)?;
        Ok(X509 {
            certificate: x509,
            der: value,
        })
    }
}

impl PartialEq for X509 {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use serde_with::serde_as;

    #[test]
    fn test_serialize_conversion_from_openssl_cert() {
        use example_certs::generate_certs;
        use example_certs::OpensslTestCerts;

        let certs: OpensslTestCerts = generate_certs().into();

        let (reg_agt_ee_cert, _) = certs.registrar_agent;

        let x509: super::X509 = reg_agt_ee_cert.clone().into();

        assert!(x509
            .public_key()
            .unwrap()
            .public_eq(&reg_agt_ee_cert.public_key().unwrap()));
    }

    #[test]
    fn test_serialize_as_der() {
        use example_certs::generate_certs;
        use example_certs::OpensslTestCerts;

        let certs: OpensslTestCerts = generate_certs().into();

        let (reg_agt_ee_cert, _) = certs.registrar_agent;

        let x509: super::X509 = reg_agt_ee_cert.clone().into();

        let serialized = serde_json::to_string(&x509).unwrap();
        let deserialized: super::X509 = serde_json::from_str(&serialized).unwrap();

        assert_eq!(x509.to_der().unwrap(), deserialized.to_der().unwrap());
    }

    #[test]
    fn test_serialize_as_base64_der() {
        use example_certs::generate_certs;
        use example_certs::OpensslTestCerts;
        use serde_with::base64::Base64;

        let certs: OpensslTestCerts = generate_certs().into();

        let (reg_agt_ee_cert, _) = certs.registrar_agent;

        let x509: super::X509 = reg_agt_ee_cert.clone().into();

        #[serde_as]
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Dummy {
            #[serde_as(as = "Base64")]
            x509: super::X509,
        }

        let serialized = serde_json::to_string(&Dummy { x509: x509.clone() }).unwrap();
        let deserialized: Dummy = serde_json::from_str(&serialized).unwrap();

        assert!(x509
            .public_key()
            .unwrap()
            .public_eq(&deserialized.x509.public_key().unwrap()));
    }

    #[test]
    fn deserialize_from_b64_der_json() {
        use example_certs::generate_certs;
        use example_certs::OpensslTestCerts;

        let certs: OpensslTestCerts = generate_certs().into();

        let (reg_agt_ee_cert, _) = certs.registrar_agent;

        let pem_b64 = reg_agt_ee_cert.to_der().unwrap();

        let encoded = openssl::base64::encode_block(&pem_b64);

        use serde_with::base64::Base64;

        let json = json!({
            "x509": encoded
        });

        #[serde_as]
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Dummy {
            #[serde_as(as = "Base64")]
            x509: super::X509,
        }

        let deserialized: Dummy = serde_json::from_value(json).unwrap();
        assert!(deserialized.x509.public_key().is_ok());
        assert_eq!(deserialized.x509, reg_agt_ee_cert.into());
    }
}
