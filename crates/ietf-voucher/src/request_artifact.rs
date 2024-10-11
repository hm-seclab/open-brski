use core::fmt;

use chrono::{DateTime, Utc};
use serde_with::{base64::Base64, serde_as};
use signeable_payload::signeable::{raw_signed::RawSigned, signed::Signed};

use crate::{agent_signed_data::AgentSignedData, assertion::Assertion};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct VoucherRequestArtifact {
    #[serde(rename = "ietf-voucher-request:voucher")]
    pub details: VoucherRequestArtifactDetails,
}

/// An unparsed Voucher Request artifact as per RFC 8366. It is a superset of the voucher itself.
/// It provides content to the MASA for consideration during a voucher request.
//#[cfg_eval::cfg_eval]
#[cfg_eval]
#[cfg_attr(feature = "json", serde_as)]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct VoucherRequestArtifactDetails {
    /// A value indicating the date this voucher was created.
    /// This node is primarily for human consumption and auditing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_on: Option<DateTime<Utc>>,

    /// A value indicating when this voucher expires.
    /// This attribute is optional, as not all pledges support expirations, such as pledges lacking a reliable clock.
    /// If this field exists, then the pledges MUST ensure that the expires-on time has not yet passed.
    /// A pledge without an accurate clock cannot meet this requirement.
    /// The expires-on value MUST NOT exceed the expiration date of any of the listed ’pinned-domain-cert’ certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_on: Option<DateTime<Utc>>,

    /// Indicates that the ownership has been positively verified by the MASA (e.g., through sales channel integration)."
    /// This field should be ignored by the MASA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion: Option<Assertion>,

    /// The serial-number of the hardware.
    /// When processing a voucher, a pledge MUST ensure that its serial-number matches this value.
    /// If no match occurs, then the pledge MUST NOT process this voucher.";
    pub serial_number: String,

    /// The Authority Key Identifier OCTET STRING (as defined in Section 4.2.1.1 of RFC 5280) from the pledge’s IDevID certificate.
    /// Optional since some serial-numbers are already unique within the scope of a MASA.
    /// Inclusion of the statistically unique key identifier ensures statistically unique identification of the hardware.
    /// When processing a voucher, a pledge MUST ensure that its IDevID Authority Key Identifier matches this value.
    /// If no match occurs, then the pledge MUST NOT process this voucher.
    /// When issuing a voucher, the MASA MUST ensure that this field is populated for serial-numbers that are not otherwise unique within the scope of the MASA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idevid_issuer: Option<Vec<u8>>,

    /// A pinned domain certificate is not valid in a voucher equest, and any occurence must be ignored. To facilitate this, this field is non-public. It will also *not* be deserialized
    /// to save memory.
    #[serde(skip)]
    #[allow(dead_code)]
    pub(crate) pinned_domain_cert: Option<Vec<u8>>,

    /// The domain cert revocation checks field is not valid in a voucher request, and any occurence must be ignored. To facilitate this, this field is non-public. It will also *not* be deserialized
    #[serde(skip)]
    #[allow(dead_code)]
    pub(crate) domain_cert_revocation_checks: Option<bool>,

    /// A value that can be used by a pledge in some bootstrapping protocols to enable anti-replay protection.
    /// This node is optional because it is not used by all bootstrapping protocols.
    /// When present, the pledge MUST compare the provided nonce value with another value that the pledge randomly generated and sent to a bootstrap server in an earlier bootstrapping message.
    /// If the values do not match, then the pledge MUST NOT process this voucher.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub nonce: Option<Vec<u8>>,

    /// The pinned-domain-pubk may replace the pinned-domain-cert in constrained uses of the voucher.
    /// The pinned-domain-pubk is the Raw Public Key of the Registrar.
    /// This field is encoded as a Subject Public Key Info block as specified in RFC7250, in section 3.
    /// The ECDSA algorithm MUST be supported. The EdDSA algorithm as specified in draft-ietf-tls-rfc4492bis-17 SHOULD be supported.
    /// Support for the DSA algorithm is not recommended. Support for the RSA algorithm is a MAY.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub pinned_domain_pubk: Option<crate::util::pki::Pkey>,

    /// The pinned-domain-pubk-sha256 is a second alternative to pinned-domain-cert.
    /// In many cases the public key of the domain has already been transmitted during the key agreement process, and it is wastefu to transmit the public key another two times.
    /// The use of a hash of public key info, at 32-bytes for sha256 is a significant savings compared to an RSA public key, but is only a minor savings compared to a 256-bit ECDSA public-key.
    /// Algorithm agility is provided by extensions to this specification which can define a new leaf for another hash type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub pinned_domain_pubk_sha256: Option<[u8; 32]>,

    /// The last renewal date is not valid in a voucher request, and any occurence must be ignored. To facilitate this, this field is non-public.
    /// It will also *not* be deserialized to save memory.

    #[serde(skip)]
    #[allow(dead_code)]
    pub(crate) last_renewal_date: Option<DateTime<Utc>>,

    // TODO convert to ietf:uri
    // The est-domain is a URL to which the Pledge should continue doing enrollment rather than with the Cloud Registrar.
    // The pinned-domain-cert contains a trust-anchor which is to be used to authenticate the server found at this URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub est_domain: Option<String>,

    // TODO convert to ietf:uri
    // The additional-configuration attribute contains a URL to which the Pledge can retrieve additional configuration information.
    // The contents of this URL are vendor specific.
    // This is intended to do things like configure a VoIP phone to point to the correct hosted PBX, for example.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_configuration: Option<String>,

    /// If it is necessary to change a voucher, or re-sign and forward a voucher that was previously provided along a protocol path, then the previously signed voucher SHOULD be included in this field.
    ///
    /// For example, a pledge might sign a voucher request with a proximity-registrar-cert, and the registrar then includes it as the prior-signed-voucher-request field.
    /// This is a simple mechanism for a chain of trusted parties to change a voucher request, while maintaining the prior signature information.
    /// The Registrar and MASA MAY examine the prior signed voucher information for the purposes of policy decisions.
    ///
    /// For example this information could be useful to a MASA to determine that both pledge and registrar agree on proximity assertions.
    /// The MASA SHOULD remove all prior-signed-voucher-request information when signing a voucher for imprinting so as to minimize the final voucher size."
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_signed_voucher_request: Option<Vec<u8>>,

    /// An X.509 v3 certificate structure as specified by RFC 5280, Section 4 encoded using the ASN.1 distinguished encoding rules (DER), as specified in [ITU.X690.1994].
    /// The first certificate in the Registrar TLS server certificate_list sequence (the end-entity TLS certificate, see [RFC8446]) presented by the Registrar to the Pledge.
    /// This MUST be populated in a Pledge's voucher request when a proximity assertion is requested.";
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub proximity_registrar_cert: Option<crate::util::pki::X509>,

    /// The proximity-registrar-pubk replaces the proximity-registrar-cert in constrained uses of the voucher-request.
    /// The proximity-registrar-pubk is the Raw Public Key of the Registrar. This field is encoded as specified in RFC7250, section 3.
    /// The ECDSA algorithm MUST be supported. The EdDSA algorithm as specified in draft-ietf-tls-rfc4492bis-17 SHOULD be supported.
    /// Support for the DSA algorithm is not recommended. Support for the RSA algorithm is a MAY, but due to size is discouraged.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub proximity_registrar_pubk: Option<crate::util::pki::Pkey>,

    /// The proximity-registrar-pubk-sha256 is an alternative to both proximity-registrar-pubk and pinned-domain-cert.
    /// In many cases the public key of the domain has already been transmitted during the key agreement protocol, and it is wasteful to transmit the public key another two times.
    /// The use of a hash of public key info, at 32-bytes for sha256 is a significant savings compared to an RSA public key, but is only a minor savings compared to a 256-bit ECDSA public-key.
    /// Algorithm agility is provided by extensions to this specification which may define a new leaf for another hash type.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub proximity_registrar_pubk_sha256: Option<[u8; 32]>,

    /// The agent-signed-data field contains a JOSE [RFC7515] object provided by the Registrar-Agent to the Pledge.
    /// This artifact is signed by the Registrar-Agent and contains a copy of the pledge's serial-number.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub agent_signed_data: Option<RawSigned<AgentSignedData>>,

    /// An X.509 v3 certificate structure, as specified by RFC 5280, Section 4, encoded using the ASN.1 distinguished encoding rules (DER), as specified in ITU X.690.
    /// The first certificate in the registrar TLS server certificate_list sequence (the end-entity TLS certificate; see RFC 8446) presented by the registrar to the registrar-agent and provided to the pledge.
    /// This MUST be populated in a pledge's voucher-request when an agent-proximity assertion is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub agent_provided_proximity_registrar_cert: Option<crate::util::pki::X509>,

    /// An X.509 v3 certificate structure, as specified by RFC 5280, Section 4, encoded using the ASN.1 distinguished encoding rules (DER), as specified in ITU X.690.
    /// This certificate can be used by the pledge, the registrar, and the MASA to verify the signature of agent-signed-data.
    /// It is an optional component for the pledge-voucher request.
    /// This MUST be populated in a registrar's voucher-request when an agent-proximity assertion is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "json", serde_as(as = "Option<Vec<Base64>>"))]
    pub agent_sign_cert: Option<Vec<crate::util::pki::X509>>,
}

impl fmt::Debug for VoucherRequestArtifactDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VoucherRequestArtifactDetails")
            .field("created_on", &self.created_on)
            .field("expires_on", &self.expires_on)
            .field("assertion", &self.assertion)
            .field("serial_number", &self.serial_number)
            .field(
                "idevid_issuer",
                &format!(
                    "{} bytes",
                    self.idevid_issuer.as_ref().map(|v| v.len()).unwrap_or(0)
                ),
            )
            .field("pinned_domain_cert", &self.pinned_domain_cert)
            .field(
                "domain_cert_revocation_checks",
                &self.domain_cert_revocation_checks,
            )
            .field("nonce", &self.nonce)
            .field("pinned_domain_pubk", &format!("Private Key"))
            .field("pinned_domain_pubk_sha256", &self.pinned_domain_pubk_sha256)
            .field("last_renewal_date", &self.last_renewal_date)
            .field("est_domain", &self.est_domain)
            .field("additional_configuration", &self.additional_configuration)
            .field(
                "prior_signed_voucher_request",
                &format!(
                    "{} bytes",
                    self.prior_signed_voucher_request
                        .as_ref()
                        .map(|v| v.len())
                        .unwrap_or(0)
                ),
            )
            .field("proximity_registrar_cert", &self.proximity_registrar_cert)
            .field("proximity_registrar_pubk", &self.proximity_registrar_pubk)
            .field(
                "proximity_registrar_pubk_sha256",
                &self.proximity_registrar_pubk_sha256,
            )
            .field("agent_signed_data", &self.agent_signed_data)
            .field(
                "agent_provided_proximity_registrar_cert",
                &self.agent_provided_proximity_registrar_cert,
            )
            .field("agent_sign_cert", &self.agent_sign_cert)
            .finish()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg(feature = "openssl")]
    #[cfg(feature = "json")]
    /// the json in this test is taken from RFC BRSKI with pledge in responder mode
    #[test]
    fn test_rfc_deserialize() {
        use std::ops::Deref;

        use chrono::Datelike;

        let json = r#"
        {
            "ietf-voucher-request:voucher":{
               "assertion":"agent-proximity",
               "serial-number":"0123456789",
               "nonce":"L3IJ6hptHCIQoNxaab9HWA==",
               "created-on":"2022-04-26T05:16:17.709Z",
               "agent-provided-proximity-registrar-cert":"MIIB4jCCAYigAwIBAgIGAXY72bbZMAoGCCqGSM49BAMCMDUxEzARBgNVBAoMCk15QnVzaW5lc3MxDTALBgNVBAcMBFNpdGUxDzANBgNVBAMMBlRlc3RDQTAeFw0yMDEyMDcwNjE4MTJaFw0zMDEyMDcwNjE4MTJaMD4xEzARBgNVBAoMCk15QnVzaW5lc3MxDTALBgNVBAcMBFNpdGUxGDAWBgNVBAMMD0RvbWFpblJlZ2lzdHJhcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBk16K/i79oRkK5YbePg8USR8/us1dPUiZHMtokSdqKW5fnWsBd+qRL7WRffeWkygeboJfIllurci25wnhiOVCGjezB5MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDHDAOBgNVHQ8BAf8EBAMCB4AwSAYDVR0RBEEwP4IdcmVnaXN0cmFyLXRlc3Quc2llbWVucy1idC5uZXSCHnJlZ2lzdHJhci10ZXN0Ni5zaWVtZW5zLWJ0Lm5ldDAKBggqhkjOPQQDAgNIADBFAiBxldBhZq0Ev5JL2PrWCtyS6hDYW1yCO/RaubpC7MaIDgIhALSJbgLnghbbAg0dcWFUVo/gGN0/jwzJZ0Sl2h4xIXk1",
               "agent-signed-data":"eyJwYXlsb2FkIjoiZXlKcFpYUm1MWFp2ZFdOb1pYSXRjbVZ4ZFdWemRDMXdjbTA2WVdkbGJuUXRjMmxuYm1Wa0xXUmhkR0VpT25zaVkzSmxZWFJsWkMxdmJpSTZJakl3TWpJdE1EUXRNalpVTURVNk1EYzZOREV1TkRRNFdpSXNJbk5sY21saGJDMXVkVzFpWlhJaU9pSXdNVEl6TkRVMk56ZzVJbjE5Iiwic2lnbmF0dXJlcyI6W3sicHJvdGVjdGVkIjoiZXlKcmFXUWlPaUpZY0hwc1RVdDRiSEJCTmpoalZUVkdVVTFZVlhadVNWUTJVWGM5SWl3aVlXeG5Jam9pUlZNeU5UWWlmUSIsInNpZ25hdHVyZSI6IkczV3hGSGV0WFA4bGxSVi05dWJyTFlqSnZRYTZfeS1QalFZNE5hd1o5cFJhb2xOSm9ENmRlZWtuSV9FWGZzeVZTYnc4U0N6TVpMbjBhQXVoaUdZTjBRIn1dfQ==",
               "agent-sign-cert":[
                  "MIIB1DCCAXqgAwIBAgIEYmd4OTAKBggqhkjOPQQDAjA+MRMwEQYDVQQKDApNeUJ1c2luZXNzMQ0wCwYDVQQHDARTaXRlMRgwFgYDVQQDDA9UZXN0UHVzaE1vZGVsQ0EwHhcNMjIwNDI2MDQ0MjMzWhcNMzIwNDI2MDQ0MjMzWjA9MRMwEQYDVQQKDApNeUJ1c2luZXNzMQ0wCwYDVQQHDARTaXRlMRcwFQYDVQQDDA5SZWdpc3RyYXJBZ2VudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGxlrNfj3iRb7/BQodW+5YioOzh+jItyquRIO/Wz7YoW3iwDc3FxewLVfzCr5NvD13ZaFb7fran+t9otY5WLhJ6jZzBlMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBRvoT1ude2f6LEQhU7HHj+vJ/d7IzAdBgNVHQ4EFgQUXpzlMKxlpA68cU5FQMXUvnIT6QwwEwYDVR0lBAwwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIgc2y6xoOtoQBlJsglOL1VxHGosTypEqRfz0Qv4ZEPv4wCIQCVyb2F9zV3n95+olgfFJgZTWEz4dSaF3hzRQb3ZuB29Q==",
                  "MIIBzDCCAXGgAwIBAgIEXXjHpDAKBggqhkjOPQQDAjA1MRMwEQYDVQQKDApNeUJ1c2luZXNzMQ0wCwYDVQQHDARTaXRlMQ8wDQYDVQQDDAZUZXN0Q0EwHhcNMTkwOTExMTAwODM2WhcNMjkwOTExMTAwODM2WjA+MRMwEQYDVQQKDApNeUJ1c2luZXNzMQ0wCwYDVQQHDARTaXRlMRgwFgYDVQQDDA9UZXN0UHVzaE1vZGVsQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATlG0fwT33oezZ1vkHQbetebmj+BoV+ZFsjcfQw2TOkJPhOkOfAbu9bS1qZi8yaEV8oerKl/6ZXbfxOmBjrRrcXo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwICBDAfBgNVHSMEGDAWgBToZIMzQdsD/j/+gX/7cBJucH/XmjAdBgNVHQ4EFgQUb6E9bnXtn+ixEIVOxx4/ryf3eyMwCgYIKoZIzj0EAwIDSQAwRgIhAPnB0w1NCurhMxJwwfjz7gDiixkUYLPSZ9eN9kohNQUjAiEAw4Y7ltxWiPwKt1J9njyfDNl5MuEDBimxR3CXoZKGQrU="
               ]
            }
         }
        "#;

        let deserialized = serde_json::from_str::<VoucherRequestArtifact>(json).unwrap();

        assert_eq!(
            deserialized.details.assertion,
            Some(Assertion::AgentProximity)
        );
        assert_eq!(deserialized.details.serial_number, "0123456789");
        assert!(deserialized.details.created_on.is_some());
        assert!(deserialized.details.created_on.unwrap().day() == 26);
        assert!(deserialized.details.created_on.unwrap().month() == 4);
        assert!(deserialized.details.created_on.unwrap().year() == 2022);
        assert!(deserialized.details.agent_signed_data.is_some());
        assert!(deserialized
            .details
            .agent_provided_proximity_registrar_cert
            .is_some());

        assert!(deserialized
            .details
            .agent_provided_proximity_registrar_cert
            .unwrap()
            .deref()
            .subject_alt_names()
            .is_some());
    }
}
