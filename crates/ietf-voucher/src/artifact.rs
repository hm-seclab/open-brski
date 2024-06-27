use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde_with::serde_as;

use serde_with::base64::Base64;

use crate::assertion::Assertion;
use crate::error::VoucherError;
use crate::target::PledgeValidityInfo;
use crate::target::VoucherTarget;
use crate::verified::VerifiedVoucher;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct VoucherArtifact {
    #[serde(rename = "ietf-voucher:voucher")]
    pub details: VoucherArtifactDetails,
}

impl VoucherArtifact {
    #[cfg(feature = "openssl")]
    pub fn verify(self, verify_for: VoucherTarget) -> Result<VerifiedVoucher, VoucherError> {
        self.details.verify(verify_for)?;

        Ok(VerifiedVoucher(self))
    }
}

/// An unparsed voucher artifact which can be converted into a Voucher using the From trait
/// Read more in RFC 8366
#[cfg_eval]
#[cfg_attr(feature = "json", serde_as)]
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct VoucherArtifactDetails {
    /// A value indicating the date this voucher was created.
    /// This node is primarily for human consumption and auditing.
    pub created_on: Option<DateTime<Utc>>,

    /// A value indicating when this voucher expires.
    /// This attribute is optional, as not all pledges support expirations, such as pledges lacking a reliable clock.
    /// If this field exists, then the pledges MUST ensure that the expires-on time has not yet passed.
    /// A pledge without an accurate clock cannot meet this requirement.
    /// The expires-on value MUST NOT exceed the expiration date of any of the listed ’pinned-domain-cert’ certificates.
    pub expires_on: Option<DateTime<Utc>>,

    /// Indicates that the ownership has been positively verified by the MASA (e.g., through sales channel integration)."
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
    pub idevid_issuer: Option<Vec<u8>>,

    /// An X.509 v3 certificate structure, as specified by RFC 5280, using Distinguished Encoding Rules (DER) encoding, as defined in ITU-T X.690.
    /// This certificate is used by a pledge to trust a Public Key Infrastructure in order to verify a domain certificate supplied to the pledge separately by the bootstrapping protocol.
    /// The domain certificate MUST have this certificate somewhere in its chain of certificates.
    /// This certificate MAY be an end-entity certificate, including a self-signed entity.    
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub pinned_domain_cert: Option<crate::util::pki::X509>,

    /// A processing instruction to the pledge that it MUST (true) or MUST NOT (false) verify the revocation status for the pinned domain certificate.
    /// If this field is not set, then normal PKIX behavior applies to validation of the domain certificate.
    #[serde(default)]
    pub domain_cert_revocation_checks: bool,

    /// A value that can be used by a pledge in some bootstrapping protocols to enable anti-replay protection.
    /// This node is optional because it is not used by all bootstrapping protocols.
    /// When present, the pledge MUST compare the provided nonce value with another value that the pledge randomly generated and sent to a bootstrap server in an earlier bootstrapping message.
    /// If the values do not match, then the pledge MUST NOT process this voucher.

    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub nonce: Option<Vec<u8>>,

    /// The pinned-domain-pubk may replace the pinned-domain-cert in constrained uses of the voucher.
    /// The pinned-domain-pubk is the Raw Public Key of the Registrar.
    /// This field is encoded as a Subject Public Key Info block as specified in RFC7250, in section 3.
    /// The ECDSA algorithm MUST be supported. The EdDSA algorithm as specified in draft-ietf-tls-rfc4492bis-17 SHOULD be supported.
    /// Support for the DSA algorithm is not recommended. Support for the RSA algorithm is a MAY.
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub pinned_domain_pubk: Option<crate::util::pki::Pkey>,

    /// The pinned-domain-pubk-sha256 is a second alternative to pinned-domain-cert.
    /// In many cases the public key of the domain has already been transmitted during the key agreement process, and it is wastefu to transmit the public key another two times.
    /// The use of a hash of public key info, at 32-bytes for sha256 is a significant savings compared to an RSA public key, but is only a minor savings compared to a 256-bit ECDSA public-key.
    /// Algorithm agility is provided by extensions to this specification which can define a new leaf for another hash type.
    #[cfg_attr(feature = "json", serde_as(as = "Option<Base64>"))]
    pub pinned_domain_pubk_sha256: Option<Vec<u8>>,

    /// The date that the MASA projects to be the last date it will renew a voucher on.
    /// This field is merely informative; it is not processed by pledges.
    /// Circumstances may occur after a voucher is generated that may alter a voucher’s validity period.
    /// For instance, a vendor may associate validity periods with support contracts, which may be terminated or extended over time.
    pub last_renewal_date: Option<DateTime<Utc>>,

    // TODO convert to ietf:uri
    // The est-domain is a URL to which the Pledge should continue doing enrollment rather than with the Cloud Registrar.
    // The pinned-domain-cert contains a trust-anchor which is to be used to authenticate the server found at this URI
    pub est_domain: Option<String>,

    // TODO convert to ietf:uri
    // The additional-configuration attribute contains a URL to which the Pledge can retrieve additional configuration information.
    // The contents of this URL are vendor specific.
    // This is intended to do things like configure a VoIP phone to point to the correct hosted PBX, for example.
    pub additional_configuration: Option<String>,
}

impl std::fmt::Debug for VoucherArtifactDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoucherArtifactDetails")
            .field("created_on", &self.created_on)
            .field("expires_on", &self.expires_on)
            .field("assertion", &self.assertion)
            .field("serial_number", &self.serial_number)
            .field("idevid_issuer", &self.idevid_issuer)
            .field("pinned_domain_cert", &self.pinned_domain_cert)
            .field("domain_cert_revocation_checks", &self.domain_cert_revocation_checks)
            .field("nonce", &self.nonce)
            .field("pinned_domain_pubk", &self.pinned_domain_pubk)
            .field("pinned_domain_pubk_sha256", &self.pinned_domain_pubk_sha256)
            .field("last_renewal_date", &self.last_renewal_date)
            .field("est_domain", &self.est_domain)
            .field("additional_configuration", &self.additional_configuration)
            .finish()
    }
}

#[cfg(feature = "openssl")]
impl VoucherArtifactDetails {
    /// Verifies the voucher for the given target. Vouchers without expiry date *and* without nonces are valid in this context. MASA services must make sure to make an informed security decision.
    fn verify(&self, verify_for: VoucherTarget) -> Result<(), VoucherError> {
        if self.expires_on.is_some()
            && self.created_on.is_some()
            && self.expires_on < self.created_on
        {
            return Err(VoucherError::MalformedVoucher(
                "The expiry date must not be earlier than the creation date".to_string(),
            ));
        }

        // A voucher must never contain both epxires_on and a nonce
        if self.expires_on.is_some() && self.nonce.is_some() {
            return Err(VoucherError::MalformedVoucher(
                "There must not be both a nonce and an expiry date".to_string(),
            ));
        }

        // If the voucher is for a pledge and it features an expiry date, there must be a sufficient clock present.
        if cfg!(not(feature = "clock"))
            && self.expires_on.is_some()
            && matches!(verify_for, VoucherTarget::Pledge(_))
        {
            return Err(VoucherError::ClockRequired);
        }

        // If the pledge has a clock the expiry must not have passed.
        if cfg!(feature = "clock") && matches!(verify_for, VoucherTarget::Pledge(_)) {
            if let Some(expires_on) = self.expires_on {
                let time_now = chrono::Utc::now();
                // todo this is much too naive. We should check if the pledge has for example only seconds left...
                if expires_on < time_now {
                    return Err(VoucherError::ExpiredVoucher);
                }
            }
        }

        // only verify certificates if the openssl feature is passed
        self.verify_certificates()?;

        // There are currently only specific steps to be taken if the voucher is processed by a pledge.
        if let VoucherTarget::Pledge(ref pvi) = verify_for {
            self.verify_for_pledge(pvi)?;
        }

        Ok(())
    }

    fn verify_certificates(&self) -> Result<(), VoucherError> {
        // If the voucher artifact feature's an expiry date and a pinned domain cert, the expiry date must not exceed the expiry date of the pinned domain cert.
        if let (Some(expires_on), Some(pinned_domain_cert)) =
            (self.expires_on, &self.pinned_domain_cert)
        {
            let not_after_str = pinned_domain_cert.not_after().to_string();

            let parsed_time: DateTime<Utc> = chrono::DateTime::from_str(&not_after_str)
                .map_err(|_| VoucherError::InvalidExpiry)?;
            if expires_on < parsed_time {
                // this is not correct for now, we have to also consider the certificate chain
                return Err(VoucherError::InvalidExpiry);
            }
        }
        Ok(())
    }

    // Verifies the voucher for a pledge.
    fn verify_for_pledge(&self, pvi: &PledgeValidityInfo) -> Result<(), VoucherError> {
        if self.pinned_domain_cert.is_none() {
            return Err(VoucherError::MissingPinnedDomainCert);
        }

        // The voucher's serial must match the pledge's serial
        if pvi.serial != self.serial_number {
            return Err(VoucherError::SerialMismatch);
        }

        // If the voucher artifact features an idevid issuer field, the pledge must provide the idevid issuer auth key id for verification. This key should be present in its IdevID certificate.
        if self.idevid_issuer.is_some() && pvi.idevid_isser_kid.is_none() {
            return Err(VoucherError::IssuerKidRequired);
        }

        // We currently do not support revocation checks.
        if self.domain_cert_revocation_checks {
            todo!("Verifying the revocation status is a complex task and not implemented yet")
        }

        // If the voucher artifact features a nonce, the pledge must supply a nonce as well for verification proccesses.
        if self.nonce.is_some() && pvi.nonce.is_none() {
            return Err(VoucherError::NonceRequired);
        }

        // If both are present, the nonces must match.
        if let Some(nonce) = &self.nonce {
            if let Some(pvi_nonce) = pvi.nonce {
                // TODO not sure if this works!
                let converted_nonce: Vec<u8> = pvi_nonce.into();
                if *nonce != converted_nonce {
                    return Err(VoucherError::NonceMismatch);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{artifact::VoucherArtifact, assertion::Assertion};

    #[cfg(feature = "openssl")]
    #[cfg(feature = "json")]
    #[test]
    /// Tests an invalid voucher who has a nonce and an expires_on field
    fn invalid_voucher_nonce_and_expires() {
        use serde_json::json;

        let nonce = b"123";
        let base64_nonce = openssl::base64::encode_block(nonce);

        let voucher_json = json!({
            "ietf-voucher:voucher": {
                "serial-number": "JADA123456789",
                "nonce": base64_nonce,
                "expires-on": "2022-01-01T00:00:00.000Z"
            }
        });

        let deserialized = serde_json::to_string(&voucher_json).unwrap();

        let voucher_artifact = serde_json::from_str::<VoucherArtifact>(&deserialized).unwrap();

        let res = voucher_artifact.verify(super::VoucherTarget::Other);
        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "openssl")]
    #[cfg(feature = "json")]
    /// Tests an invalid voucher whose expires_on date is earlier than the created_on date
    fn test_invalid_voucher_dates() {
        let voucher_request_json = r#"
        {
            "ietf-voucher:voucher": {
                "serial-number": "JADA123456789", 
                "created-on": "2018-01-01T00:00:00.000Z",
                "expires-on": "2017-01-01T00:00:00.000Z"
            }
        }
       "#;

        let voucher_artifact =
            serde_json::from_str::<VoucherArtifact>(voucher_request_json).unwrap();

        let res = voucher_artifact.verify(super::VoucherTarget::Other);
        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "clock")]
    #[cfg(feature = "openssl")]
    #[cfg(feature = "json")]
    fn test_expires_on_in_the_past() {
        use crate::target::VoucherTarget;

        let voucher_request_json = r#"
        {
            "ietf-voucher:voucher": { 
                "serial-number": "JADA123456789",
                "expires-on": "1997-01-01T00:00:00.000Z"
            }
        }
       "#;

        let voucher_artifact =
            serde_json::from_str::<VoucherArtifact>(voucher_request_json).unwrap();

        let res = voucher_artifact.verify(VoucherTarget::Other);
        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "openssl")]
    #[cfg(not(feature = "clock"))]
    #[cfg(feature = "json")]
    fn test_feature_no_clock_error() {
        use crate::target::{PledgeValidityInfo, VoucherTarget};

        let voucher_request_json = r#"
        {
            "ietf-voucher:voucher": { 
                "serial-number": "JADA123456789",
                "expires-on": "2999-01-01T00:00:00.000Z"
            }
        }
       "#;

        let voucher_artifact =
            serde_json::from_str::<VoucherArtifact>(voucher_request_json).unwrap();

        let res = voucher_artifact.verify(VoucherTarget::Pledge(PledgeValidityInfo {
            serial: "JADA123456789",
            idevid_isser_kid: None,
            nonce: None,
        }));
        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "openssl")]
    #[cfg(feature = "json")]
    fn test_voucher_serializes_correctly() {
        let voucher = VoucherArtifact {
            details: VoucherArtifactDetails {
                assertion: Some(Assertion::Proximity),
                serial_number: "JADA123456789".to_string(),
                created_on: Some("2017-01-01T00:00:00.000Z".parse().unwrap()),
                expires_on: Some("2018-01-01T00:00:00.000Z".parse().unwrap()),
                idevid_issuer: None,
                pinned_domain_cert: None,
                domain_cert_revocation_checks: false,
                nonce: None,
                pinned_domain_pubk: None,
                pinned_domain_pubk_sha256: None,
                last_renewal_date: None,
                est_domain: None,
                additional_configuration: None,
            },
        };

        let serialized = serde_json::to_string(&voucher).unwrap();
        assert!(!serialized.is_empty());
        assert!(serialized.contains("JADA123456789"));
    }
}
