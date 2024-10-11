use std::str::FromStr;

use rcgen::{Certificate, CertificateParams};

use rcgen::{Ia5String, KeyPair};
use time::OffsetDateTime;

pub fn generate_regagt_cert(
    common_name: &str,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + time::Duration::weeks(4);
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        Ia5String::from_str("BRSKI Registrar-Agent").unwrap(),
    )];

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name);
    dn.push(rcgen::DnType::CountryName, "DE");
    dn.push(rcgen::DnType::StateOrProvinceName, "Bavaria");
    dn.push(rcgen::DnType::LocalityName, "Munich");
    dn.push(
        rcgen::DnType::OrganizationName,
        "University of Applied Sciences Munich",
    );
    dn.push(
        rcgen::DnType::OrganizationalUnitName,
        "Department of Computer Science",
    );

    params.distinguished_name = dn;
    // TODO we currently *must* errorusly set this to include a CA, or rcgen will not include the subject key identifier...
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));

    // todo find out what OID enabled CMS signing
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::CodeSigning,
    ];

    // key pair

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();

    (cert, key_pair)
}
