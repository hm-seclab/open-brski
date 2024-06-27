use rcgen::Certificate;
use rcgen::CertificateParams;

use rcgen::KeyPair;
use time::OffsetDateTime;

pub fn generate_owner_ca_cert(common_name: &str) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365);
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;

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

    params.use_authority_key_identifier_extension = true;

    params.distinguished_name = dn;
    // what
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    // key pair

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    (cert, key_pair)
}

pub fn generate_owner_cert(
    common_name: &str,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365);
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;

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
    // what
    params.is_ca = rcgen::IsCa::NoCa;

    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];

    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Other(
        [1, 3, 6, 1, 5, 5, 7, 3, 28].to_vec(),
    )];

    // key pair

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();

    (cert, key_pair)
}
