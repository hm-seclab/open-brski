use rcgen::Certificate;
use rcgen::CertificateParams;
use rcgen::KeyPair;
use time::OffsetDateTime;

///
/// Generate a self-signed certificate with a serial number as the common name and
/// a custom extension with the MASA URL
pub fn generate_vendor_ca_cert(common_name: &str) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc().replace_year(2999).unwrap();
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;

    // Create a custom DN type for "serial-number"

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name);
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

pub fn generate_vendor_cert(
    common_name: &str,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc().replace_year(2999).unwrap();
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;

    // Create a custom DN type for "serial-number"

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name);
    params.distinguished_name = dn;
    // what
    params.is_ca = rcgen::IsCa::ExplicitNoCa;

    // key pair

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();

    (cert, key_pair)
}
