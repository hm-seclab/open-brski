use rcgen::Certificate;
use rcgen::CertificateParams;
use rcgen::Ia5String;
use rcgen::KeyPair;
use rcgen::SanType;
use rcgen::SerialNumber;
use time::OffsetDateTime;

///
/// Generate a self-signed certificate with a serial number as the common name and
/// a custom extension with the MASA URL
pub fn generate_idevid_cert(
    serial: &str,
    masa_url: &str,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365);
    params.serial_number = Some(SerialNumber::from_slice("1".as_bytes()));
    params.subject_alt_names = vec![SanType::DnsName(Ia5String::try_from(serial).unwrap())];

    // Create a custom DN type for "serial-number"
    let serial_number_dn_type = rcgen::DnType::from_oid(&[2, 5, 4, 5]);
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(serial_number_dn_type, serial);
    params.distinguished_name = dn;
    // what
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 5, 5, 7, 1, 32],
        masa_url.as_bytes().to_vec(),
    )];

    // key pair

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.signed_by(&key_pair, &ca_cert, &ca_key).unwrap();

    (cert, key_pair)
}
