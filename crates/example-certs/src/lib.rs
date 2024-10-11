use std::{fs, path::PathBuf};

mod masa_cert;
mod pledge_cert;
mod registrar_agent_cert;
mod registrar_cert;

pub struct TestCerts {
    pub vendor_ca: (rcgen::Certificate, rcgen::KeyPair),
    pub vendor: (rcgen::Certificate, rcgen::KeyPair),
    pub registrar_ca: (rcgen::Certificate, rcgen::KeyPair),
    pub registrar: (rcgen::Certificate, rcgen::KeyPair),
    pub registrar_agent: (rcgen::Certificate, rcgen::KeyPair),
    pub pledge: (rcgen::Certificate, rcgen::KeyPair),
}

#[cfg(feature = "openssl")]
pub struct OpensslTestCerts {
    pub vendor_ca: (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ),
    pub vendor: (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ),
    pub registrar_ca: (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ),
    pub registrar: (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ),
    pub registrar_agent: (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ),
    pub pledge: (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ),
}

fn serialize_certpair(name: &str, path: &PathBuf, pair: &(rcgen::Certificate, rcgen::KeyPair)) {
    let cert = pair.0.pem();
    let key = pair.1.serialize_pem();

    let cert_path = path.join(format!("{}.cert", name));

    let key_path = path.join(format!("{}.key", name));

    fs::write(cert_path, cert).unwrap();
    fs::write(key_path, key).unwrap();
}

pub fn serialize_certs(certs: TestCerts, path: PathBuf) {
    serialize_certpair(
        "vendor-ca",
        &path.join("masa/certificate-authority"),
        &certs.vendor_ca,
    );
    serialize_certpair(
        "vendor",
        &path.join("masa/signing-authority"),
        &certs.vendor,
    );
    serialize_certpair(
        "registrar-ca",
        &path.join("registrar/certificate-authority"),
        &certs.registrar_ca,
    );
    serialize_certpair(
        "registrar",
        &path.join("registrar/signing-authority"),
        &certs.registrar,
    );
    serialize_certpair(
        "registrar-agent",
        &path.join("registrar-agent"),
        &certs.registrar_agent,
    );
    serialize_certpair("pledge", &path.join("pledge"), &certs.pledge);
}

pub fn generate_certs() -> TestCerts {
    let (vendor_ca_cert, vendor_ca_keypair) =
        masa_cert::generate_vendor_ca_cert("masa-ca.example.com CA");
    let (vendor_cert, vendor_keypair) = masa_cert::generate_vendor_cert(
        "masa-ca.example.com MASA",
        &vendor_ca_cert,
        &vendor_ca_keypair,
    );
    let (registrar_ca_cert, registrar_ca_keypair) =
        registrar_cert::generate_owner_ca_cert("registrar-ca.example.com Root CA");
    let (registrar_cert, registrar_keypair) = registrar_cert::generate_owner_cert(
        "registrar.example.com",
        &registrar_ca_cert,
        &registrar_ca_keypair,
    );
    let (ra_cert, ra_keypair) = registrar_agent_cert::generate_regagt_cert(
        "registrar-agent.example.com",
        &registrar_ca_cert,
        &registrar_ca_keypair,
    );
    let (idevid_cert, idevid_key) = pledge_cert::generate_idevid_cert(
        "00-D0-E5-F2-00-02",
        "localhost:3000",
        &vendor_ca_cert,
        &vendor_ca_keypair,
    );

    TestCerts {
        vendor_ca: (vendor_ca_cert, vendor_ca_keypair),
        vendor: (vendor_cert, vendor_keypair),
        registrar_ca: (registrar_ca_cert, registrar_ca_keypair),
        registrar: (registrar_cert, registrar_keypair),
        registrar_agent: (ra_cert, ra_keypair),
        pledge: (idevid_cert, idevid_key),
    }
}

#[cfg(feature = "openssl")]
fn convert_pair(
    (cert, key): (rcgen::Certificate, rcgen::KeyPair),
) -> (
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    let cert = openssl::x509::X509::from_pem(cert.pem().as_bytes()).unwrap();
    // generate keypair
    let key = openssl::pkey::PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap();
    (cert, key)
}

#[cfg(feature = "openssl")]
impl From<TestCerts> for OpensslTestCerts {
    fn from(value: TestCerts) -> Self {
        OpensslTestCerts {
            vendor_ca: convert_pair(value.vendor_ca),
            vendor: convert_pair(value.vendor),
            registrar_ca: convert_pair(value.registrar_ca),
            registrar: convert_pair(value.registrar),
            registrar_agent: convert_pair(value.registrar_agent),
            pledge: convert_pair(value.pledge),
        }
    }
}
