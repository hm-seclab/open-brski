use core::str::FromStr;

use brski_prm_artifacts::ietf_voucher::pki::X509Req;
use sha2::{Digest, Sha256};

use p256::{
    ecdsa::{self, DerSignature},
    pkcs8::DecodePrivateKey,
    NistP256,
};

use tracing::info;
use x509_cert::{
    builder::{profile, AsyncBuilder, Builder, CertificateBuilder, RequestBuilder},
    ext::pkix::{
        name::{DirectoryString, GeneralName},
        SubjectAltName,
    },
    name::Name,
    request,
    serial_number::SerialNumber,
    time::Validity,
};

use x509_cert::{der::Encode, spki::DynAssociatedAlgorithmIdentifier};
fn ecdsa_signer(privkey: impl AsRef<[u8]>) -> p256::ecdsa::SigningKey {
    //let secret = p256::SecretKey::from_sec1_der(privkey.as_ref()).unwrap();
    info!("Loading private key from sec1 der");
    let secret_key = p256::SecretKey::from_pkcs8_der(privkey.as_ref()).unwrap();

    info!("Loaded Secret key");

    let pem = secret_key.to_sec1_pem(Default::default()).unwrap();

    let alg = secret_key.algorithm_identifier().unwrap();
    info!("Algorithm: {:?}", alg);

    info!("Building signing key");
    p256::ecdsa::SigningKey::from(secret_key)
}
pub fn create_csr(privkey: impl AsRef<[u8]>) -> X509Req {
    info!("Building subject");
    let subj_str = "CN=common_name,C=DE,ST=Bavaria,L=Munich,O=University of Applied Sciences Munich,OU=Department of Computer Science";
    info!("Subject: {:?}", subj_str);
    let subject = Name::from_str(&subj_str).unwrap();

    info!("Building CSR");
    let mut builder = RequestBuilder::new(subject).unwrap();

    info!("Building Signer");
    let signer = ecdsa_signer(privkey);

    info!("Signing CSR");
    let csr = builder.build::<_, DerSignature>(&signer).unwrap();

    let mut buf = vec![];
    csr.encode_to_vec(&mut buf).unwrap();

    let req = X509Req::try_from(buf).unwrap();
    req
}
