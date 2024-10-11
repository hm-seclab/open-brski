use anyhow::anyhow;
use brski_prm_artifacts::ietf_voucher::pki::Pkey;
use cli::config::RegistrarConfig;
use common::error::AppError;
use openssl::{
    ec::{self, EcKey},
    pkey::{PKey, Private},
    x509::X509,
};

#[derive(Clone, Debug)]
pub(crate) struct ParsedConfig {
    pub(crate) config: RegistrarConfig,
    pub(crate) ca_certificate: X509,
    pub(crate) ca_key: Vec<u8>,
    pub(crate) registrar_certificate: X509,
    pub(crate) registrar_key: Vec<u8>,
    pub(crate) reg_agt_ee_cert: X509,
    pub(crate) masa_url: String,
}

pub(crate) fn parse_config(config: RegistrarConfig) -> anyhow::Result<ParsedConfig, AppError> {
    let masa_url = config.masa_url.clone();

    let unparsed_reg_agt_ee_cert = std::fs::read(config.reg_agt_ee_cert.relative())?;
    let reg_agt_ee_cert = X509::from_pem(&unparsed_reg_agt_ee_cert)?;

    let unparsed_ca_cert = std::fs::read(config.ca_certificate.relative())?;
    let ca_certificate = X509::from_pem(&unparsed_ca_cert)?;

    if ca_certificate.subject_key_id().is_none() {
        return Err(anyhow!(
            "RegAgt EE Certificate missing critical attribute SubjectKeyIdentifier"
        )
        .into());
    }

    let unparsed_ca_key = std::fs::read(config.ca_key.relative())?;
    let ca_key = ec::EcKey::private_key_from_pem(&unparsed_ca_key)?;
    let ca_key_pkcs8 = PKey::from_ec_key(ca_key.clone())?.private_key_to_pkcs8()?;

    let unparsed_registrar_cert = std::fs::read(config.registrar_certificate.relative())?;
    let registrar_certificate = X509::from_pem(&unparsed_registrar_cert)?;

    let unparsed_registrar_key = std::fs::read(config.registrar_key.relative())?;
    let registrar_key = ec::EcKey::private_key_from_pem(&unparsed_registrar_key)?;
    let registrar_key_pkcs8 = PKey::from_ec_key(registrar_key.clone())?.private_key_to_pkcs8()?;

    /// This registrar certificate must be signed by the CA certificate
    assert!(registrar_certificate
        .verify(&openssl::pkey::PKey::from_ec_key(ca_key.clone()).unwrap())
        .unwrap());

    Ok(ParsedConfig {
        config,
        ca_certificate,
        ca_key: ca_key_pkcs8,
        registrar_certificate,
        registrar_key: registrar_key_pkcs8,
        reg_agt_ee_cert,
        masa_url,
    })
}
