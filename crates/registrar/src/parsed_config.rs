use anyhow::anyhow;
use cli::config::{RegistrarConfig};
use common::error::AppError;
use openssl::ec::{self, EcKey};
use openssl::pkey::{Private};
use openssl::x509::X509;

#[derive(Clone, Debug)]
pub(crate) struct ParsedConfig {
    pub(crate) config: RegistrarConfig,
    pub(crate) ca_certificate: X509,
    pub(crate) ca_key: EcKey<Private>,
    pub(crate) registrar_certificate: X509,
    pub(crate) registrar_key: EcKey<Private>,
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

    let unparsed_registrar_cert = std::fs::read(config.registrar_certificate.relative())?;
    let registrar_certificate = X509::from_pem(&unparsed_registrar_cert)?;

    let unparsed_registrar_key = std::fs::read(config.registrar_key.relative())?;
    let registrar_key = ec::EcKey::private_key_from_pem(&unparsed_registrar_key)?;

    /// This registrar certificate must be signed by the CA certificate 
    assert!(registrar_certificate.verify(&openssl::pkey::PKey::from_ec_key(ca_key.clone()).unwrap()).unwrap());

    Ok(ParsedConfig {
        config,
        ca_certificate,
        ca_key,
        registrar_certificate,
        registrar_key,
        reg_agt_ee_cert,
        masa_url
    })
}
