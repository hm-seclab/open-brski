use anyhow::anyhow;
use cli::config::RegistrarAgentConfig;
use common::error::AppError;
use openssl::ec::{self, EcKey};
use openssl::pkey::{Private};
use openssl::x509::X509;

#[derive(Clone, Debug)]
pub(crate) struct ParsedConfig {
    pub(crate) config: RegistrarAgentConfig,
    pub(crate) ee_certificate: X509,
    pub(crate) ee_key: EcKey<Private>,
    pub(crate) registrar_certificate: X509,
}

pub(crate) fn parse_config(config: RegistrarAgentConfig) -> anyhow::Result<ParsedConfig, AppError> {
    let unparsed_ee_cert = std::fs::read(config.ee_certificate.relative())?;
    let ee_cert = X509::from_pem(&unparsed_ee_cert)?;

    if ee_cert.subject_key_id().is_none() {
        return Err(anyhow!(
            "RegAgt EE Certificate missing critical attribute SubjectKeyIdentifier"
        )
        .into());
    }

    let unparsed_ee_key = std::fs::read(config.ee_key.relative())?;
    let ee_key = ec::EcKey::private_key_from_pem(&unparsed_ee_key)?;

    let unparsed_reg_cert = std::fs::read(config.registrar_certificate.relative())?;
    let registrar_cert = X509::from_pem(&unparsed_reg_cert)?;

    let registrar_pubkey = registrar_cert.public_key()?;
    let result = ee_cert.verify(&registrar_pubkey).unwrap();
    if result == false {
        return Err(anyhow!("Unable to verify CA signage of RegAgt Certificate").into());
    }
    Ok(ParsedConfig {
        config,
        ee_certificate: ee_cert,
        ee_key,
        registrar_certificate: registrar_cert,
    })
}
