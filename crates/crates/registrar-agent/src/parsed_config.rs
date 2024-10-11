use anyhow::anyhow;
use cli::config::RegistrarAgentConfig;
use common::error::AppError;
use openssl::{
    ec::{self, EcKey},
    pkey::{PKey, Private},
    x509::X509,
};

#[derive(Clone, Debug)]
pub struct ParsedConfig {
    pub config: RegistrarAgentConfig,
    pub ee_certificate: X509,
    pub ee_key: Vec<u8>,
    pub registrar_certificate: X509,
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
    let ee_key_pkcs8 = PKey::from_ec_key(ee_key)?.private_key_to_pkcs8()?;

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
        ee_key: ee_key_pkcs8,
        registrar_certificate: registrar_cert,
    })
}
