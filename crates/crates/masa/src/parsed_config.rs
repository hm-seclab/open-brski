use anyhow::anyhow;
use cli::config::MasaConfig;
use common::error::AppError;
use openssl::{
    ec::{self, EcKey},
    pkey::{PKey, Private},
    x509::X509,
};

#[derive(Clone, Debug)]
pub(crate) struct ParsedConfig {
    pub(crate) config: MasaConfig,
    pub(crate) ca_certificate: X509,
    pub(crate) ca_key: Vec<u8>,
    pub(crate) masa_certificate: X509,
    pub(crate) masa_key: Vec<u8>,
}

pub(crate) fn parse_config(config: MasaConfig) -> anyhow::Result<ParsedConfig, AppError> {
    let unparsed_ca_cert = std::fs::read(config.ca_certificate.relative())?;
    let ca_certificate = X509::from_pem(&unparsed_ca_cert)?;

    let unparsed_ca_key = std::fs::read(config.ca_key.relative())?;
    let ca_key = ec::EcKey::private_key_from_pem(&unparsed_ca_key)?;
    let ca_key_pkcs8 = PKey::from_ec_key(ca_key)?.private_key_to_pkcs8()?;

    let unparsed_masa_cert = std::fs::read(config.masa_certificate.relative())?;
    let masa_certificate = X509::from_pem(&unparsed_masa_cert)?;

    let unparsed_masa_key = std::fs::read(config.masa_key.relative())?;
    let masa_key = ec::EcKey::private_key_from_pem(&unparsed_masa_key)?;
    let masa_key_pkcs8 = PKey::from_ec_key(masa_key)?.private_key_to_pkcs8()?;

    //assert!(masa_certificate.verify(&openssl::pkey::PKey::from_ec_key(ca_key.clone()).unwrap()).unwrap());
    //assert!(ca_certificate.verify(&openssl::pkey::PKey::from_ec_key(ca_key.clone()).unwrap()).unwrap());

    Ok(ParsedConfig {
        config,
        ca_certificate,
        ca_key: ca_key_pkcs8,
        masa_certificate,
        masa_key: masa_key_pkcs8,
    })
}
