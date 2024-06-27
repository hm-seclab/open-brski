use cli::config::PledgeConfig;
use common::error::AppError;
use openssl::{
    ec::{self, EcKey},
    pkey::Private,
    x509::X509,
};

#[derive(Clone, Debug)]
pub(crate) struct ParsedConfig {
    pub(crate) config: PledgeConfig,
    pub(crate) idevid_certificate: X509,
    pub(crate) idevid_privkey: EcKey<Private>,
}

pub(crate) fn parse_config(config: PledgeConfig) -> anyhow::Result<ParsedConfig, AppError> {
    let unparsed_ee_key = std::fs::read(config.idevid_privkey.relative())?;
    let ee_key = ec::EcKey::private_key_from_pem(&unparsed_ee_key)?;

    let unparsed_idevid_cert = std::fs::read(config.idevid_certificate.relative())?;
    let idevid_cert = X509::from_pem(&unparsed_idevid_cert)?;
    Ok(ParsedConfig {
        config,
        idevid_certificate: idevid_cert,
        idevid_privkey: ee_key,
    })
}
