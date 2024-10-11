use brski_prm_artifacts::{
    pledge_info::PledgeInfo,
    token_type::{DataInterchangeFormat, PlainTokenType, VoucherTokenType},
};
use cli::config::PledgeConfig;
use common::error::AppError;
use openssl::{
    ec::{self, EcKey},
    pkey::{HasPrivate, PKey, Private},
    x509::X509,
};
use tracing::info;

#[derive(Clone, Debug)]
pub(crate) struct ParsedConfig {
    pub(crate) config: PledgeConfig,
    pub(crate) idevid_certificate: X509,
    pub(crate) idevid_privkey: Vec<u8>,
    pub(crate) pledge_info: PledgeInfo,
}

#[tracing::instrument]
fn get_pledge_info() -> PledgeInfo {
    let res = PledgeInfo::simple_cbor();

    info!("Pledge info: {:?}", res);
    res
}

pub(crate) fn parse_config(config: PledgeConfig) -> anyhow::Result<ParsedConfig, AppError> {
    info!("Parsing config");
    let unparsed_ee_key = std::fs::read(config.idevid_privkey.relative())?;
    let ee_key = ec::EcKey::private_key_from_pem(&unparsed_ee_key)?;
    let ee_key = PKey::from_ec_key(ee_key)?;
    let ee_key = ee_key.private_key_to_pkcs8()?;

    let unparsed_idevid_cert = std::fs::read(config.idevid_certificate.relative())?;
    let idevid_cert = X509::from_pem(&unparsed_idevid_cert)?;
    Ok(ParsedConfig {
        config,
        idevid_certificate: idevid_cert,
        idevid_privkey: ee_key,
        pledge_info: get_pledge_info(),
    })
}
