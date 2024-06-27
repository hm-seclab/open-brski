use crate::util::parse_relative_path_buf;
use anyhow::anyhow;
use clap::{arg, Args};
use figment::value::magic::RelativePathBuf;
use serde::{Deserialize, Serialize};

use crate::validate::Validate;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MasaConfig {
    pub port: String,
    pub ca_certificate: RelativePathBuf,
    pub ca_key: RelativePathBuf,
    pub masa_certificate: RelativePathBuf,
    pub masa_key: RelativePathBuf,
    pub registrar_ee_certificate: RelativePathBuf,
}
impl Validate for MasaConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.port.is_empty() {
            return Err(anyhow!("Port cannot be empty".to_owned()));
        }

        if !self.ca_certificate.relative().exists() {
            return Err(anyhow!("masa ca_certificate is empty or not exist".to_owned()));
        }

        if !self.ca_key.relative().exists() {
            return Err(anyhow!("masa ca_key is empty or not exist".to_owned()));
        }

        if !self.masa_certificate.relative().exists() {
            return Err(anyhow!("masa ee_certificate is empty or not exist".to_owned()));
        }

        if !self.masa_key.relative().exists() {
            return Err(anyhow!(" masa ee_key is empty or not exist".to_owned()));
        }
        if !self.registrar_ee_certificate.relative().exists() {
            return Err(anyhow!("registrar ee_certificate is empty or not exist".to_owned()));
        }
        Ok(())
    }
}

impl Default for MasaConfig {
    fn default() -> Self {
        Self {
            port: "3000".to_owned(),
            ca_certificate: RelativePathBuf::from(
                "/etc/open-brski/conf/masa/certificate-authority/vendor-ca.cert",
            ),
            ca_key: RelativePathBuf::from(
                "/etc/open-brski/conf/masa/certificate-authority/vendor-ca.key",
            ),
            masa_certificate: RelativePathBuf::from(
                "/etc/open-brski/conf/masa/signing-authority/vendor.cert",
            ),
            masa_key: RelativePathBuf::from("/etc/open-brski/conf/masa/signing-authority/vendor.key"),
            registrar_ee_certificate: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar/signing-authority/registrar.cert",
            ),
        }
    }
}

#[derive(Args, Serialize, Deserialize)]
pub struct NullableMasaConfig {
    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_certificate: Option<RelativePathBuf>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_key: Option<RelativePathBuf>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masa_certificate: Option<RelativePathBuf>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masa_key: Option<RelativePathBuf>,
}
