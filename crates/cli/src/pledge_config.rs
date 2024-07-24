use crate::util::parse_relative_path_buf;
use crate::validate::Validate;
use anyhow::anyhow;
use clap::Args;
use figment::value::magic::RelativePathBuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PledgeConfig {
    pub port: String,
    pub idev_id: String,
    pub idevid_certificate: RelativePathBuf,
    pub idevid_privkey: RelativePathBuf,
}

impl Validate for PledgeConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.port.is_empty() {
            return Err(anyhow!("Port cannot be empty".to_owned()));
        }
        if self.idev_id.is_empty() {
            return Err(anyhow!("idev_id cannot be empty".to_owned()));
        }

        if !self.idevid_certificate.relative().exists() {
            return Err(anyhow!("idevid_certificate does not exist".to_owned()));
        }

        if !self.idevid_privkey.relative().exists() {
            return Err(anyhow!("idevid_privkey does not exist".to_owned()));
        }
        Ok(())
    }
}

impl Default for PledgeConfig {
    fn default() -> Self {
        Self {
            port: "3002".to_owned(),
            idev_id: "example-pledge-id".to_owned(),
            idevid_certificate: RelativePathBuf::from(
                "/etc/open-brski/conf/pledge/idevid_certificate.pem",
            ),
            idevid_privkey: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar-agent/idevid_privkey.key",
            ),
        }
    }
}

#[derive(Args, Serialize, Deserialize, Debug)]
pub struct NullablePledgeConfig {
    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idev_id: Option<String>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idevid_certificate: Option<RelativePathBuf>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idevid_privkey: Option<RelativePathBuf>,
}
