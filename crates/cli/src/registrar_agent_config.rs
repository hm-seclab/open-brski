use crate::{util::parse_relative_path_buf, validate::Validate};
use anyhow::anyhow;
use clap::{arg, Args};
use figment::value::magic::RelativePathBuf;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistrarAgentConfig {
    pub port: String,
    pub bootstrap_serials: Vec<String>,
    pub autodiscover: bool,
    pub autodiscover_registrar: bool,
    pub use_tls: bool,
    pub ee_certificate: RelativePathBuf,
    pub ee_key: RelativePathBuf,
    pub registrar_certificate: RelativePathBuf,
    pub registrar_url: String,
}

impl Default for RegistrarAgentConfig {
    fn default() -> Self {
        Self {
            port: "3003".to_owned(),
            bootstrap_serials: vec![],
            autodiscover: false,
            use_tls: false,
            ee_certificate: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar-agent/ee_certificate.pem",
            ),
            ee_key: RelativePathBuf::from("/etc/open-brski/conf/registrar-agent/ee_privkey.key"),
            autodiscover_registrar: false,
            registrar_certificate: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar/ee_certificate.pem",
            ),
            registrar_url: "http://localhost:3001".to_owned(),
        }
    }
}

impl Validate for RegistrarAgentConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.port.is_empty() {
            return Err(anyhow!("Port cannot be empty".to_owned()));
        }

        if !self.ee_certificate.relative().exists() {
            return Err(anyhow!("ee_certificate is empty or not exist".to_owned()));
        }
        if !self.ee_key.relative().exists() {
            return Err(anyhow!("ee_privkey is empty or does not exist".to_owned()));
        }

        if !self.autodiscover_registrar && !self.registrar_certificate.relative().exists() {
            return Err(anyhow!("You need to either set autodiscover_registrar or provide the registrar's ee certificate".to_owned()));
        }

        if self.autodiscover_registrar {
            return Err(anyhow!(
                "autodiscover_registrar is not implemented yet".to_owned()
            ));
        }

        Ok(())
    }
}

#[derive(Args, Serialize, Deserialize)]
pub struct NullableRegistrarAgentConfig {
    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_serials: Option<Vec<String>>,
    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autodiscover: Option<bool>,
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autodiscover_registrar: Option<bool>,
    #[arg(short, long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_tls: Option<bool>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ee_certificate: Option<RelativePathBuf>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ee_key: Option<RelativePathBuf>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar_certificate: Option<RelativePathBuf>,
    #[arg(long)]
    #[clap(value_parser = parse_relative_path_buf)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar_url: Option<String>,
}
