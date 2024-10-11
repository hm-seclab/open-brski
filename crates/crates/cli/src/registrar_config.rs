use crate::util::parse_relative_path_buf;
use anyhow::anyhow;
use clap::Args;
use figment::value::magic::RelativePathBuf;
use serde::{Deserialize, Serialize};

use crate::validate::Validate;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct RegistrarConfig {
    pub port: String,
    pub ca_certificate: RelativePathBuf,
    pub ca_key: RelativePathBuf,
    pub registrar_certificate: RelativePathBuf,
    pub registrar_key: RelativePathBuf,
    pub reg_agt_ee_cert: RelativePathBuf,
    pub masa_url: String,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        Self {
            port: "3001".to_owned(),
            reg_agt_ee_cert: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar-agent/ee_certificate.cert",
            ),
            ca_certificate: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar/certificate-authority/registrar-ca.cert",
            ),
            ca_key: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar/certificate-authority/registrar-ca.key",
            ),
            registrar_certificate: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar/signing-authority/registrar.cert",
            ),
            registrar_key: RelativePathBuf::from(
                "/etc/open-brski/conf/registrar/signing-authority/registrar.key",
            ),
            masa_url: "http://localhost:3000".to_owned(),
        }
    }
}

impl Validate for RegistrarConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if self.port.is_empty() {
            return Err(anyhow!("Port cannot be empty".to_owned()));
        }

        if !self.ca_certificate.relative().exists() {
            return Err(anyhow!("ee_certificate is empty or not exist".to_owned()));
        }

        if !self.ca_key.relative().exists() {
            return Err(anyhow!("ee_certificate is empty or not exist".to_owned()));
        }

        if !self.registrar_certificate.relative().exists() {
            return Err(anyhow!("ee_certificate is empty or not exist".to_owned()));
        }

        if !self.registrar_key.relative().exists() {
            return Err(anyhow!("ee_certificate is empty or not exist".to_owned()));
        }
        Ok(())
    }
}

#[derive(Args, Serialize, Deserialize, Debug)]
pub struct NullableRegistrarConfig {
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
