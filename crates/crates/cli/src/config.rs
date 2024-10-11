use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::cli::{Cli, OperatingMode};

pub use crate::{
    masa_config::MasaConfig, pledge_config::PledgeConfig,
    registrar_agent_config::RegistrarAgentConfig, registrar_config::RegistrarConfig,
};
use crate::{
    masa_config::NullableMasaConfig, pledge_config::NullablePledgeConfig,
    registrar_agent_config::NullableRegistrarAgentConfig,
    registrar_config::NullableRegistrarConfig, validate::Validate, Command,
};

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Config {
    pub registrar: RegistrarConfig,
    pub masa: MasaConfig,
    pub pledge: PledgeConfig,
    pub registrar_agent: RegistrarAgentConfig,
    pub operating_mode: OperatingMode,
}

impl Validate for Config {
    fn validate(&self) -> anyhow::Result<()> {
        match self.operating_mode {
            OperatingMode::Registrar => self.registrar.validate(),
            OperatingMode::Masa => self.masa.validate(),
            OperatingMode::Pledge => self.pledge.validate(),
            OperatingMode::RegistrarAgent => self.registrar_agent.validate(),
            OperatingMode::TestCerts => Ok(()),
            OperatingMode::None => Ok(()),
            OperatingMode::All => {
                self.registrar.validate()?;
                self.masa.validate()?;
                self.pledge.validate()?;
                self.registrar_agent.validate()
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NullableConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<NullableRegistrarConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masa: Option<NullableMasaConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pledge: Option<NullablePledgeConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar_agent: Option<NullableRegistrarAgentConfig>,
    operating_mode: OperatingMode,
}

impl Default for NullableConfig {
    fn default() -> Self {
        NullableConfig {
            registrar: None,
            masa: None,
            pledge: None,
            registrar_agent: None,
            operating_mode: OperatingMode::None,
        }
    }
}

impl From<Cli> for NullableConfig {
    fn from(value: Cli) -> Self {
        match value.command {
            Command::RegistrarAgent(conf) => NullableConfig {
                registrar_agent: Some(conf),
                operating_mode: OperatingMode::RegistrarAgent,
                ..Default::default()
            },
            Command::Registrar(conf) => NullableConfig {
                registrar: Some(conf),
                operating_mode: OperatingMode::Registrar,
                ..Default::default()
            },
            Command::Masa(conf) => NullableConfig {
                masa: Some(conf),
                operating_mode: OperatingMode::Masa,
                ..Default::default()
            },
            Command::Pledge(conf) => NullableConfig {
                pledge: Some(conf),
                operating_mode: OperatingMode::Pledge,
                ..Default::default()
            },
            Command::TestCerts => NullableConfig {
                operating_mode: OperatingMode::TestCerts,
                ..Default::default()
            },
            Command::All => NullableConfig {
                operating_mode: OperatingMode::All,
                ..Default::default()
            },
        }
    }
}
