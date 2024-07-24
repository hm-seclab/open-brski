use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

use crate::{
    config::NullableConfig, masa_config::NullableMasaConfig, pledge_config::NullablePledgeConfig, registrar_agent_config::NullableRegistrarAgentConfig, registrar_config::NullableRegistrarConfig
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    RegistrarAgent(NullableRegistrarAgentConfig),
    Registrar(NullableRegistrarConfig),
    Masa(NullableMasaConfig),
    Pledge(NullablePledgeConfig),

    All,
    TestCerts,
}
#[derive(Serialize, Deserialize, Default, Debug)]
pub enum OperatingMode {
    RegistrarAgent,
    Registrar,
    Masa,
    Pledge,
    TestCerts,
    All,
    #[default] None,
}