mod cli;
pub mod config;
mod layering;
mod masa_config;
mod pledge_config;
mod registrar_agent_config;
mod registrar_config;
mod util;
mod validate;

pub use cli::Command;

use clap::Parser;
use cli::Cli;
use common::error::AppError;
use config::Config;
use layering::get_layered_configs;

pub fn parse_args() -> Cli {
    Cli::parse()
}

pub fn get_config() -> anyhow::Result<Config, AppError> {
    let config = get_layered_configs()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]

    fn it_correctly_sets_defaults() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Config.toml",
                r#"
                [registrar]
                port = "8080"
            "#,
            )?;

            let config = get_config().unwrap();

            assert_eq!(config.registrar.port, "8080");
            assert_eq!(config.masa.port, "3000");
            assert_eq!(config.pledge.port, "3002");
            assert_eq!(config.pledge.idev_id, "example-pledge-id");

            Ok(())
        })
    }

    #[test]
    fn it_parses_the_complete_config() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Config.toml",
                r#"
                [registrar]
                port = "8080"
                [masa]
                port = "8081"
                [pledge]
                port = "8082"
                idev_id = "example" 
                [registrar_agent]
                port = "8083"
                bootstrap_serials = ["example"]
                autodiscover = true
                use_tls = true
            "#,
            )?;

            let config = get_config().unwrap();

            assert_eq!(config.registrar.port, "8080");
            assert_eq!(config.masa.port, "8081");
            assert_eq!(config.pledge.port, "8082");
            assert_eq!(config.pledge.idev_id, "example");
            assert_eq!(config.registrar_agent.port, "8083");
            assert_eq!(config.registrar_agent.bootstrap_serials, vec!["example"]);
            assert!(config.registrar_agent.autodiscover);
            assert!(config.registrar_agent.use_tls);

            Ok(())
        });
    }

    #[test]
    fn it_parses_incomplete_config() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Config.toml",
                r#"
                [registrar]
                port = "8080"
            "#,
            )?;

            let config = get_config().unwrap();

            assert_eq!(config.registrar.port, "8080");

            Ok(())
        })
    }
}
