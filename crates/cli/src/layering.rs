use crate::{
    cli::Cli,
    config::{Config, NullableConfig},
    validate::Validate,
};
use clap::Parser;
use figment::{
    providers::{Format, Serialized, Toml},
    Figment,
};

pub fn get_layered_configs() -> anyhow::Result<Config> {
    let cli_config: Option<Cli> = Cli::try_parse().ok();
    let config = get_layered_configs_from_cli_config(cli_config)?;
    Ok(config)
}

fn get_layered_configs_from_cli_config(cli_config: Option<Cli>) -> anyhow::Result<Config> {
    let defaults = Figment::from(Serialized::defaults(Config::default()));
    let config_file = {
        // test if file exists in /etc/open-brski/conf
        if std::path::Path::exists(std::path::Path::new("/etc/open-brski/conf/Config.toml")) {
            Figment::from(Toml::file("/etc/open-brski/conf/Config.toml"))
        } else {
            Figment::from(Toml::file("Config.toml"))
        }
    };

    let mut merged_config = defaults.merge(config_file);
    if let Some(cli) = cli_config {
        let nullable_cli_conf: NullableConfig = cli.into();
        let cli = Figment::from(Serialized::defaults(nullable_cli_conf));
        merged_config = merged_config.merge(cli);
    }

    let final_config: Config = merged_config.extract()?;
    println!("final config before validation: {:#?}", final_config);
    final_config.validate()?;
    Ok(final_config)
}
