use axum::Router;
use cli::config::PledgeConfig;
use common::error::AppError;

use crate::{parsed_config::ParsedConfig, server::get_app};

pub async fn get_test_app() -> anyhow::Result<Router<()>, AppError> {
    let certs: example_certs::OpensslTestCerts = example_certs::generate_certs().into();

    let pledge_config = PledgeConfig::default();

    let config = ParsedConfig {
        idevid_certificate: certs.pledge.0,
        idevid_privkey: openssl::ec::EcKey::private_key_from_der(&certs.pledge.1.private_key_to_der()?)?,
        config: pledge_config
    };

    let app = get_app(&config).await?;
    Ok(app)
}