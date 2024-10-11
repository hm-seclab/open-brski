use axum::Router;
use brski_prm_artifacts::pledge_info::PledgeInfo;
use cli::config::PledgeConfig;
use common::error::AppError;

use crate::{parsed_config::ParsedConfig, server::get_app};

pub async fn get_test_app() -> anyhow::Result<Router<()>, AppError> {
    let certs: example_certs::OpensslTestCerts = example_certs::generate_certs().into();

    let pledge_config = PledgeConfig::default();

    let config = ParsedConfig {
        idevid_certificate: certs.pledge.0,
        idevid_privkey: openssl::pkey::PKey::private_key_from_der(
            &certs.pledge.1.private_key_to_der()?,
        )?
        .private_key_to_pkcs8()?,
        config: pledge_config,
        pledge_info: PledgeInfo {
            data_interchance_format: brski_prm_artifacts::token_type::DataInterchangeFormat::JSON,
            supported_token_type: brski_prm_artifacts::token_type::PlainTokenType::JOSE,
            supported_voucher_type: brski_prm_artifacts::token_type::VoucherTokenType::JWS,
        },
    };

    let app = get_app(&config).await?;
    Ok(app)
}
