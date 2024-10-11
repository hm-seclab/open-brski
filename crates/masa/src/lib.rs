mod parsed_config;
mod server;

use cli::config::MasaConfig;
use common::error::AppError;
use parsed_config::parse_config;
use tokio::task::JoinHandle;
use tracing::{event, Level};

#[tracing::instrument(target = "MASA", skip(config), name = "MASA::start")]
pub async fn start(config: MasaConfig) -> anyhow::Result<JoinHandle<()>, AppError> {
    let address = "0.0.0.0:".to_owned() + &config.port;
    let parsed_address: &std::net::SocketAddr = &address.parse()?;

    event!(Level::DEBUG, "Received config {:?}", config);
    event!(Level::INFO, "Starting server on {}", address);

    let parsed_config = parse_config(config)?;

    let app = server::get_app(&parsed_config).await?;

    let listener = tokio::net::TcpListener::bind(parsed_address).await?;

    let server_handle = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });

    Ok(server_handle)
}
