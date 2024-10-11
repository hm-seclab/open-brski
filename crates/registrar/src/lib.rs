mod client;
mod parsed_config;
mod server;
mod sign_cert;

use cli::config::RegistrarConfig;
use common::error::AppError;
use parsed_config::parse_config;
use tokio::task::JoinHandle;
use tracing::{event, Level};

#[tracing::instrument(target = "Registrar", skip(config), name = "Registrar::start")]
pub async fn start(config: RegistrarConfig) -> anyhow::Result<JoinHandle<()>, AppError> {
    let address = "0.0.0.0:".to_owned() + &config.port;
    let parsed_address: &std::net::SocketAddr = &address.parse()?;

    event!(Level::DEBUG, "Received config {:?}", config);

    event!(Level::INFO, "Starting server on {}", address);

    let parsed_config = parse_config(config)?;

    event!(Level::INFO, "Parsed config");
    event!(Level::DEBUG, "Parsed Registrar Config: {:?}", parsed_config);

    let app = server::get_app(&parsed_config).await?;

    let listener = tokio::net::TcpListener::bind(parsed_address).await?;

    let server_handle = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });

    Ok(server_handle)
}
