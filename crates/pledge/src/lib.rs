mod handlers;
mod parsed_config;
mod server;
use axum::{
    Router,
};
use handlers::brski_routes;
use parsed_config::{parse_config};

use cli::config::PledgeConfig;
use common::error::AppError;
use tokio::task::JoinHandle;
use tower_http::trace::TraceLayer;
use tracing::{event, Level};
mod util;

#[tracing::instrument(skip(config), target = "Pledge", name = "Pledge::start")]
pub async fn start(config: PledgeConfig) -> anyhow::Result<JoinHandle<()>, AppError> {
    let address = "0.0.0.0:".to_owned() + &config.port;

    event!(Level::DEBUG, "Received config: {:?}", config);

    let parsed_config = parse_config(config)?;

    event!(Level::DEBUG, "Parsed config: {:?}", parsed_config);

    let app = server::get_app(&parsed_config).await?;
    let parsed_address: &std::net::SocketAddr = &address.parse()?;

    let listener = tokio::net::TcpListener::bind(parsed_address).await?;

    event!(Level::INFO, "Starting Server on {}", address);

    let server_handle = tokio::spawn(async {
        axum::serve(listener, app).await.unwrap()
    });

    Ok(server_handle)
}
