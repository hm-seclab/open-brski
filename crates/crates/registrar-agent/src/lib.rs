mod client;
mod parsed_config;
mod pledge_communicator;
mod server;

use cli::config::RegistrarAgentConfig;
use common::error::AppError;
use parsed_config::parse_config;
use tokio::task::JoinHandle;
use tracing::{event, Level};

pub use client::*;
pub use parsed_config::*;
pub use pledge_communicator::{DiscoveredPledge, PledgeCommunicator, PledgeCtx};
pub use server::{
    bootstrap_pledge,
    server::{get_state, ServerState},
};

#[tracing::instrument(
    skip(config),
    target = "RegistrarAgent",
    name = "RegistrarAgent::start"
)]
pub async fn start(config: RegistrarAgentConfig) -> anyhow::Result<JoinHandle<()>, AppError> {
    let address = "0.0.0.0:".to_owned() + &config.port;

    event!(Level::DEBUG, "Received config {:?}", config);

    let parsed_address: &std::net::SocketAddr = &address.parse()?;

    let parsed_config = parse_config(config)?;

    event!(Level::INFO, "Parsed config");
    event!(
        Level::DEBUG,
        "Registrar Agent Parsed Config: {:?}",
        parsed_config
    );

    let app = server::get_app(&parsed_config).await?;

    let listener = tokio::net::TcpListener::bind(parsed_address).await?;

    event!(Level::INFO, "Starting Server on {:?}", address);

    let server_handle = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });

    Ok(server_handle)
}
