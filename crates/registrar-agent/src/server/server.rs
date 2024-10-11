use crate::{
    parsed_config::ParsedConfig,
    pledge_communicator::{http_communicator::HTTPCommunicator, PledgeCommunicator},
};
use axum::Router;
use common::error::AppError;
use reqwest::Client;
use tower_http::trace::TraceLayer;

use super::handlers::brski_routes;

#[derive(Clone)]
pub struct ServerState {
    pub config: ParsedConfig,
    pub client: reqwest::Client,
    pub communicator: Box<dyn PledgeCommunicator>,
}

fn get_server_state(config: &ParsedConfig) -> anyhow::Result<ServerState, AppError> {
    let client = Client::new();

    Ok(ServerState {
        config: config.clone(),
        client: client.clone(),
        communicator: Box::new(HTTPCommunicator::new(client)),
    })
}

pub fn get_state(
    config: &ParsedConfig,
    communicator: Box<dyn PledgeCommunicator>,
) -> anyhow::Result<ServerState, AppError> {
    Ok(ServerState {
        config: config.clone(),
        client: Client::new(),
        communicator,
    })
}

pub async fn get_app(config: &ParsedConfig) -> anyhow::Result<Router<()>, AppError> {
    let state = get_server_state(config)?;

    let routes = Router::new().nest("/.well-known/brski", brski_routes());

    let app = routes
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(
            common::middleware::log_request_size,
        ));

    Ok(app)
}
