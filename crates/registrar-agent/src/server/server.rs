use crate::{
    parsed_config::{ParsedConfig},
};
use axum::{Router};
use common::error::AppError;
use reqwest::Client;
use tower_http::trace::TraceLayer;

use super::handlers::brski_routes;

#[derive(Clone, Debug)]
pub struct ServerState {
    pub config: ParsedConfig,
    pub client: reqwest::Client,
}

pub async fn get_app(config: &ParsedConfig) -> anyhow::Result<Router<()>, AppError> {
    let client = Client::new();

    let state = ServerState {
        config: config.clone(),
        client: client.clone(),
    };

    let routes = Router::new().nest("/.well-known/brski", brski_routes());

    let app = routes.with_state(state).layer(TraceLayer::new_for_http());

    Ok(app)
}
