use core::time::Duration;

use crate::parsed_config::ParsedConfig;
use axum::Router;
use common::error::AppError;
use reqwest::Client;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{error, error_span, Span};

use super::handlers::brski_routes;

#[derive(Clone)]
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

    let routes = Router::new()
        .nest("/.well-known/brski", brski_routes())
        .layer(TraceLayer::new_for_http().on_failure(
            |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                let _ = _span.enter();
                error!("Request failed: {}", _error.to_string());
            },
        ))
        .layer(axum::middleware::from_fn(
            common::middleware::log_request_size,
        ));

    let app = routes.with_state(state);

    Ok(app)
}
