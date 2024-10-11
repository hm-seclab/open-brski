mod requestvoucher;
use axum::{routing::post, Router};

use super::server::ServerState;

#[tracing::instrument(target = "MASA")]
pub(crate) fn brski_routes() -> Router<ServerState> {
    Router::new().route(
        "/requestvoucher",
        post(requestvoucher::handle_requestvoucher),
    )
}
