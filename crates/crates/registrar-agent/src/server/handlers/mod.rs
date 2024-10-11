mod init;
use axum::{routing::post, Router};
pub use init::bootstrap_pledge;

use super::server::ServerState;

pub(crate) fn brski_routes() -> Router<ServerState> {
    Router::new().route("/init", post(init::init))
}
