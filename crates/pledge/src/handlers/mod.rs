mod tper;
mod tpvr;
mod svr;
mod scac;
mod ser;
mod qps;
use axum::{routing::post, Router};

use crate::parsed_config::ParsedConfig;
use crate::server::ServerState;

#[tracing::instrument(target = "Pledge")]
pub(crate) fn brski_routes() -> Router<ServerState> {
    Router::new()
        .route("/tpvr", post(tpvr::handle_tpvr))
        .route("/tper", post(tper::handle_tper))
        .route("/svr", post(svr::handle_svr))
        .route("/scac", post(scac::handle_scac))
        .route("/ser", post(ser::handle_ser))
        .route("/qps", post(qps::handle_qps))
}
