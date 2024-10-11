mod dif;
mod pi;
mod qps;
mod scac;
mod ser;
mod svr;
mod tper;
mod tpvr;
use axum::{
    routing::{get, post},
    Router,
};

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
        .route("/dif", get(dif::handle_dif))
        .route("/pi", get(pi::handle_pi))
}
