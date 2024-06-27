mod requestvoucher;
mod requestenroll;
mod wrappedcacerts;
mod voucher_status;
mod enrollstatus;
use axum::{routing::{get, post}, Router};


use super::server::ServerState;

#[tracing::instrument(target = "Registrar")]
pub(crate) fn brski_routes() -> Router<ServerState> {
    Router::new().route(
        "/requestvoucher",
        post(requestvoucher::handle_requestvoucher),

    ).route("/requestenroll", post(requestenroll::handle_requestenroll))
    .route("/wrappedcacerts", get(wrappedcacerts::handle_wrappedcacerts))
    .route("/voucher_status", post(voucher_status::handle_voucher_status))
    .route("/enrollstatus", post(enrollstatus::handle_enrollstatus))
}
