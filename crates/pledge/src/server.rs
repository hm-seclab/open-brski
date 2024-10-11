use std::{fmt::Debug, sync::Arc};

use crate::parsed_config::ParsedConfig;
use axum::{response::Response, Router};
use brski_prm_artifacts::ietf_voucher::{artifact::VoucherArtifact, pki::X509};
use common::error::AppError;
use tower_http::trace::TraceLayer;
use tracing::{event, info, Level, Span};

use super::handlers::brski_routes;

use tokio::{
    sync::RwLock,
    time::{self, Duration, Instant},
};

#[derive(Clone)]
pub struct State {
    pub config: ParsedConfig,
    pub cacerts: Option<Vec<X509>>,
    pub ldevid_cert: Option<X509>,
    pub trust_anchor: Option<X509>,
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ServerState {{ cacerts: {:?}, ldevid_cert: {:?}, trust_anchor: {:?} }}",
            self.cacerts, self.ldevid_cert, self.trust_anchor
        )
    }
}

pub type ServerState = Arc<RwLock<State>>;
pub async fn get_app(config: &ParsedConfig) -> anyhow::Result<Router<()>, AppError> {
    let state = State {
        config: config.clone(),
        cacerts: None,
        ldevid_cert: None,
        trust_anchor: None,
    };

    let server_state = Arc::new(RwLock::new(state));

    let routes = Router::new().nest("/.well-known/brski", brski_routes());

    let app = routes
        .with_state(Arc::clone(&server_state))
        .layer(axum::middleware::from_fn(
            common::middleware::log_request_size,
        ))
        .layer(TraceLayer::new_for_http().on_response(
            |response: &Response, _latency: Duration, _span: &Span| {
                let _ = _span.enter();
                event!(Level::INFO, "Response: {:?}", response);
            },
        ));

    tokio::spawn(async move {
        let sleep = time::sleep(Duration::from_millis(10));
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                () = &mut sleep => {
                    println!("timer elapsed");
                    sleep.as_mut().reset(Instant::now() + Duration::from_secs(30));
                    event!(Level::INFO, "Server State: {:?}", server_state.read().await);
                },
            }
        }
    });

    Ok(app)
}
