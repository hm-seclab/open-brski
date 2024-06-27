use axum::{
    debug_handler,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{
    per::response::PER_JWS,
    status::pledge::{request::StatusQueryJWS, response::PledgeStatusJWS},
};
use common::{
    server_error::ServerError,
    util::{is_jose, is_json},
};
use tracing::{event, Level};

use crate::{parsed_config::ParsedConfig, server::ServerState};

#[tracing::instrument(target = "Pledge", skip(state, headers, body))]
#[debug_handler]
// We don't trust client's to supply just any base64 encoded data, so we parse it.
pub async fn handle_qps(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: String,
) -> Result<PledgeStatusJWS, ServerError> {
    event!(Level::INFO, "Received qps request");
    event!(Level::DEBUG, "Headers: {:#?}", headers);
    event!(Level::DEBUG, "Body: {:#?}", body);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()?;

    is_jose(CONTENT_TYPE, content_type)?;

    let accept = headers
    .get(ACCEPT)
    .ok_or(ServerError::BadRequest)?
    .to_str()?;

    is_jose(ACCEPT, accept)?;

    let jws: StatusQueryJWS = StatusQueryJWS::Encoded(body);

    event!(Level::INFO, "Decoding Status Query JWS");

    let decoded = jws.decode()?;

    event!(Level::INFO, "Building Pledge Status");
    let pledge_status = brski_prm_artifacts::status::pledge::status::PledgeStatus::default();

    let pledge_idevid_cert = state.read().await.config.idevid_certificate.clone();
    let plege_idevid_key = state.read().await.config.idevid_privkey.clone();

    let response = brski_prm_artifacts::status::pledge::response::Response::new(
        pledge_status,
        [pledge_idevid_cert],
    );

    event!(Level::INFO, "Encoding Pledge Status JWS");
    let jws: PledgeStatusJWS = response.try_into()?;

    let encoded = jws.encode(plege_idevid_key.private_key_to_der()?)?;
    encoded.verify()?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use axum::{routing::post, Router};
    use brski_prm_artifacts::content_type::JOSE;

    use super::*;
    use crate::util::get_test_app;
    use crate::{parsed_config::ParsedConfig, server::get_app};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_illegal_content_type() {
        let app = get_test_app().await.unwrap();

        let response =  app.oneshot(Request::builder().method("POST").uri("/.well-known/brski/qps").header(CONTENT_TYPE, "application/text").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    
    #[tokio::test]
    async fn test_invalid_jws() {
        let app = get_test_app().await.unwrap();

        let response =  app.oneshot(Request::builder().method("POST").uri("/.well-known/brski/qps").header(CONTENT_TYPE, JOSE).header(ACCEPT, JOSE).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_accept() {
        let app = get_test_app().await.unwrap();

        let response =  app.oneshot(Request::builder().method("POST").uri("/.well-known/brski/qps").header(CONTENT_TYPE, JOSE).header(ACCEPT, "application/text").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_ACCEPTABLE);
    }
}
