use axum::{
    body::Bytes,
    debug_handler,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
};
use brski_prm_artifacts::{
    status::pledge::status::{PledgeStatus, PledgeStatusQuery},
    token_type::{PlainTokenType, TokenType},
};
use common::server_error::ServerError;
use signeable_payload::{
    signeable::{
        raw_signed::RawSigned, signed::Signed, signing_context::BasicSigningContext,
        unsigned::Unsigned,
    },
    DefaultSignerVerifyer,
};
use tracing::{event, Level};

use crate::{parsed_config::ParsedConfig, server::ServerState};

#[tracing::instrument(target = "Pledge", skip(state, headers, bytes))]
// We don't trust client's to supply just any base64 encoded data, so we parse it.
pub async fn handle_qps(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Signed<PledgeStatus>, ServerError> {
    event!(Level::INFO, "Received qps request");
    event!(Level::DEBUG, "Headers: {:#?}", headers);

    // TODO make sure content type and accept match
    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()?;

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()?;

    let pledge_idevid_cert = state.read().await.config.idevid_certificate.clone();
    let plege_idevid_key = state.read().await.config.idevid_privkey.clone();

    let args = pledge_lib::qps::TransformQpsArgs {
        token_type: PlainTokenType::from_content_type(content_type),
        raw_status_query: bytes.to_vec(),
        pledge_idevid_chain: vec![pledge_idevid_cert.into()],
        pledge_idevid_key: plege_idevid_key,
    };

    let res = pledge_lib::qps::transform_qps(args)?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, routing::post, Router};
    use brski_prm_artifacts::token_type::JOSE;

    use super::*;
    use crate::{parsed_config::ParsedConfig, server::get_app, util::get_test_app};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_illegal_content_type() {
        let app = get_test_app().await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/brski/qps")
                    .header(CONTENT_TYPE, "application/text")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[tokio::test]
    async fn test_invalid_jws() {
        let app = get_test_app().await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/brski/qps")
                    .header(CONTENT_TYPE, JOSE)
                    .header(ACCEPT, JOSE)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_accept() {
        let app = get_test_app().await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/brski/qps")
                    .header(CONTENT_TYPE, JOSE)
                    .header(ACCEPT, "application/text")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_ACCEPTABLE);
    }
}
