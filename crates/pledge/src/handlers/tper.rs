use axum::{
    debug_handler,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::per::response::PER_JWS;
use common::{
    server_error::ServerError,
    util::{is_jose, is_json},
};
use tracing::{event, Level};

use crate::parsed_config::ParsedConfig;
use crate::server::ServerState;

#[tracing::instrument(target = "Pledge", skip(state, headers, payload))]
#[debug_handler]
// We don't trust client's to supply just any base64 encoded data, so we parse it.
pub async fn handle_tper(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(payload): Json<brski_prm_artifacts::per::trigger::Trigger>,
) -> Result<PER_JWS, ServerError> {

    event!(Level::INFO, "Received tPER request");
    event!(Level::DEBUG, "Headers: {:#?}", headers);
    event!(Level::DEBUG, "Payload: {:#?}", payload);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    is_json(content_type)?;

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    is_jose(ACCEPT, accept)?;

    // brski servers can currently only accept one value
    if payload != brski_prm_artifacts::per::trigger::Trigger::default() {
        return Err(ServerError::BadRequest);
    }

    event!(Level::INFO, "Drawing private key from state");

    let private_key = state.read().await.config.idevid_privkey.clone();
    let private_key =
        openssl::pkey::PKey::private_key_from_der(private_key.private_key_to_der()?.as_slice())?;

    event!(Level::INFO, "Building tPER response payload");
    let per_response_payload =
        brski_prm_artifacts::per::response_payload::ResponsePayload::try_new(&private_key)?;


    event!(Level::INFO, "Building tPER response");    
    let per_response = brski_prm_artifacts::per::response::Response::new(
        per_response_payload,
        [state.read().await.config.idevid_certificate.clone()],
    );

    event!(Level::INFO, "Built tPER response");
    event!(Level::DEBUG, "Per Reponse: {:#?}", per_response);

    let jws: PER_JWS = per_response.try_into()?;

    event!(Level::INFO, "Encoding tPER response into JWS");
    let jws = jws.encode(private_key.private_key_to_der()?)?;
    jws.verify()?;
    event!(Level::DEBUG, "tPER JWS: {}", jws);
    Ok(jws)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use axum::{routing::post, Router};
    use brski_prm_artifacts::content_type::{JOSE, JSON};
    use brski_prm_artifacts::ietf_voucher::agent_signed_data;

    use super::*;
    use crate::util::get_test_app;
    use crate::{parsed_config::ParsedConfig, server::get_app};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_illegal_content_type() {
        let app = get_test_app().await.unwrap();

        let per = brski_prm_artifacts::per::trigger::Trigger::default();

        let per = serde_json::to_string(&per).unwrap();

        let response =  app.oneshot(Request::builder().method("POST").uri("/.well-known/brski/tper").header(CONTENT_TYPE, "application/text").body(Body::from(per)).unwrap()).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_invalid_accept() {
        let app = get_test_app().await.unwrap();

        let per = brski_prm_artifacts::per::trigger::Trigger::default();

        let per = serde_json::to_string(&per).unwrap(); 

        let response =  app.oneshot(Request::builder().method("POST").uri("/.well-known/brski/tper").header(CONTENT_TYPE, JSON).header(ACCEPT, "application/text").body(Body::from(per)).unwrap()).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn test_valid_json() {
        let app = get_test_app().await.unwrap();


        let per = brski_prm_artifacts::per::trigger::Trigger::default();

        let per = serde_json::to_string(&per).unwrap();

        let response =  app.oneshot(Request::builder().method("POST").uri("/.well-known/brski/tper").header(CONTENT_TYPE, JSON).header(ACCEPT, JOSE).body(Body::from(per)).unwrap()).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}