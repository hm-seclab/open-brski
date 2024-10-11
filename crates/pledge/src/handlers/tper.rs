use axum::{
    body::Bytes,
    debug_handler,
    extract::State,
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderMap,
    },
    Json,
};
use brski_prm_artifacts::{
    per::{response_payload::PledgeEnrollRequest, trigger::EnrollTrigger},
    token_type::{DataInterchangeFormat, PlainTokenType, JSON},
};
use common::server_error::ServerError;
use pledge_lib::tper::TransformPerArgs;
use tracing::{debug, event, info, Level};

use signeable_payload::{
    signeable::{signed::Signed, signing_context::BasicSigningContext, unsigned::Unsigned},
    DefaultSignerVerifyer,
};

use crate::server::ServerState;

#[tracing::instrument(target = "Pledge", skip(state, headers, bytes))]
// We don't trust client's to supply just any base64 encoded data, so we parse it.
pub async fn handle_tper(
    State(state): State<ServerState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Signed<PledgeEnrollRequest>, ServerError> {
    event!(Level::INFO, "Received tPER request");
    event!(Level::DEBUG, "Headers: {:#?}", headers);

    let content_type = headers
        .get(CONTENT_TYPE)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    let cloned_state = state.read().await.clone();

    if content_type
        != cloned_state
            .config
            .pledge_info
            .data_interchance_format
            .as_content_type()
    {
        return Err(ServerError::UnsupportedMediaType);
    }

    let accept = headers
        .get(ACCEPT)
        .ok_or(ServerError::BadRequest)?
        .to_str()
        .map_err(|_| ServerError::BadRequest)?;

    let cloned_state = state.read().await.clone();

    let payload: EnrollTrigger = match cloned_state.config.pledge_info.data_interchance_format {
        DataInterchangeFormat::JSON => serde_json::from_slice(&bytes)?,
        DataInterchangeFormat::CBOR => ciborium::from_reader(&bytes[..])
            .map_err(|e| ServerError::InternalError(anyhow::anyhow!(e)))?,
        _ => return Err(ServerError::UnsupportedMediaType),
    };

    // brski servers can currently only accept one value
    if payload != brski_prm_artifacts::per::trigger::EnrollTrigger::default() {
        return Err(ServerError::BadRequest);
    }

    info!("Drawing private key from state");

    let private_key = state.read().await.config.idevid_privkey.clone();

    info!("Building tPER response payload");

    let csr = pledge_lib::csr::create_csr(&private_key);

    let requested_token_type = PlainTokenType::from_content_type(accept);

    let x509 = brski_prm_artifacts::ietf_voucher::pki::X509::from(
        state.read().await.config.idevid_certificate.clone(),
    );

    let args: TransformPerArgs = TransformPerArgs {
        x509_req: csr,
        signature_type: requested_token_type,
        pledge_idevid_key: private_key,
        pledge_idevid_chain: vec![x509],
    };

    let signed = pledge_lib::tper::transform_per(args)?;

    Ok(signed)
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, routing::post, Router};
    use brski_prm_artifacts::{
        ietf_voucher::agent_signed_data,
        token_type::{JOSE, JSON},
    };

    use super::*;
    use crate::{parsed_config::ParsedConfig, server::get_app, util::get_test_app};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_illegal_content_type() {
        let app = get_test_app().await.unwrap();

        let per = brski_prm_artifacts::per::trigger::EnrollTrigger::default();

        let per = serde_json::to_string(&per).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/brski/tper")
                    .header(CONTENT_TYPE, "application/text")
                    .body(Body::from(per))
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
    async fn test_invalid_accept() {
        let app = get_test_app().await.unwrap();

        let per = brski_prm_artifacts::per::trigger::EnrollTrigger::default();

        let per = serde_json::to_string(&per).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/brski/tper")
                    .header(CONTENT_TYPE, JSON)
                    .header(ACCEPT, "application/text")
                    .body(Body::from(per))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn test_valid_json() {
        let app = get_test_app().await.unwrap();

        let per = brski_prm_artifacts::per::trigger::EnrollTrigger::default();

        let per = serde_json::to_string(&per).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/.well-known/brski/tper")
                    .header(CONTENT_TYPE, JSON)
                    .header(ACCEPT, JOSE)
                    .body(Body::from(per))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
