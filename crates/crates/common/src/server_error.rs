use axum::{
    http::header::ToStrError,
    response::{IntoResponse, Response},
};
use core::error::{self, Error};
use signeable_payload::error::SigneableError;
use thiserror::Error;
use tracing::{event, info};
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Bad Request")]
    BadRequest,

    #[error("Bad Request - Reason: {0}")]
    BadRequestWithReason(String),

    #[error("Bad Response - Reason: {0}")]
    BadResponse(String),

    #[cfg(feature = "openssl")]
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),

    #[cfg(feature = "jws")]
    #[error(transparent)]
    JWSError(#[from] josekit::JoseError),

    //#[error("Internal crate error. Please report this issue.")]
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
    //#[error("Internal BRSKI crate error")]
    #[error(transparent)]
    BRSKIError(#[from] brski_prm_artifacts::error::BRSKIPRMError),

    #[error("Not Acceptible")]
    NotAcceptible,

    #[error("Unsupported Media Type")]
    UnsupportedMediaType,

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    ToStrError(#[from] ToStrError),

    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),

    #[error(transparent)]
    SigneableError(#[from] SigneableError),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        event!(tracing::Level::ERROR, error = %self);
        self.source().map(|e| info!("Caused by: {}", e));

        let status = match self {
            Self::BadRequest => axum::http::StatusCode::BAD_REQUEST,
            Self::InternalError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotAcceptible => axum::http::StatusCode::NOT_ACCEPTABLE,
            Self::UnsupportedMediaType => axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::BRSKIError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadResponse(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::ReqwestError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::IoError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::BadRequestWithReason(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::ToStrError(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::SerdeError(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::SigneableError(_) => axum::http::StatusCode::BAD_REQUEST,
            _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        };

        status.into_response()
    }
}
