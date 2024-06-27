use std::any;

use axum::http::{header::{ACCEPT, CONTENT_TYPE}, HeaderName, HeaderValue};
use brski_prm_artifacts::{content_type::{JOSE, JSON, JWS_VOUCHER, PKCS7}, jws::JWS};

use crate::server_error::ServerError;

pub fn is_json(content_type: &str) -> Result<(), ServerError> {
    match content_type {
        JSON => Ok(()),
        _ => Err(ServerError::UnsupportedMediaType),
    }
}

pub fn is_jose(header: HeaderName, content: &str) -> Result<(), ServerError> {

    match (header, content) {
        (ACCEPT, JOSE) => Ok(()),
        (ACCEPT, _) => Err(ServerError::NotAcceptible),
        (CONTENT_TYPE, JOSE) => Ok(()),
        (CONTENT_TYPE, _) => Err(ServerError::UnsupportedMediaType),
        _ => Err(ServerError::InternalError { source: anyhow::anyhow!("Tested unsupported header")}),
    }

}

pub fn is_jws_voucher(content_type: &str) -> Result<(), ServerError> {
    match content_type {
        JWS_VOUCHER => Ok(()),
        _ => Err(ServerError::UnsupportedMediaType),
    }
}

pub fn is_pkcs7(content_type: &str) -> Result<(), ServerError> {
    match content_type {
        PKCS7 => Ok(()),
        _ => Err(ServerError::UnsupportedMediaType),
    }
}
