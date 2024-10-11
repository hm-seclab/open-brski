use brski_prm_artifacts::token_type::PKCS7;

use crate::server_error::ServerError;

pub fn is_pkcs7(content_type: &str) -> Result<(), ServerError> {
    match content_type {
        PKCS7 => Ok(()),
        _ => Err(ServerError::UnsupportedMediaType),
    }
}
