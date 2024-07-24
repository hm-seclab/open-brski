
use ietf_voucher::pki::X509;
use crate::content_type;

#[derive(Debug, Clone)]
pub struct Response(pub X509);

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for Response {
    fn into_response(self) -> axum::response::Response {
        axum::response::Response::builder()
            .header(axum::http::header::CONTENT_TYPE, content_type::PKCS7)
            .body(self.0.to_der().unwrap().into())
            .unwrap()
    }
}