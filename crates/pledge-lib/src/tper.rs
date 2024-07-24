use brski_prm_artifacts::{ietf_voucher::pki::{X509Req, X509}, per::{response::Response, response_payload::{ResponsePayload, ResponsePayloadInner}}};

pub fn create_per(x509_req: impl Into<X509Req>, pledge_idevid_certs: impl IntoIterator<Item = impl Into<X509>>,) -> Response {
    let payload = ResponsePayload {
        csr: ResponsePayloadInner {
            p10_csr: x509_req.into(),
        }
    };
    Response::new(payload, pledge_idevid_certs)
}