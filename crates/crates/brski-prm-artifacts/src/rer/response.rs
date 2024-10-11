use ietf_voucher::pki::X509;

#[derive(Debug, Clone)]
pub struct RegistrarEnrollRequestResponse(pub X509);
