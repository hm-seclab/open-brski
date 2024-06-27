use josekit::jws::{self, JwsHeaderSet};

use crate::error::BRSKIPRMError;
use crate::jws::{DecodedJWS, JWS};

use ietf_voucher::pki::X509;

use super::status::StatusQuery;

pub struct Request {
    status: StatusQuery,
    reg_agt_ee_certs: Vec<X509>,
}

pub type StatusQueryJWS = JWS<StatusQuery>;

impl TryFrom<Request> for JWS<StatusQuery> {
    type Error = BRSKIPRMError;

    fn try_from(value: Request) -> Result<Self, Self::Error> {
        let mut header_set = JwsHeaderSet::new();
        header_set.set_x509_certificate_chain(&value.reg_agt_ee_certs, true);
        header_set.set_algorithm(jws::ES256.to_string(), true);
        header_set.set_token_type("voucher-jws+json", false);

        let jws = JWS::Decoded(DecodedJWS {
            payload: value.status,
            header_set: Some(header_set),
            header: None,
        });

        Ok(jws)
    }
}

impl Request {
    pub fn new(
        status: StatusQuery,
        reg_agt_ee_certs: impl IntoIterator<Item = impl Into<X509>>,
    ) -> Self {
        Self {
            status,
            reg_agt_ee_certs: reg_agt_ee_certs.into_iter().map(Into::into).collect(),
        }
    }
}
