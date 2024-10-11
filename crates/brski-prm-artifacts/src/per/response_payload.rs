use core::{fmt::Display, str::FromStr};
use std::vec;

use ietf_voucher::pki::X509Req;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct PledgeEnrollRequest {
    #[serde(rename = "ietf-ztp-types")]
    pub csr: ResponsePayloadInner,
}

#[cfg_attr(feature = "json", serde_with::serde_as)]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ResponsePayloadInner {
    #[cfg_attr(feature = "json", serde_as(as = "Base64"))]
    pub p10_csr: X509Req,
}

impl PledgeEnrollRequest {
    pub fn new(csr: X509Req) -> Self {
        Self {
            csr: ResponsePayloadInner { p10_csr: csr },
        }
    }
}

impl TryFrom<Vec<u8>> for PledgeEnrollRequest {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let csr: X509Req = value.try_into()?;
        Ok(Self::new(csr))
    }
}
