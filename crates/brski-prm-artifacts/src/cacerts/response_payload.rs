use ietf_voucher::pki::{X509Req, X509};
use openssl::pkey::Private;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ResponsePayload {
    #[serde_as(as = "Vec<Base64>")]
    pub x5bag: Vec<X509>
}
