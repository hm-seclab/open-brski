use ietf_voucher::pki::X509;
use serde::{Deserialize, Serialize};
#[cfg(feature = "json")]
use serde_with::serde_as;

#[cfg_attr(feature = "json", serde_as)]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct CaCerts {
    #[cfg_attr(feature = "json", serde_as(as = "Vec<Base64>"))]
    pub x5bag: Vec<X509>,
}
