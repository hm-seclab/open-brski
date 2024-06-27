use ietf_voucher::pki::X509Req;
use openssl::pkey::Private;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ResponsePayload {
    #[serde(rename = "ietf-ztp-types")]
    pub csr: ResponsePayloadInner,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct ResponsePayloadInner {
    #[serde_as(as = "Base64")]
    pub p10_csr: X509Req,
}

impl ResponsePayload {
    pub fn try_new(
        keypair: &openssl::pkey::PKey<Private>,
    ) -> Result<ResponsePayload, openssl::error::ErrorStack> {
        let mut cert_req = openssl::x509::X509Req::builder()?;
        cert_req.set_pubkey(keypair).unwrap();
        let mut parsed_subject_name = openssl::x509::X509NameBuilder::new()?;
        parsed_subject_name.append_entry_by_text("CN", "common_name")?;
        parsed_subject_name.append_entry_by_text("C", "DE")?;
        parsed_subject_name.append_entry_by_text("ST", "Bavaria")?;
        parsed_subject_name.append_entry_by_text("L", "Munich")?;
        parsed_subject_name.append_entry_by_text("O", "University of Applied Sciences Munich")?;
        parsed_subject_name.append_entry_by_text("OU", "Department of Computer Science")?;
        cert_req.set_subject_name(&parsed_subject_name.build())?;
        cert_req.sign(keypair, openssl::hash::MessageDigest::sha256())?;

        let req = cert_req.build();
        Ok(ResponsePayload {
            csr: ResponsePayloadInner {
                p10_csr: req.into(),
            },
        })
    }
}
