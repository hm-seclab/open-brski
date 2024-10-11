use anyhow::Result;
use brski_prm_artifacts::{
    ietf_voucher::pki::{X509Req, X509},
    per::{
        response::PledgeEnrollRequestResponse,
        response_payload::{PledgeEnrollRequest, ResponsePayloadInner},
    },
    token_type::PlainTokenType,
};
use signeable_payload::{BasicSigningContext, Signed, Unsigned};
use tracing::info;
pub struct TransformPerArgs {
    pub x509_req: X509Req,
    pub signature_type: PlainTokenType,
    pub pledge_idevid_key: Vec<u8>,
    pub pledge_idevid_chain: Vec<X509>,
}

pub fn create_per(
    x509_req: impl Into<X509Req>,
    pledge_idevid_certs: impl IntoIterator<Item = impl Into<X509>>,
    signature_type: PlainTokenType,
) -> PledgeEnrollRequestResponse {
    info!("Building tPER response payload");
    let payload = PledgeEnrollRequest {
        csr: ResponsePayloadInner {
            p10_csr: x509_req.into(),
        },
    };
    PledgeEnrollRequestResponse::new(payload, pledge_idevid_certs, signature_type)
}
pub fn transform_per(args: TransformPerArgs) -> Result<Signed<PledgeEnrollRequest>> {
    info!("Building tPER response");
    let per = create_per(
        args.x509_req,
        args.pledge_idevid_chain,
        args.signature_type.clone(),
    );
    let unsinged_per: Unsigned<PledgeEnrollRequest> = per.try_into()?;
    info!("Built tPER response");
    info!("Signing tPER response");
    let signer = args
        .signature_type
        .signature_type()
        .get_sv::<PledgeEnrollRequest>()?;
    let ctx = BasicSigningContext::new();
    let signed = unsinged_per
        .into_signeable_boxed(signer)
        .sign(args.pledge_idevid_key, ctx)?;
    info!("Signed tPER response");
    Ok(signed)
}
