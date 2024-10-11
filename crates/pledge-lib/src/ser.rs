use anyhow::Result;
use brski_prm_artifacts::{
    ietf_voucher::pki::X509,
    status::enroll::{response::PledgeEnrollStatusResponse, status::PledgeEnrollStatus},
    token_type::PlainTokenType,
};
use signeable_payload::{BasicSigningContext, Signed, Unsigned};
use tracing::{event, Level};

pub struct TransformSerArgs {
    pub requested_token_type: PlainTokenType,
    pub raw_ldevid_cert: Vec<u8>,
    pub enroll_status: PledgeEnrollStatus,
    pub pledge_idevid_chain: Vec<X509>,
    pub pledge_idevid_key: Vec<u8>,
}

pub struct TransformSerResult {
    pub signed_enroll_status: Signed<PledgeEnrollStatus>,
    pub ldevid_cert: X509,
}

pub fn transform_ser(args: TransformSerArgs) -> Result<TransformSerResult> {
    event!(Level::INFO, "Building enroll status");
    let ldevid_cert = X509::try_from(args.raw_ldevid_cert)?;
    let enroll_status_response = PledgeEnrollStatusResponse::new(
        args.enroll_status,
        args.pledge_idevid_chain,
        args.requested_token_type.clone(),
    );
    event!(Level::INFO, "Encoding enroll status");
    let unsigned: Unsigned<PledgeEnrollStatus> = enroll_status_response.try_into()?;

    let signer = args
        .requested_token_type
        .signature_type()
        .get_sv::<PledgeEnrollStatus>()?;

    let signed = unsigned
        .into_signeable_boxed(signer)
        .sign(args.pledge_idevid_key, BasicSigningContext::new())?;
    let res = TransformSerResult {
        signed_enroll_status: signed,
        ldevid_cert,
    };

    Ok(res)
}
