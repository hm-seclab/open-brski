use brski_prm_artifacts::{
    ietf_voucher::pki::X509,
    status::pledge::status::{PledgeStatus, PledgeStatusQuery},
    token_type::PlainTokenType,
};
use signeable_payload::{BasicSigningContext, RawSigned, Signed, Unsigned};
use tracing::{event, Level};

pub struct TransformQpsArgs {
    pub token_type: PlainTokenType,
    pub raw_status_query: Vec<u8>,
    pub pledge_idevid_chain: Vec<X509>,
    pub pledge_idevid_key: Vec<u8>,
}
pub fn transform_qps(args: TransformQpsArgs) -> anyhow::Result<Signed<PledgeStatus>> {
    let status_query: RawSigned<PledgeStatusQuery> = RawSigned::new(args.raw_status_query);

    let verifyer = args
        .token_type
        .signature_type()
        .get_sv::<PledgeStatusQuery>()?;

    event!(Level::INFO, "Decoding Status Query");

    let decoded = status_query
        .into_verifyable_boxed(verifyer)
        .verify(Default::default())?;

    event!(Level::INFO, "Building Pledge Status");
    let pledge_status = brski_prm_artifacts::status::pledge::status::PledgeStatus::default();

    let requested_token_type = args.token_type;

    let response = brski_prm_artifacts::status::pledge::response::PledgeStatusResponse::new(
        pledge_status,
        args.pledge_idevid_chain,
        requested_token_type.clone(),
    );

    event!(Level::INFO, "Encoding Pledge Status JWS");

    let raw_signed: Unsigned<PledgeStatus> = response.try_into()?;

    let signer = requested_token_type
        .signature_type()
        .get_sv::<PledgeStatus>()?;

    let signing_ctx = BasicSigningContext::new();

    let signed = raw_signed
        .into_signeable_boxed(signer)
        .sign(args.pledge_idevid_key, signing_ctx)?;

    Ok(signed)
}
