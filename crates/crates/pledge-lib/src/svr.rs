use brski_prm_artifacts::{
    ietf_voucher::{artifact::VoucherArtifact, pki::X509},
    status::voucher::status::VoucherStatus,
    token_type::{PlainTokenType, VoucherTokenType},
};
use signeable_payload::{BasicSigningContext, RawSigned, Signed, Unsigned};
use tracing::{event, Level};

pub struct TransformSvrArgs {
    pub raw_issued_voucher: Vec<u8>,
    pub token_type: VoucherTokenType,
}

pub fn transform_svr(args: TransformSvrArgs) -> anyhow::Result<(VoucherArtifact)> {
    let issued_voucher: RawSigned<VoucherArtifact> =
        RawSigned::new(args.raw_issued_voucher.to_vec());

    let verifier = args
        .token_type
        .signature_type()
        .get_sv::<VoucherArtifact>()?;

    let decoded = issued_voucher
        .into_verifyable_boxed(verifier)
        .verify(Default::default())?;

    let voucher = decoded.payload().clone();

    Ok(voucher)
}

pub struct TransformVoucherStatusArgs {
    pub status: VoucherStatus,
    pub pledge_idevid_chain: Vec<X509>,
    pub pledge_idevid_key: Vec<u8>,
    pub requested_token_type: PlainTokenType,
}

pub fn transform_voucher_status(
    args: TransformVoucherStatusArgs,
) -> anyhow::Result<Signed<VoucherStatus>> {
    let response = brski_prm_artifacts::status::voucher::response::VoucherStatusResponse::new(
        args.status,
        args.pledge_idevid_chain,
        args.requested_token_type.clone(),
    );

    let raw_signed: Unsigned<VoucherStatus> = response.try_into()?;

    let signer = args
        .requested_token_type
        .signature_type()
        .get_sv::<VoucherStatus>()?;

    let signing_ctx = BasicSigningContext::new();

    event!(Level::INFO, "Encoding voucher response");
    let encoded = raw_signed
        .into_signeable_boxed(signer)
        .sign(args.pledge_idevid_key, signing_ctx)?;
    Ok(encoded)
}
