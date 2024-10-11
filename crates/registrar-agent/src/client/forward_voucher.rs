use brski_prm_artifacts::{issued_voucher::IssuedVoucher, status::voucher::status::VoucherStatus};
use common::server_error::ServerError;
use signeable_payload::signeable::raw_signed::RawSigned;
use tracing::event;

use crate::{pledge_communicator::PledgeCtx, server::server::ServerState};

#[tracing::instrument(
    skip(state, voucher),
    target = "RegistrarAgent",
    name = "send_voucher_to_pledge"
)]
pub async fn send_voucher_to_pledge(
    state: &ServerState,
    voucher: RawSigned<IssuedVoucher>,
    pledge: &PledgeCtx,
) -> Result<RawSigned<VoucherStatus>, ServerError> {
    let data = voucher.data();

    let response = state
        .communicator
        .send_voucher(data, pledge.clone())
        .await?;
    event!(tracing::Level::INFO, "Received vStatus response_data");
    //event!(tracing::Level::DEBUG, "vStatus Reponse Data: {}", response);

    event!(tracing::Level::INFO, "Parsing vStatus response data");
    let raw_signed_voucher_status: RawSigned<VoucherStatus> = RawSigned::from(response);
    event!(
        tracing::Level::DEBUG,
        "vStatus {:#?}",
        raw_signed_voucher_status
    );

    Ok(raw_signed_voucher_status)
}
