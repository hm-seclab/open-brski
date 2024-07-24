use brski_prm_artifacts::issued_voucher::IssuedVoucherJWS;
use brski_prm_artifacts::status::voucher::response::vStatus_JWS;
use common::server_error::ServerError;
use tracing::event;

use crate::pledge_communicator::PledgeCtx;
use crate::server::server::ServerState;



#[tracing::instrument(skip(state, voucher), target = "RegistrarAgent", name="send_voucher_to_pledge")]
pub async fn send_voucher_to_pledge(
    state: &ServerState,
    voucher: IssuedVoucherJWS,
    pledge: &PledgeCtx,
) -> Result<vStatus_JWS, ServerError> {

    let voucher_str = voucher.try_encoded_data()?;

    let response = state.communicator.send_voucher(voucher_str, pledge.clone()).await?;
    event!(tracing::Level::INFO, "Received vStatus response_data");
    event!(tracing::Level::DEBUG, "vStatus Reponse Data: {}", response);
    // TODO convert this to jws

    event!(tracing::Level::INFO, "Parsing vStatus response data into JWS");
    let jws = vStatus_JWS::Encoded(response);
    event!(tracing::Level::DEBUG, "vStatus JWS{:#?}", jws);

    Ok(jws)
}