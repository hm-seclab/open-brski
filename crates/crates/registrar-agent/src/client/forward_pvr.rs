use brski_prm_artifacts::{ietf_voucher::VoucherRequest, issued_voucher::IssuedVoucher};
use common::server_error::ServerError;
use signeable_payload::signeable::raw_signed::RawSigned;
use tracing::event;

use crate::{parsed_config::ParsedConfig, PledgeCtx};

use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};

#[tracing::instrument(
    skip(client, parsed_config, pvr),
    target = "RegistrarAgent",
    name = "send_pvr_to_registrar"
)]
pub async fn send_pvr_to_registrar(
    parsed_config: &ParsedConfig,
    pvr: RawSigned<VoucherRequest>,
    client: &Client,
    ctx: &PledgeCtx,
) -> Result<RawSigned<IssuedVoucher>, ServerError> {
    let request_enroll_registrar_url = format!(
        "{}/.well-known/brski/requestvoucher",
        parsed_config.config.registrar_url
    );

    event!(
        tracing::Level::INFO,
        "Sending PVR to registrar at: {}",
        request_enroll_registrar_url
    );

    let data = pvr.data();

    let response = client
        .post(request_enroll_registrar_url)
        .header(
            ACCEPT,
            ctx.pledge_info.supported_voucher_type.as_content_type(),
        )
        .header(
            CONTENT_TYPE,
            ctx.pledge_info.supported_voucher_type.as_content_type(),
        )
        .body(data)
        .send()
        .await?;

    event!(tracing::Level::INFO, "Received response");
    event!(tracing::Level::DEBUG, "Response: {:#?}", response);

    if !response.status().is_success() {
        event!(
            tracing::Level::ERROR,
            "Sending PVR to registrar failed: {:#?}",
            response
        );
        return Err(ServerError::BadResponse(
            "Sending PVR to registrar failed".to_string(),
        ));
    }

    if response.headers().get(CONTENT_TYPE).is_none() {
        event!(
            tracing::Level::ERROR,
            "No content type in response: {:#?}",
            response
        );
        return Err(ServerError::BadResponse(
            "No content type in response".to_string(),
        ));
    }

    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type != ctx.pledge_info.supported_voucher_type.as_content_type() {
            event!(
                tracing::Level::ERROR,
                "Wrong content type in response: {:#?}",
                response
            );
            return Err(ServerError::BadResponse(
                "Wrong content type in response".to_string(),
            ));
        }
    }

    let response_data = response.bytes().await?;
    event!(
        tracing::Level::INFO,
        "Received issued voucher response_data"
    );

    event!(
        tracing::Level::INFO,
        "Parsing IssuedVoucher response data into signed format"
    );
    let raw_signed_issued_voucher: RawSigned<IssuedVoucher> =
        RawSigned::new(response_data.to_vec());
    event!(
        tracing::Level::DEBUG,
        "Issued Voucher: {:#?}",
        raw_signed_issued_voucher
    );

    Ok(raw_signed_issued_voucher)
}
