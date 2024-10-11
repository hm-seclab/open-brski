use std::{
    sync::{Arc, Mutex},
    vec,
};

use brski_prm_artifacts::status::voucher::status::{ReasonContext, VoucherStatus};
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD};
use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};

use log::info;
use pledge_lib::{ser::TransformSerArgs, svr::{TransformSvrArgs, TransformVoucherStatusArgs}};
use signeable_payload::{BasicSigningContext, Signed};

use crate::{
    ble_async::UUIDS,
    CREDENTIALS,
};

pub fn handle_svr(data: Vec<u8>) -> anyhow::Result<Signed<VoucherStatus>> {

    let args: TransformSvrArgs = TransformSvrArgs {
        raw_issued_voucher: data,
        token_type: brski_prm_artifacts::token_type::VoucherTokenType::COSE,
    };

    let issued_voucher = pledge_lib::svr::transform_svr(args).unwrap();

    // install trust anchor

    let status: VoucherStatus = brski_prm_artifacts::status::voucher::status::VoucherStatus {
        reason: Some("Voucher installed".to_string()),
        reason_context: ReasonContext {
            pvs_details: "COSE".to_string(),
        },
        ..Default::default()
    };

    let args: TransformVoucherStatusArgs = TransformVoucherStatusArgs {
        requested_token_type: brski_prm_artifacts::token_type::PlainTokenType::COSE,
        status,
        pledge_idevid_chain: CREDENTIALS.cert_chain.clone(),
        pledge_idevid_key: CREDENTIALS.private_key.to_vec(),
    };

    let transformed = pledge_lib::svr::transform_voucher_status(args)?;

    Ok(transformed)
}