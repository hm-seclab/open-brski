use std::{
    sync::{Arc, Mutex},
    vec,
};

use brski_prm_artifacts::status::enroll::status::PledgeEnrollStatus;
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD};
use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};

use log::info;
use pledge_lib::ser::TransformSerArgs;
use signeable_payload::{BasicSigningContext, Signed};

use crate::{
    ble_async::UUIDS,
    CREDENTIALS,
};

pub fn handle_ser(data: Vec<u8>) -> anyhow::Result<Signed<PledgeEnrollStatus>> {

    let enroll_status = PledgeEnrollStatus::default();

    let args: TransformSerArgs = TransformSerArgs {
        requested_token_type: brski_prm_artifacts::token_type::PlainTokenType::COSE,
        raw_ldevid_cert: data,
        enroll_status,
        pledge_idevid_chain: CREDENTIALS.cert_chain.clone(),
        pledge_idevid_key: CREDENTIALS.private_key.to_vec(),
    };

    let transformed = pledge_lib::ser::transform_ser(args)?;

    let signed_enroll_status = transformed.signed_enroll_status;

    Ok(signed_enroll_status)
}