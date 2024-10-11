use std::{
    sync::{Arc, Mutex},
    vec,
};

use brski_prm_artifacts::token_type::PlainTokenType;
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD};
use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};


use ietf_voucher::request_artifact::VoucherRequestArtifact;
use log::info;
use pledge_lib::tpvr::TransformTpvrArgs;
use signeable_payload::Signed;

use crate::{
    CREDENTIALS,
};

pub fn handle_tpvr(data: Vec<u8>) -> anyhow::Result<Signed<VoucherRequestArtifact>> {

    let trigger: brski_prm_artifacts::pvr::trigger::VoucherRequestTrigger = ciborium::from_reader(&data[..]).unwrap();

    info!("Trigger: {:?}", trigger);

    let args: TransformTpvrArgs = TransformTpvrArgs {
        trigger: trigger.clone(),
        requested_token_type: brski_prm_artifacts::token_type::VoucherTokenType::COSE,
        pledge_idevid_key: CREDENTIALS.private_key.to_vec(),
        pledge_idevid_chain: CREDENTIALS.cert_chain.clone(),
        serial_number: CREDENTIALS.serial_number.to_owned()
    };

    let vra = pledge_lib::tpvr::transform_tpvr(args)?;

    unsafe {
        let watermark = esp_idf_svc::sys::uxTaskGetStackHighWaterMark(std::ptr::null_mut());
        info!("Watermark: {}", watermark);
    }

    Ok(vra)
}