use std::{
    sync::{Arc, Mutex},
    vec,
};

use brski_prm_artifacts::{status::pledge::status::{PledgeStatus, PledgeStatusQuery}, token_type::{self, PlainTokenType}};
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD};
use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};

use log::info;
use pledge_lib::qps::TransformQpsArgs;
use signeable_payload::{BasicSigningContext, RawSigned, Signed};

use crate::{
    ble_async::UUIDS,
    CREDENTIALS,
};

pub fn handle_qps(data: Vec<u8>) -> anyhow::Result<Signed<PledgeStatus>> {

    let args: TransformQpsArgs = TransformQpsArgs {
        token_type: PlainTokenType::COSE,
        raw_status_query: data,
        pledge_idevid_chain: CREDENTIALS.cert_chain.clone(),
        pledge_idevid_key: CREDENTIALS.private_key.to_vec(),

    };

    let tranformed = pledge_lib::qps::transform_qps(args)?;

    Ok(tranformed)
}