use std::{
    sync::{Arc, Mutex},
    vec,
};

use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD};
use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};

use log::info;
use signeable_payload::BasicSigningContext;

use crate::{
    ble_async::UUIDS,
    CREDENTIALS, PLEDGE_INFO,
};

pub fn handle_pi(data: Vec<u8>) -> anyhow::Result<Vec<u8>> {

    let pledge_info = PLEDGE_INFO.clone();
    let mut buf = vec![];
    ciborium::into_writer(&pledge_info, &mut buf)?;

    Ok(buf)
}