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

pub fn handle_dif(data: Vec<u8>) -> Vec<u8> {

    let content_type = PLEDGE_INFO.data_interchance_format.as_content_type();

    content_type.as_bytes().to_vec()
}