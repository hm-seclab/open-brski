use std::{
    sync::{Arc, Mutex},
    vec,
};

use brski_prm_artifacts::{cacerts::response_payload::CaCerts, token_type::PlainTokenType};
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD};
use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};

use log::info;
use signeable_payload::{BasicSigningContext, RawSigned};

use crate::{
    ble_async::UUIDS,
    CREDENTIALS,
};

pub fn handle_scac(data: Vec<u8>) {

    let signed_cacerts: RawSigned<CaCerts> = RawSigned::new(data);

    let token_type = PlainTokenType::COSE;

    let verifier = token_type.signature_type().get_sv::<CaCerts>().unwrap();

    let decoded = signed_cacerts.into_verifyable_boxed(verifier).verify(Default::default()).unwrap();

    let ca_certs = decoded.payload().clone().x5bag;
}