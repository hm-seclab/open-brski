use std::{
    sync::{Arc, Mutex},
    vec,
};

use brski_prm_artifacts::per::response_payload::PledgeEnrollRequest;
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD};
use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};

use ietf_voucher::pki::X509;
use log::info;
use pledge_lib::tper::{transform_per, TransformPerArgs};
use signeable_payload::{BasicSigningContext, Signed, Unsigned};

use crate::{
    ble_async::UUIDS,
    CREDENTIALS,
};

pub fn handle_tper(data: Vec<u8>) -> anyhow::Result<Signed<PledgeEnrollRequest>> {

    // verification needed
    let _payload: brski_prm_artifacts::per::trigger::EnrollTrigger = ciborium::from_reader(&data[..])?;

    let csr = pledge_lib::csr::create_csr(&CREDENTIALS.private_key);
    let cert = X509::try_from(CREDENTIALS.certificate.to_vec())?;
    let args: TransformPerArgs = TransformPerArgs {
        x509_req: csr,
        signature_type: brski_prm_artifacts::token_type::PlainTokenType::COSE,
        pledge_idevid_key: CREDENTIALS.private_key.to_vec(),
        pledge_idevid_chain: vec![cert],
    };

    let transformed = transform_per(args)?;

    Ok(transformed)
}