use std::{sync::{Arc, Mutex}, vec};

use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD};
use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};

use log::info;
use pledge_lib::tpvr::create_pvr;

use crate::{biscuit::{self, Base64Url}, ble_async::UUIDS, CREDENTIALS};

pub fn handle_tpvr(server: &mut BLEServer) -> BleUuid {
    let my_service = server.create_service(UUIDS.tpvr);

    info!(
        "Building TPVR write characteristic on broadcasting uid: {:?}",
        UUIDS.tpvr_write
    );

    let tpvr_write_characteristic = my_service
        .lock()
        .create_characteristic(UUIDS.tpvr_write, NimbleProperties::WRITE);

    info!(
        "Building TPVR read characteristic on broadcasting uid: {:?}",
        UUIDS.tpvr_read
    );
    let tpvr_read_characteristic = my_service.lock().create_characteristic(
        UUIDS.tpvr_read,
        NimbleProperties::READ | NimbleProperties::NOTIFY,
    );

    let write_buf = Arc::new(Mutex::new(vec![0u8; 0]));
    let computed_buf = Arc::new(Mutex::new(vec![0u8; 0])); 
    let computed_buf_ref = Arc::clone(&computed_buf);


    tpvr_read_characteristic.lock().on_read(move |_this, _args| {
        info!("Read request received");
        info!("Value with len: {:?}", _this.len());
        info!("Value: {:?}", String::from_utf8_lossy(_this.value()));
        let chunk_size = _args.mtu() - 3;
        let mut computed = computed_buf_ref.lock().unwrap();
        if computed.is_empty() {
            info!("Computed buffer is empty");
            _this.set_value("".as_bytes());
            return;
        }
        let drain_end = if computed.len() < chunk_size as usize {
            computed.len()
        } else {
            chunk_size as usize
        };
        let chunk = computed.drain(0..drain_end).collect::<Vec<u8>>();
        info!("Sending chunk: {:?}", String::from_utf8_lossy(&chunk));

        _this.set_value(&chunk);
    });

    tpvr_write_characteristic.lock().on_write(move |args| {
        info!("{}", String::from_utf8_lossy(args.recv_data()));
        info!("{}", String::from_utf8_lossy(args.current_data()));

        write_buf
            .lock()
            .unwrap()
            .extend(args.recv_data());

        if (args.recv_data().len() as u16) < args.desc().mtu() - 3 {
            //         println!("Received likely end of message data");

            let res: serde_json::Result<brski_prm_artifacts::pvr::trigger::Trigger> =
                serde_json::from_slice(&write_buf.lock().unwrap());

            let trigger = match res {
                Ok(trigger) => trigger,
                Err(e) => {
                    info!("Error deserializing trigger: {}", e);
                    return;
                }
            };

            // clear buf to make stack space
            write_buf.lock().unwrap().clear();
            info!("Trigger: {:?}", trigger);

            let voucher_request = pledge_lib::tpvr::create_pvr(trigger, "abcdefg".to_string());

            info!("Should be Voucher request: {:?}", voucher_request);

            info!("Prototype Voucher request: {:?}", voucher_request);

            let signeable = {
                let payload = serde_json::to_vec(&voucher_request).unwrap();

                let header = crate::biscuit::jws::Header::<crate::biscuit::Empty>::from(
                    crate::biscuit::jws::RegisteredHeader {
                        algorithm: crate::biscuit::jwa::SignatureAlgorithm::ES256,
                        // important to use base64 standard encoding
                        x509_chain: Some(vec![BASE64.encode(&CREDENTIALS.certificate)]),
                        media_type: Some("JWT".to_string()),
                        ..Default::default()
                    },
                );

                let signeable = crate::biscuit::jws::Signable::new(header, payload).unwrap();
                signeable
            };

            let secret =
                crate::biscuit::jws::Secret::EcdsaKeyPair(Arc::clone(&CREDENTIALS.private_key));
            unsafe {
                let watermark = esp_idf_svc::sys::uxTaskGetStackHighWaterMark(std::ptr::null_mut());
                info!("Watermark: {}", watermark);
            }

            info!("Signing data");
            let x = signeable.sign(secret).unwrap();
            info!("Serializing data");
            let serialized = x.serialize_general();
            
            info!("Set value with length: {}", tpvr_read_characteristic.lock().value_mut().len());
            computed_buf.lock().unwrap().extend(serialized.as_bytes());
            args.notify();
        }
    });

    // let shared_string = Arc::new(Mutex::new(String::from("")));

    // tpvr_write_characteristic.lock().on_write(move |args| {
    //     info!("{}", String::from_utf8_lossy(args.recv_data()));
    //     info!("{}", String::from_utf8_lossy(args.current_data()));

    //     shared_string
    //     .lock()
    //     .unwrap()
    //     .push_str(String::from_utf8_lossy(args.recv_data()).as_ref());

    //     //TODO there is a likely bug here, what if the last message is exactly the MTU size?
    //     // three bytes ble overhead as in Dart code
    //     if (args.recv_data().len() as u16) < args.desc().mtu() - 3 {
    //         println!("Received likely end of message data");
    //         let res: serde_json::Result<brski_prm_artifacts::pvr::trigger::Trigger> =
    //             serde_json::from_str(&shared_string.lock().unwrap());
    //         let trigger = match res {
    //             Ok(trigger) => trigger,
    //             Err(e) => {
    //                 info!("Error deserializing trigger: {}", e);
    //                 return;
    //             }
    //         };

    //         let voucher_request = pledge_lib::tpvr::create_pvr(trigger, "abcdefg".to_string());

    //         info!("Voucher request: {:?}", voucher_request);
    //         let signeable = {
    //             let payload = serde_json::to_vec(&voucher_request).unwrap();

    //             let header = crate::biscuit::jws::Header::<crate::biscuit::Empty>::from(
    //                 crate::biscuit::jws::RegisteredHeader {
    //                     algorithm: crate::biscuit::jwa::SignatureAlgorithm::ES256,
    //                     media_type: Some("JWT".to_string()),
    //                     ..Default::default()
    //                 },
    //             );

    //             let signeable = crate::biscuit::jws::Signable::new(header, payload).unwrap();
    //             signeable
    //         };

    //         let secret =
    //             crate::biscuit::jws::Secret::EcdsaKeyPair(Arc::clone(&CREDENTIALS.private_key));
    //         unsafe {
    //             let watermark = esp_idf_svc::sys::uxTaskGetStackHighWaterMark(std::ptr::null_mut());
    //             info!("Watermark: {}", watermark);
    //         }

    //         info!("Signing data");
    //         let x = signeable.sign(secret).unwrap();
    //         info!("Serializing data");
    //         let serialized = x.serialize_general();

    //         info!("Setting value");
    //         tpvr_read_characteristic
    //             .lock()
    //             .set_value(serialized.as_bytes())
    //             .notify();
    //     }

    // });

    info!(
        "Returning TPVR handle on broadcasting uid: {:?}",
        UUIDS.tpvr
    );
    UUIDS.tpvr
}
