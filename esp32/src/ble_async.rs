use std::sync::LazyLock;

use consts::ble::*;
use esp32_nimble::{BLEAdvertisementData, BLEDevice};
use esp32_nimble::utilities::BleUuid;
use esp_idf_svc::hal::delay::FreeRtos;
use log::info;

use crate::{ble_router::BleRouter, routes::{tper, tpvr}};

pub(crate) struct Uuids {
    pub tpvr: UUIDBundle,
    pub tper: UUIDBundle,
    pub svr: UUIDBundle,
    pub ser: UUIDBundle,
    pub scac: UUIDBundle,
    pub qps: UUIDBundle,
    pub pi: UUIDBundle,
    pub dif: UUIDBundle,
}
pub struct UUIDBundle {
    pub service: BleUuid,
    pub write: BleUuid,
    pub read: BleUuid,
}

pub(crate) static UUIDS: LazyLock<Uuids> = LazyLock::new(|| {
    //let private_key = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, PRIVATE_KEY, &ring::rand::SystemRandom::new()).unwrap();
    let tpvr_service = BleUuid::from_uuid128_string(TPVR_UUID).unwrap();
    let tpvr_read = BleUuid::from_uuid128_string(TPVR_READ_UUID).unwrap();
    let tpvr_write = BleUuid::from_uuid128_string(TPVR_WRITE_UUID).unwrap();

    let tper_service = BleUuid::from_uuid128_string(TPER_UUID).unwrap();
    let tper_read = BleUuid::from_uuid128_string(TPER_READ_UUID).unwrap();
    let tper_write = BleUuid::from_uuid128_string(TPER_WRITE_UUID).unwrap();

    let svr_service = BleUuid::from_uuid128_string(VOUCHER_UUID).unwrap();
    let svr_read = BleUuid::from_uuid128_string(VOUCHER_READ_UUID).unwrap();
    let svr_write = BleUuid::from_uuid128_string(VOUCHER_WRITE_UUID).unwrap();

    let ser_service = BleUuid::from_uuid128_string(ENROLL_RESPONSE_UUID).unwrap();
    let ser_read = BleUuid::from_uuid128_string(ENROLL_RESPONSE_READ_UUID).unwrap();
    let ser_write = BleUuid::from_uuid128_string(ENROLL_RESPONSE_WRITE_UUID).unwrap();

    let scac_service = BleUuid::from_uuid128_string(CA_CERTS_UUID).unwrap();
    let scac_read = BleUuid::from_uuid128_string(CA_CERTS_READ_UUID).unwrap();
    let scac_write = BleUuid::from_uuid128_string(CA_CERTS_WRITE_UUID).unwrap();

    let qps_service = BleUuid::from_uuid128_string(PLEDGE_STATUS_UUID).unwrap();
    let qps_read = BleUuid::from_uuid128_string(PLEDGE_STATUS_READ_UUID).unwrap();
    let qps_write = BleUuid::from_uuid128_string(PLEDGE_STATUS_WRITE_UUID).unwrap();

    let pi_service = BleUuid::from_uuid128_string(PLEDGE_INFO_UUID).unwrap();
    let pi_read = BleUuid::from_uuid128_string(PLEDGE_INFO_READ_UUID).unwrap();
    let pi_write = BleUuid::from_uuid128_string(PLEDGE_INFO_WRITE_UUID).unwrap();

    let dif_service = BleUuid::from_uuid128_string(PLEDGE_DATA_FORMAT_UUID).unwrap();
    let dif_read = BleUuid::from_uuid128_string(PLEDGE_DATA_FORMAT_READ_UUID).unwrap();
    let dif_write = BleUuid::from_uuid128_string(PLEDGE_DATA_FORMAT_WRITE_UUID).unwrap();

    Uuids {
        tpvr: UUIDBundle {
            service: tpvr_service,
            write: tpvr_write,
            read: tpvr_read,
        },
        tper: UUIDBundle {
            service: tper_service,
            write: tper_write,
            read: tper_read,
        },
        svr: UUIDBundle {
            service: svr_service,
            write: svr_write,
            read: svr_read,
        },
        ser: UUIDBundle {
            service: ser_service,
            write: ser_write,
            read: ser_read,
        },
        scac: UUIDBundle {
            service: scac_service,
            write: scac_write,
            read: scac_read,
        },
        qps: UUIDBundle {
            service: qps_service,
            write: qps_write,
            read: qps_read,
        },
        pi: UUIDBundle {
            service: pi_service,
            write: pi_write,
            read: pi_read,
        },
        dif: UUIDBundle {
            service: dif_service,
            write: dif_write,
            read: dif_read,
        },
    }
});

pub async fn run_ble() -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let ble_device = BLEDevice::take();
        let server = ble_device.get_server();
        unsafe {
            let mut preferred_mtu: u16;
            if(esp_idf_svc::sys::BLE_ATT_MTU_MAX < 500) {
                preferred_mtu = esp_idf_svc::sys::BLE_ATT_MTU_MAX as u16;
            } else {
                preferred_mtu = 500;
            }
            esp_idf_svc::sys::ble_att_set_preferred_mtu(preferred_mtu);
            info!("Preferred MTU set to {}", preferred_mtu);
        }

        server.on_connect(|server, client_desc| {
            info!("Connected to {:?}", client_desc);
            server
                .update_conn_params(client_desc.conn_handle(), 24, 48, 0, 60)
                .unwrap();
        });

        server.on_disconnect(|_server, client_desc| {
            info!("Disconnected from {:?}", client_desc);
        });

        let mut router = BleRouter::new(server);

        router
        .route(&UUIDS.tpvr, tpvr::handle_tpvr)
        .route(&UUIDS.tper, tper::handle_tper)
        .route(&UUIDS.svr, tper::handle_tper)
        .route(&UUIDS.ser, tper::handle_tper)
        .route(&UUIDS.scac, tper::handle_tper)
        .route(&UUIDS.qps, tper::handle_tper)
        .route(&UUIDS.pi, tper::handle_tper)
        .route(&UUIDS.dif, tper::handle_tper);

        let mut advertisement_data = BLEAdvertisementData::new();
        advertisement_data.name("ESP32 Server");
        for uuid in router.registered_handlers() {
            advertisement_data.add_service_uuid(uuid.service);
        }

        let ble_advertiser = ble_device.get_advertising();
        ble_advertiser
            .lock()
            .set_data(
                &mut advertisement_data
            )
            .unwrap();

        ble_advertiser.lock().start().unwrap();

        loop {
            //tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            FreeRtos::delay_ms(1000);
        }
        // let ble_scan = ble_device.get_scan();
        // ble_scan
        //     .active_scan(true)
        //     .interval(100)
        //     .window(99)
        //     .on_result(|_scan, param| {
        //         info!("Advertised Device: {:?}", param);
        //     });
        // ble_scan.start(5000).await.unwrap();
        // info!("Scan end");
    })
}
