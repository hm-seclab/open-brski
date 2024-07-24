use std::sync::LazyLock;

use consts::ble::{TPVR_READ_UUID, TPVR_UUID, TPVR_WRITE_UUID};
use esp32_nimble::{BLEAdvertisementData, BLEDevice};
use esp32_nimble::utilities::BleUuid;
use esp_idf_svc::hal::delay::FreeRtos;
use log::info;

use crate::tpvr;

pub(crate) struct Uuids {
    pub tpvr: BleUuid,
    pub tpvr_read: BleUuid,
    pub tpvr_write: BleUuid,
}

pub(crate) static UUIDS: LazyLock<Uuids> = LazyLock::new(|| {
    //let private_key = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, PRIVATE_KEY, &ring::rand::SystemRandom::new()).unwrap();
    let tpvr = BleUuid::from_uuid128_string(TPVR_UUID).unwrap();
    let tpvr_read = BleUuid::from_uuid128_string(TPVR_READ_UUID).unwrap();
    let tpvr_write = BleUuid::from_uuid128_string(TPVR_WRITE_UUID).unwrap();

    Uuids {
        tpvr,
        tpvr_read,
        tpvr_write,
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

        let tpvr_handle = tpvr::handle_tpvr(server);

        let ble_advertiser = ble_device.get_advertising();
        ble_advertiser
            .lock()
            .set_data(
                BLEAdvertisementData::new()
                    .name("ESP32 Server")
                    .add_service_uuid(tpvr_handle),
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
