
#![feature(lazy_cell)]
#![feature(unboxed_closures)]
#![feature(fn_traits)]
use std::sync::{Arc, LazyLock};


use ble_async::run_ble;

use brski_prm_artifacts::pledge_info::PledgeInfo;
use esp_idf_svc::eventloop::EspSystemEventLoop;

use esp_idf_svc::wifi::{AsyncWifi, EspWifi};
use esp_idf_svc::{hal::peripherals::Peripherals, nvs::EspDefaultNvsPartition};
use ietf_voucher::pki::X509;
use tokio::join;
mod ble_async;
mod wifi_async;
mod ble_router;
pub mod routes;
pub mod ble_response;
use log::info;

use wifi_async::{run_wifi};


//static CERTIFICATE : &[u8] = include_bytes!("../data/pledge.der");
//static PRIVATE_KEY : &[u8] = include_bytes!("../data/key.der");

struct Credentials {
    pub certificate: &'static [u8],
    pub cert_chain: Vec<X509>,
    pub private_key: &'static [u8],
    pub serial_number: &'static str,
}

static CREDENTIALS: LazyLock<Credentials> = LazyLock::new(|| {
    //let private_key = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, PRIVATE_KEY, &ring::rand::SystemRandom::new()).unwrap();
    let rng = ring::rand::SystemRandom::new();
    let key_data = include_bytes!("../data/private_key.der");
    // convert key_data to ring format 
    // let keypair = ring::signature::EcdsaKeyPair::from_pkcs8(
    //     &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    //     key_data.as_ref(),
    //     &rng,
    // )
    // .unwrap();

    

    let certificate = include_bytes!("../data/pledge.der");
    let converted = X509::try_from(certificate.to_vec()).unwrap();
    let serial_number = "1234567890";

    Credentials {
        certificate,
        private_key: key_data,
        cert_chain: vec![converted],
        serial_number
    }
});

static PLEDGE_INFO: LazyLock<PledgeInfo> = LazyLock::new(|| {
    PledgeInfo::simple_cbor()
});


fn main() {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    // Bind the log crate to the ESP Logging facilities
    esp_idf_svc::log::EspLogger::initialize_default();

    // eventfd is needed by our mio poll implementation.  Note you should set max_fds
    // higher if you have other code that may need eventfd.
    //info!("Setting up eventfd...");
    esp_idf_svc::io::vfs::initialize_eventfd(1).unwrap();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            // we run join handles to run *parallel* to avoid blocking the main thread
            run().await;
        });
}

async fn run() {
    let peripherals = Peripherals::take().expect("Unable to gather peripherals");
    let sysloop = EspSystemEventLoop::take().expect("Unable to gather system event loop");
    let timer = esp_idf_svc::timer::EspTaskTimerService::new().unwrap();
    let nvs = EspDefaultNvsPartition::take().expect("Unable to gather NVS partition");

    let esp_wifi = EspWifi::new(peripherals.modem, sysloop.clone(), Some(nvs))
        .expect("Unable to gather EspWifi");

    let wifi = AsyncWifi::wrap(esp_wifi, sysloop, timer).expect("Unable to gather AsyncWifi");

    info!("Starting async run loop");

    join!(run_wifi(wifi), run_ble());

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
