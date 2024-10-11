use std::sync::{Arc, Mutex};

use esp32_nimble::{utilities::BleUuid, BLEServer, NimbleProperties};
use log::info;
use serde::{Deserialize, Serialize};

use crate::{ble_async::UUIDBundle, ble_response::{IntoResponse, Response}};

pub struct BleRouter<'a> {
    server: &'a mut BLEServer,
    registered_handlers: Vec<&'a UUIDBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataFrameHeader {
    offset: usize,
    length: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataFrame {
    header: DataFrameHeader,
    data: Vec<u8>,
}


impl<'a> BleRouter<'a> {
    pub fn new(server: &'a mut BLEServer) -> BleRouter<'a> {
        BleRouter { server, registered_handlers: vec![] }
    }

    pub fn registered_handlers(&self) -> &Vec<&UUIDBundle> {
        &self.registered_handlers
    }

    pub fn route(
        &mut self,
        bundle: &'a UUIDBundle,
        handler: impl Fn<(Vec<u8>, ), Output = impl IntoResponse> + Send + Sync + 'static,
    ) -> &mut Self {
        let service = self.server.create_service(bundle.service);

        // Create a write characteristic
        let write_characteristic = service
            .lock()
            .create_characteristic(bundle.write, NimbleProperties::WRITE);

        // Create buffers for write and computed data
        let write_buf: Arc<Mutex<Vec<DataFrame>>> = Arc::new(Mutex::new(vec![]));
        let computed_buf = Arc::new(Mutex::new(vec![0u8; 0]));
        let computed_buf_ptr_copy = Arc::clone(&computed_buf);

        write_characteristic.lock().on_write(move |args| {
            //  Deserialize the received data
            let received_data = args.recv_data();
            let deserialized: DataFrame = ciborium::from_reader(received_data).unwrap();

            // Get the target length of the data
            let target_len = deserialized.header.length;

            // Get lock on write buffer and insert the deserialized data
            let write_buf_ref = &mut write_buf.lock().unwrap();
            write_buf_ref.insert(deserialized.header.offset, deserialized);

            if write_buf_ref.len() == target_len {
                // Check if the write buffer is full
                let entire_payload = write_buf_ref.iter().fold(vec![], |mut acc, df| {
                    acc.extend_from_slice(&df.data);
                    acc
                });
                // clear stack space
                write_buf_ref.clear();
                // Call handler with the entire payload
                let result: Response = handler.call((entire_payload, )).into_response();
                // get lock on computed buffer and clear it
                let computed_buf_ref = &mut computed_buf.lock().unwrap();
                computed_buf_ref.clear();
                computed_buf_ref.extend_from_slice(&result.data());
            }
        });

        let read_characteristic = service.lock().create_characteristic(
            bundle.read,
            NimbleProperties::READ | NimbleProperties::NOTIFY,
        );

        read_characteristic.lock().on_read(move |_this, _args| {
            info!("Read request received");
            info!("Value with len: {:?}", _this.len());
            info!("Value: {:?}", String::from_utf8_lossy(_this.value()));
            // compute chunk size
            let header_size = std::mem::size_of::<DataFrameHeader>();
            let transferrable_size = (_args.mtu() - 3) as usize;
            let chunk_size = transferrable_size - header_size;

            let computed_buf_ptr = computed_buf_ptr_copy.lock().unwrap();
            let chunk_iter = computed_buf_ptr.chunks(chunk_size as usize);
            for (index, chunk) in chunk_iter.enumerate() {
                let header = DataFrameHeader {
                    offset: index * chunk_size,
                    length: chunk.len(),
                };
                let df = DataFrame {
                    header,
                    data: chunk.to_vec(),
                };
                info!("Sending chunk: {:?}", String::from_utf8_lossy(&chunk));
                let mut buf = vec![0u8; 0];
                ciborium::into_writer(&df, &mut buf).unwrap();
                _this.set_value(&buf);
            }
        });

        self.registered_handlers.push(bundle);
        self
    }
}
