use consts::ble::*;

#[derive(Default, Clone)]
pub struct Identifier {
    pub uuid: String,
    pub read_uuid: String,
    pub write_uuid: String,
}

impl Identifier {
    pub fn get_uuid(&self) -> String {
        self.uuid.clone()
    }

    pub fn get_read_uuid(&self) -> String {
        self.read_uuid.clone()
    }

    pub fn get_write_uuid(&self) -> String {
        self.write_uuid.clone()
    }
}

#[derive(Default, Clone)]
pub struct BleIdentifiers {
    pub tpvr: Identifier,
    pub tper: Identifier,
    pub voucher: Identifier,
    pub ca_certs: Identifier,
    pub enroll_response: Identifier,
} 

impl BleIdentifiers {
    pub fn new() -> Self {
        BleIdentifiers {
            tpvr: Identifier {
                uuid: TPVR_UUID.to_string(),
                read_uuid: TPVR_READ_UUID.to_string(),
                write_uuid: TPVR_WRITE_UUID.to_string(),
            },
            tper: Identifier {
                uuid: TPER_UUID.to_string(),
                read_uuid: TPER_READ_UUID.to_string(),
                write_uuid: TPER_WRITE_UUID.to_string(),
            },
            voucher: Identifier {
                uuid: VOUCHER_UUID.to_string(),
                read_uuid: VOUCHER_READ_UUID.to_string(),
                write_uuid: VOUCHER_WRITE_UUID.to_string(),
            },
            ca_certs: Identifier {
                uuid: CA_CERTS_UUID.to_string(),
                read_uuid: CA_CERTS_READ_UUID.to_string(),
                write_uuid: CA_CERTS_WRITE_UUID.to_string(),
            },
            enroll_response: Identifier {
                uuid: ENROLL_RESPONSE_UUID.to_string(),
                read_uuid: ENROLL_RESPONSE_READ_UUID.to_string(),
                write_uuid: ENROLL_RESPONSE_WRITE_UUID.to_string(),
            },
        }
    }

    pub fn get_tpvr(&self) -> Identifier {
        self.tpvr.clone()
    }

    pub fn get_tper(&self) -> Identifier {
        self.tper.clone()
    }

    pub fn get_voucher(&self) -> Identifier {
        self.voucher.clone()
    }

    pub fn get_ca_certs(&self) -> Identifier {
        self.ca_certs.clone()
    }

    pub fn get_enroll_response(&self) -> Identifier {
        self.enroll_response.clone()
    }
}

pub fn get_identifiers() -> BleIdentifiers {
    BleIdentifiers::new()
}