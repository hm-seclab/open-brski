use serde::{Deserialize, Serialize};

use crate::token_type::{DataInterchangeFormat, PlainTokenType, VoucherTokenType};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PledgeInfo {
    pub data_interchance_format: DataInterchangeFormat,
    pub supported_token_type: PlainTokenType,
    pub supported_voucher_type: VoucherTokenType,
}

impl PledgeInfo {
    pub fn simple_json() -> Self {
        Self {
            data_interchance_format: DataInterchangeFormat::JSON,
            supported_token_type: PlainTokenType::JOSE,
            supported_voucher_type: VoucherTokenType::JWS,
        }
    }

    pub fn simple_cbor() -> Self {
        Self {
            data_interchance_format: DataInterchangeFormat::CBOR,
            supported_token_type: PlainTokenType::COSE,
            supported_voucher_type: VoucherTokenType::COSE,
        }
    }
}
