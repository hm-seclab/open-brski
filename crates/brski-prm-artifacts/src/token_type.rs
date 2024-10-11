use serde::{Deserialize, Serialize};
use signeable_payload::SignatureType;

pub const JSON: &str = "application/json";

pub const CBOR: &str = "application/cbor";
pub const JWS_VOUCHER: &str = "application/voucher-jws+json";

pub const COSE_VOUCHER: &str = "application/voucher+cose";

pub const JOSE: &str = "application/jose+json";

pub const COSE: &str = "application/cose+cbor";

pub const PKCS7: &str = "application/pkcs7-mime";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataInterchangeFormat {
    JSON,
    CBOR,
}

impl DataInterchangeFormat {
    pub fn as_content_type(&self) -> &str {
        match self {
            DataInterchangeFormat::JSON => JSON,
            DataInterchangeFormat::CBOR => CBOR,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    Voucher(VoucherTokenType),
    Plain(PlainTokenType),
}

impl TokenType {
    pub fn as_content_type(&self) -> &str {
        match self {
            TokenType::Voucher(v) => v.as_content_type(),
            TokenType::Plain(p) => p.as_content_type(),
        }
    }

    pub fn as_token_type(&self) -> String {
        match self {
            TokenType::Voucher(v) => v.as_token_type(),
            TokenType::Plain(p) => p.as_token_type(),
        }
    }

    pub fn signature_type(&self) -> SignatureType {
        match self {
            TokenType::Voucher(v) => v.signature_type(),
            TokenType::Plain(p) => p.signature_type(),
        }
    }

    pub fn from_content_type(content_type: &str) -> Self {
        match content_type {
            JWS_VOUCHER => TokenType::Voucher(VoucherTokenType::JWS),
            COSE_VOUCHER => TokenType::Voucher(VoucherTokenType::COSE),
            JOSE => TokenType::Plain(PlainTokenType::JOSE),
            COSE => TokenType::Plain(PlainTokenType::COSE),
            _ => panic!("Unsupported content type: {}", content_type),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum VoucherTokenType {
    JWS,
    COSE,
}

impl VoucherTokenType {
    pub fn as_content_type(&self) -> &str {
        match self {
            VoucherTokenType::JWS => JWS_VOUCHER,
            VoucherTokenType::COSE => COSE_VOUCHER,
        }
    }

    pub fn as_token_type(&self) -> String {
        match self {
            VoucherTokenType::JWS => JWS_VOUCHER.replace("application/", ""),
            VoucherTokenType::COSE => COSE_VOUCHER.replace("application/", ""),
        }
    }

    pub fn signature_type(&self) -> SignatureType {
        match self {
            VoucherTokenType::JWS => SignatureType::JWS,
            VoucherTokenType::COSE => SignatureType::COSE,
        }
    }

    pub fn from_content_type(content_type: &str) -> Self {
        match content_type {
            JWS_VOUCHER => VoucherTokenType::JWS,
            COSE_VOUCHER => VoucherTokenType::COSE,
            _ => panic!("Unsupported content type: {}", content_type),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlainTokenType {
    JOSE,
    COSE,
}

impl PlainTokenType {
    pub fn as_content_type(&self) -> &str {
        match self {
            PlainTokenType::JOSE => JOSE,
            PlainTokenType::COSE => COSE,
        }
    }

    pub fn as_token_type(&self) -> String {
        match self {
            PlainTokenType::JOSE => JSON.replace("application/", ""),
            PlainTokenType::COSE => COSE.replace("application/", ""),
        }
    }

    pub fn signature_type(&self) -> SignatureType {
        match self {
            PlainTokenType::JOSE => SignatureType::JWS,
            PlainTokenType::COSE => SignatureType::COSE,
        }
    }

    pub fn from_content_type(content_type: &str) -> Self {
        match content_type {
            JOSE => PlainTokenType::JOSE,
            COSE => PlainTokenType::COSE,
            _ => panic!("Unsupported content type: {}", content_type),
        }
    }
}
