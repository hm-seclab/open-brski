use thiserror::Error;
#[derive(Error, Debug)]
pub enum VoucherError {
    #[error("Invalid Voucher")]
    InvalidVoucher,
    #[error("Malformed Voucher - Reason {0}")]
    MalformedVoucher(String),
    #[error("Invalid Expiry (expires after created)")]
    InvalidExpiry,
    #[error("Voucher already expired")]
    ExpiredVoucher,
    #[error("Invalid Voucher for rtc-less pledge")]
    ClockRequired,
    #[error("Voucher serial does not match pledge serial")]
    SerialMismatch,
    #[error("Voucher issuer kid required from pledge's IDevID certificate to check if it matches the voucher's issuer kid value")]
    IssuerKidRequired,
    #[error("Pledge needs to provide the nonce it sent during the bootstrap process to compare it to the nonce contained in the voucher")]
    NonceRequired,
    #[error("Voucher nonce does not match pledge nonce")]
    NonceMismatch,

    #[error("Missing pinnsed-domain-cert field in voucher on pledge. See more at RFC 8995 section 5.6.1")]
    MissingPinnedDomainCert,

    #[cfg(feature = "openssl")]
    #[error("Openssl error")]
    OpensslError {
        #[from]
        source: openssl::error::ErrorStack,
    },
    #[error("Internal crate error. Please report this issue.")]
    InternalError,
    #[error("Invalid Expiry (expires after created)")]
    MalformedAgentSignedData(String),

    #[cfg(feature = "json")]
    #[error("JWS error")]
    JWSError(#[from] josekit::JoseError),
}
