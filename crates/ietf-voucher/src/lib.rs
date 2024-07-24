#![feature(cfg_eval)]
pub mod artifact;
pub mod assertion;
///
/// # Voucher
///
/// Voucher reference implementation as per [RFC 8366 - A Voucher Artifact for Bootstrapping Protocols](https://datatracker.ietf.org/doc/html/rfc8366) and
/// [RFC 8995 - Manufacturer Usage Description Specification](https://datatracker.ietf.org/doc/html/rfc8995)
///
/// ## Usage
/// This module comes with simple serde deserializing and serializing functions for the Voucher struct.
/// By default, a json encoded voucher is deserialized into the VoucherRequest struct, which itself contains a VoucherArtifact.
/// This artifact is a 1:1 representation of the encoded voucher without any verification.
///
/// To get ahold of a verified voucher, you need to use the Voucher struct.
///
/// For simplified use, you can parse the JSON encoded voucher into a Voucher struct by calling `serde_json::try_from(json: &str) -> Result<Voucher, Error>`.
pub mod error;
pub mod request_artifact;
pub mod target;
pub mod verified;

pub mod agent_signed_data;

mod util;
pub use util::pki;

use request_artifact::VoucherRequestArtifact;

pub type VoucherRequest = VoucherRequestArtifact;

pub const VOUCHER_MEDIA_TYPE: &str = "voucher-cms+json";
pub const VOUCHER_MIME_TYPE: &str = "application/voucher-cms+json";

pub const VOUCHER_FILE_TYPE: &str = ".vcj";
