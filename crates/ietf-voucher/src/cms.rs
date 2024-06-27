use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    pkey::{HasPrivate, PKeyRef},
    stack::StackRef,
    x509::{store::X509StoreRef, X509Ref, X509},
};
use openssl_sys::CMS_BINARY;
use serde::{Deserialize, Serialize};

use crate::error::VoucherError;

pub fn sign<T: HasPrivate, V: Serialize>(
    voucher: V,
    signcert: &X509Ref,
    pkey: &PKeyRef<T>,
    certs: Option<&StackRef<X509>>,
) -> Result<CmsContentInfo, VoucherError> {
    // todo check if binary is correct here!
    let flags = CMSOptions::from_bits(CMS_BINARY).ok_or(VoucherError::InternalError)?;

    // TODO the content type should be "40". Rust Openssl can't do this (yet?) so we serialize into binary instead...
    let serialized = serde_json::to_string(&voucher).map_err(|_| VoucherError::InvalidVoucher)?; // .as_bytes(

    let data = serialized.as_bytes();

    let cms = CmsContentInfo::sign(Some(signcert), Some(pkey), certs, Some(data), flags)?;

    Ok(cms)
}

// Verify the voucher using a CMS signature. The only way to get a SignedVoucher is by verifying a CMS signature.
pub fn verify_signature<V: for<'de> Deserialize<'de>>(
    cms: &mut CmsContentInfo,
    certs: Option<&StackRef<X509>>,
    store: Option<&X509StoreRef>,
) -> Result<V, VoucherError> {
    let flags = CMSOptions::from_bits(CMS_BINARY).ok_or(VoucherError::InternalError)?;

    let output_data: &mut Vec<u8> = &mut Vec::new();

    // vouchers *must* be stored inside the CMS structure. We do not support detached data.
    // The trusted CA cert from which the signing certificate is derived must be provided in the store parameter.
    cms.verify(certs, store, None, Some(output_data), flags)
        .unwrap();

    let deserialized: V =
        serde_json::from_slice(output_data).map_err(|_| VoucherError::InvalidVoucher)?;

    Ok(deserialized)
}
