use openssl::{
    cms::CmsContentInfo,
    pkey::{HasPrivate, PKeyRef},
    stack::StackRef,
    x509::{store::X509StoreRef, X509Ref, X509},
};

use crate::{cms, error::VoucherError, request_artifact::VoucherRequestArtifact, VoucherRequest};

/// A CMS Wrapped Voucher Request struct. This API is subject to change.
/// The CMSContentInfo structure is wrapped to ensure correct useage of API.
/// We also need to ensur that the CMS structure *always* wraps the voucher, it can not be passed in a detached state.
pub struct CMSSignedVoucherRequest(CmsContentInfo);

impl CMSSignedVoucherRequest {
    // Sign the voucher using a CMS signature.
    pub fn sign<T: HasPrivate>(
        voucher: VoucherRequest,
        signcert: &X509Ref,
        pkey: &PKeyRef<T>,
        certs: Option<&StackRef<X509>>,
    ) -> Result<CMSSignedVoucherRequest, VoucherError> {
        let serialized = cms::sign(voucher, signcert, pkey, certs)?;
        Ok(Self(serialized))
    }

    pub fn verify_signature(
        &mut self,
        certs: Option<&StackRef<X509>>,
        store: Option<&X509StoreRef>,
    ) -> Result<VoucherRequestArtifact, VoucherError> {
        let deserialized =
            cms::verify_signature::<VoucherRequestArtifact>(&mut self.0, certs, store)?;
        Ok(deserialized)
    }

    pub fn to_pem(&self) -> Result<Vec<u8>, VoucherError> {
        let pem = self.0.to_pem()?;
        Ok(pem)
    }

    pub fn from_pem(pem: &[u8]) -> Result<CMSSignedVoucherRequest, VoucherError> {
        let cms = CmsContentInfo::from_pem(pem)?;
        Ok(Self(cms))
    }
}
