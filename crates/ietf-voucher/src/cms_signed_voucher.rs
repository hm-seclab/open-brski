use openssl::{
    cms::CmsContentInfo,
    pkey::{HasPrivate, PKeyRef},
    stack::StackRef,
    x509::{store::X509StoreRef, X509Ref, X509},
};

use crate::{artifact::VoucherArtifact, cms, error::VoucherError};

/// A CMS Wrapped Voucher struct. This API is subject to change.
/// The CMSContentInfo structure is wrapped to ensure correct useage of API.
/// We also need to ensur that the CMS structure *always* wraps the voucher, it can not be passed in a detached state.
pub struct CMSSignedVoucher(CmsContentInfo);

impl CMSSignedVoucher {
    // Sign the voucher using a CMS signature.
    pub fn sign<T: HasPrivate>(
        voucher: VoucherArtifact,
        signcert: &X509Ref,
        pkey: &PKeyRef<T>,
        certs: Option<&StackRef<X509>>,
    ) -> Result<CMSSignedVoucher, VoucherError> {
        let data = cms::sign(voucher, signcert, pkey, certs)?;
        Ok(Self(data))
    }
    // Verify the voucher using a CMS signature. The only way to get a SignedVoucher is by verifying a CMS signature.
    pub fn verify_signature(
        &mut self,
        certs: Option<&StackRef<X509>>,
        store: Option<&X509StoreRef>,
    ) -> Result<VoucherArtifact, VoucherError> {
        let deserialized = cms::verify_signature::<VoucherArtifact>(&mut self.0, certs, store)?;
        Ok(deserialized)
    }

    pub fn to_pem(&self) -> Result<Vec<u8>, VoucherError> {
        let pem = self.0.to_pem()?;
        Ok(pem)
    }

    pub fn from_pem(pem: &[u8]) -> Result<CMSSignedVoucher, VoucherError> {
        let cms = CmsContentInfo::from_pem(pem)?;
        Ok(Self(cms))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[cfg(feature = "openssl")]
    fn test_cms_voucher_not_containing_ca_chain() {
        use example_certs::generate_certs;

        let voucher_request_json = r#"
        {
            "ietf-voucher:voucher": { 
                "assertion": "proximity",
                "serial-number": "JADA123456789",
                "expires-on": "2040-01-01T00:00:00.000Z",
                "proximity-registrar-cert": "base64encodedvalue=="
            }
        }
       "#;

        // generate voucher artifact
        let voucher_artifact =
            serde_json::from_str::<VoucherArtifact>(voucher_request_json).unwrap();

        // generate set of test certificates
        let certs: example_certs::OpensslTestCerts = generate_certs().into();

        // get the masa certificate to sign the voucher
        let (masa_cert, masa_key) = certs.vendor;

        // we also need the vendor_ca_cert on the pledge inside the x509 certificate store to verify the signature certificate.
        let (vendor_ca_cert, _) = certs.vendor_ca;

        // Genereate the voucher by signing the voucher artifact
        let cms_voucher = CMSSignedVoucher::sign(voucher_artifact, &masa_cert, &masa_key, None)
            .expect("Failed to sign voucher");

        // get the .pem formatted voucher
        let pem = cms_voucher.to_pem().expect("Failed to convert to pem");

        // deserialize the signed voucher from pem into the struct
        let mut deserialized = CMSSignedVoucher::from_pem(&pem).expect("Failed to deserialize");

        // build a new X509 Certificate store which includes the vendor ca. The certificate chain must exist so that the signature can be verified.
        let mut store = openssl::x509::store::X509StoreBuilder::new().unwrap();
        store.add_cert(vendor_ca_cert).unwrap();

        // build the store
        let final_store = store.build();

        // finally, verify the signature
        let voucher_artifact = deserialized
            .verify_signature(None, Some(&final_store))
            .expect("Failed to verify signature");

        // asserts!
        assert!(!pem.is_empty());
        assert!(voucher_artifact.details.serial_number == "JADA123456789")
    }

    #[test]
    #[cfg(feature = "openssl")]
    fn test_cms_voucher_containing_ca_chain() {
        use example_certs::generate_certs;
        use openssl::{stack::Stack, x509::X509};

        use crate::artifact::VoucherArtifact;

        let voucher_request_json = r#"
        {
            "ietf-voucher:voucher": { 
                "assertion": "proximity",
                "serial-number": "JADA123456789",
                "expires-on": "2040-01-01T00:00:00.000Z",
                "proximity-registrar-cert": "base64encodedvalue=="
            }
        }
       "#;

        // generate voucher artifact
        let voucher_artifact =
            serde_json::from_str::<VoucherArtifact>(voucher_request_json).unwrap();

        // generate set of test certificates
        let certs: example_certs::OpensslTestCerts = generate_certs().into();

        // get the masa certificate to sign the voucher
        let (masa_cert, masa_key) = certs.vendor;

        // we also need the vendor_ca_cert on the pledge inside the x509 certificate store to verify the signature certificate.
        let (vendor_ca_cert, _) = certs.vendor_ca;

        let mut certificate_stack: Stack<X509> = Stack::new().unwrap();

        // add the vendor_ca_cert to the certificate stack. This corresponds to RFC 8366 section 6.1 paragraph 6.
        certificate_stack.push(masa_cert.clone()).unwrap();
        certificate_stack.push(vendor_ca_cert.clone()).unwrap();

        // Genereate the voucher by signing the voucher artifact
        let cms_voucher = CMSSignedVoucher::sign(
            voucher_artifact,
            &masa_cert,
            &masa_key,
            Some(&certificate_stack),
        )
        .expect("Failed to sign voucher");

        // get the .pem formatted voucher
        let pem = cms_voucher.to_pem().expect("Failed to convert to pem");

        // deserialize the signed voucher from pem into the struct
        let mut deserialized = CMSSignedVoucher::from_pem(&pem).expect("Failed to deserialize");

        // build a new X509 Certificate store which includes the vendor ca. The certificate chain must exist so that the signature can be verified.
        let mut store = openssl::x509::store::X509StoreBuilder::new().unwrap();
        store.add_cert(vendor_ca_cert).unwrap();

        // build the store
        let final_store = store.build();

        // finally, verify the signature
        let voucher_artifact = deserialized
            .verify_signature(None, Some(&final_store))
            .expect("Failed to verify signature");

        // asserts!
        assert!(!pem.is_empty());
        assert!(voucher_artifact.details.serial_number == "JADA123456789")
    }
}
