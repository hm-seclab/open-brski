use std::ops::Deref;

use crate::artifact::VoucherArtifact;

/// A fully verified Voucher object that has been verified by the verification function.
pub struct VerifiedVoucher(pub VoucherArtifact);

impl Deref for VerifiedVoucher {
    type Target = VoucherArtifact;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
