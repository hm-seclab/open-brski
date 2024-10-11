pub trait VerifyingContext {
    fn get_public_key(&self) -> Option<Vec<u8>>;
}

#[derive(Debug, Clone, Default)]
pub struct BasicVeryingContext {
    pub pub_key: Option<Vec<u8>>,
}

impl VerifyingContext for BasicVeryingContext {
    fn get_public_key(&self) -> Option<Vec<u8>> {
        self.pub_key.clone()
    }
}
