use crate::{algorithm::Algorithm, header::HeaderSet};

pub trait SigningContext {
    fn set_skid(&mut self, skid: Option<String>) -> &mut Self;
    fn get_skid(&self) -> Option<String>;

    fn set_algorithm(&mut self, algorithm: Algorithm) -> &mut Self;

    fn get_algorithm(&self) -> Algorithm;
}

pub struct BasicSigningContext {
    skid: Option<String>,
    algorithm: Algorithm,
}

impl SigningContext for BasicSigningContext {
    fn get_skid(&self) -> Option<String> {
        self.skid.clone()
    }

    fn set_skid(&mut self, skid: Option<String>) -> &mut Self {
        self.skid = skid;
        self
    }

    fn set_algorithm(&mut self, algorithm: Algorithm) -> &mut Self {
        self.algorithm = algorithm;
        self
    }

    fn get_algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

impl BasicSigningContext {
    pub fn new() -> Self {
        Self {
            skid: None,
            algorithm: Algorithm::ES256,
        }
    }

    pub fn with_alg(algorithm: Algorithm) -> Self {
        Self {
            skid: None,
            algorithm,
        }
    }
}
