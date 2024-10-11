use crate::algorithm::Algorithm;

pub fn match_algorithm(alg: Algorithm) -> josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm {
    match alg {
        Algorithm::ES256 => josekit::jws::ES256,
    }
}
