use coset::RegisteredLabelWithPrivate;

use crate::algorithm::Algorithm;

pub fn match_algorithm(alg: Algorithm) -> &'static ring::signature::EcdsaSigningAlgorithm {
    match alg {
        Algorithm::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    }
}

pub fn match_algorithm_from_str(alg: &str) -> Option<coset::iana::Algorithm> {
    match alg {
        "ES256" => Some(coset::iana::Algorithm::ES256),
        _ => None,
    }
}

pub fn match_cose_algorithm_to_ring(
    alg: RegisteredLabelWithPrivate<coset::iana::Algorithm>,
) -> &'static ring::signature::EcdsaVerificationAlgorithm {
    let inner = match alg {
        RegisteredLabelWithPrivate::Assigned(alg) => alg,
        _ => unimplemented!(),
    };

    match inner {
        coset::iana::Algorithm::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED,
        _ => unimplemented!(),
    }
}

pub fn match_cose_algorithm(alg: RegisteredLabelWithPrivate<coset::iana::Algorithm>) -> Algorithm {
    let inner = match alg {
        RegisteredLabelWithPrivate::Assigned(alg) => alg,
        _ => unimplemented!(),
    };

    match inner {
        coset::iana::Algorithm::ES256 => Algorithm::ES256,
        _ => unimplemented!(),
    }
}
