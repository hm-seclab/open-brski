use ciborium::Value;
use coset::{
    iana::{EnumI64, HeaderParameter},
    RegisteredLabel,
};
use serde_json::Map;

use crate::header::HeaderSet;

use super::alg::{match_algorithm, match_algorithm_from_str, match_cose_algorithm};

impl From<HeaderSet> for (coset::Header, coset::Header) {
    fn from(value: HeaderSet) -> Self {
        into_coset_header(value)
    }
}
fn into_coset_header(header: HeaderSet) -> (coset::Header, coset::Header) {
    let mut unprotected = coset::HeaderBuilder::new();
    let mut protected = coset::HeaderBuilder::new();

    if let Some(alg) = header.algorithm() {
        if header.claims_set(true).contains_key("alg") {
            protected = protected.algorithm(match_algorithm_from_str(alg).unwrap());
        } else {
            unprotected = unprotected.algorithm(match_algorithm_from_str(alg).unwrap());
        }
    }

    if let Some(cty) = header.content_type() {
        if header.claims_set(true).contains_key("cty") {
            protected = protected.content_type(cty.to_string());
        } else {
            unprotected = unprotected.content_type(cty.to_string());
        }
    }

    if let Some(kid) = header.key_id() {
        if header.claims_set(true).contains_key("kid") {
            protected = protected.key_id(kid.bytes().collect());
        } else {
            unprotected = unprotected.key_id(kid.bytes().collect());
        }
    }

    if let Some(x5u) = header.x509_url() {
        if header.claims_set(true).contains_key("x5u") {
            protected = protected.value(
                coset::iana::HeaderParameter::X5U.to_i64(),
                ciborium::Value::Text((x5u.to_string())),
            );
        } else {
            unprotected = unprotected.value(
                coset::iana::HeaderParameter::X5U.to_i64(),
                ciborium::Value::Text((x5u.to_string())),
            );
        }
    }

    if let Some(x5c) = header.x509_certificate_chain() {
        if header.claims_set(true).contains_key("x5c") {
            protected = protected.value(
                coset::iana::HeaderParameter::X5Chain.to_i64(),
                ciborium::Value::Array(
                    x5c.iter()
                        .map(|x| ciborium::Value::Bytes(x.clone()))
                        .collect(),
                ),
            );
        } else {
            unprotected = unprotected.value(
                coset::iana::HeaderParameter::X5Chain.to_i64(),
                ciborium::Value::Array(
                    x5c.iter()
                        .map(|x| ciborium::Value::Bytes(x.clone()))
                        .collect(),
                ),
            );
        }
    }

    if let Some(x5t) = header.x509_certificate_sha1_thumbprint() {
        if header.claims_set(true).contains_key("x5t") {
            protected = protected.value(
                coset::iana::HeaderParameter::X5T.to_i64(),
                ciborium::Value::Bytes(x5t.clone()),
            );
        } else {
            unprotected = unprotected.value(
                coset::iana::HeaderParameter::X5T.to_i64(),
                ciborium::Value::Bytes(x5t.clone()),
            );
        }
    }

    (unprotected.build(), protected.build())
}

impl From<(coset::Header, coset::Header)> for HeaderSet {
    fn from(value: (coset::Header, coset::Header)) -> Self {
        let mut set = Self::new();
        into_header_set(value.0, &mut set, false);
        into_header_set(value.1, &mut set, true);
        set
    }
}

fn into_header_set(header: coset::Header, header_set: &mut HeaderSet, protection: bool) {
    if let Some(alg) = header.alg {
        let matched = match_cose_algorithm(alg);
        header_set.set_algorithm(matched.to_string(), protection)
    }

    if let Some(cty) = header.content_type {
        let matched = match cty {
            RegisteredLabel::Assigned(_) => unimplemented!(),
            RegisteredLabel::Text(cty) => cty,
        };
        header_set.set_content_type(matched, protection);
    }

    if let Ok(kid) = String::from_utf8(header.key_id) {
        header_set.set_key_id(kid, protection);
    }

    if let Some((_, x5u)) = header
        .rest
        .iter()
        .find(|(key, _)| key == &coset::Label::Int(coset::iana::HeaderParameter::X5U.to_i64()))
    {
        if let Value::Text(x5u) = x5u {
            header_set.set_x509_url(x5u, protection);
        }
    }

    if let Some((_, x5c)) = header
        .rest
        .iter()
        .find(|(key, _)| key == &coset::Label::Int(coset::iana::HeaderParameter::X5Chain.to_i64()))
    {
        if let Value::Array(x5c) = x5c {
            let mapped: Vec<Vec<u8>> = x5c
                .iter()
                .map(|x| {
                    if let Value::Bytes(x) = x {
                        x.clone()
                    } else {
                        unimplemented!()
                    }
                })
                .collect();
            header_set.set_x509_certificate_chain(&mapped, protection);
        }
    }

    if let Some((_, x5t)) = header
        .rest
        .iter()
        .find(|(key, _)| key == &coset::Label::Int(coset::iana::HeaderParameter::X5T.to_i64()))
    {
        if let Value::Bytes(x5t) = x5t {
            header_set.set_x509_certificate_sha1_thumbprint(x5t.clone(), protection);
        }
    }
}
