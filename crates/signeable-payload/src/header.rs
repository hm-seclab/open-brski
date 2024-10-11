// shamelessly stolen from josekit

use crate::error::SigneableError;
use anyhow::bail;
use base64::prelude::*;
use serde_json::{Map, Value};
use std::{
    fmt::{Debug, Display},
    sync::LazyLock,
};

/// Represent JWS protected and unprotected header claims
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HeaderSet {
    pub(crate) protected: Map<String, Value>,
    pub(crate) unprotected: Map<String, Value>,
}

impl HeaderSet {
    /// Return a JwsHeader instance.
    pub fn new() -> Self {
        Self {
            protected: Map::new(),
            unprotected: Map::new(),
        }
    }

    /// Set a value for algorithm header claim (alg).
    ///
    /// # Arguments
    ///
    /// * `value` - a algorithm
    /// * `protection` - If it dosen't need protection, set false.
    pub fn set_algorithm(&mut self, value: impl Into<String>, protection: bool) {
        let key = "alg";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for algorithm header claim (alg).
    pub fn algorithm(&self) -> Option<&str> {
        match self.claim("alg") {
            Some(Value::String(val)) => Some(&val),
            _ => None,
        }
    }

    /// Return the value for JWK set URL header claim (jku).
    pub fn jwk_set_url(&self) -> Option<&str> {
        match self.claim("jku") {
            Some(Value::String(val)) => Some(val.as_str()),
            _ => None,
        }
    }

    /// Set a value for X.509 URL header claim (x5u).
    ///
    /// # Arguments
    ///
    /// * `value` - a X.509 URL
    pub fn set_x509_url(&mut self, value: impl Into<String>, protection: bool) {
        let key = "x5u";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return a value for a X.509 URL header claim (x5u).
    pub fn x509_url(&self) -> Option<&str> {
        match self.claim("x5u") {
            Some(Value::String(val)) => Some(val.as_str()),
            _ => None,
        }
    }

    /// Set values for X.509 certificate chain header claim (x5c).
    ///
    /// # Arguments
    ///
    /// * `values` - X.509 certificate chain
    pub fn set_x509_certificate_chain(&mut self, values: &Vec<impl AsRef<[u8]>>, protection: bool) {
        let key = "x5c";
        let vec = values
            .iter()
            .map(|v| Value::String(BASE64_STANDARD.encode(v)))
            .collect();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::Array(vec));
        } else {
            self.protected.remove(key);
            self.unprotected.insert(key.to_string(), Value::Array(vec));
        }
    }

    /// Return values for a X.509 certificate chain header claim (x5c).
    pub fn x509_certificate_chain(&self) -> Option<Vec<Vec<u8>>> {
        match self.claim("x5c") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => match BASE64_STANDARD.decode(val2) {
                            Ok(val3) => vec.push(val3.clone()),
                            Err(_) => return None,
                        },
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    /// Set a value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    ///
    /// # Arguments
    ///
    /// * `value` - A X.509 certificate SHA-1 thumbprint
    pub fn set_x509_certificate_sha1_thumbprint(
        &mut self,
        value: impl AsRef<[u8]>,
        protection: bool,
    ) {
        let key = "x5t";
        let value = BASE64_URL_SAFE_NO_PAD.encode(value);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claim("x5t") {
            Some(Value::String(val)) => match BASE64_URL_SAFE_NO_PAD.decode(val) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// Set a value for a x509 certificate SHA-256 thumbprint header claim (x5t#S256).
    ///
    /// # Arguments
    ///
    /// * `value` - A x509 certificate SHA-256 thumbprint
    pub fn set_x509_certificate_sha256_thumbprint(
        &mut self,
        value: impl AsRef<[u8]>,
        protection: bool,
    ) {
        let key = "x5t#S256";
        let value = BASE64_URL_SAFE_NO_PAD.encode(value);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for X.509 certificate SHA-256 thumbprint header claim (x5t#S256).
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claim("x5t#S256") {
            Some(Value::String(val)) => match BASE64_URL_SAFE_NO_PAD.decode(val) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// Set a value for key ID header claim (kid).
    ///
    /// # Arguments
    ///
    /// * `value` - a key ID
    pub fn set_key_id(&mut self, value: impl Into<String>, protection: bool) {
        let key = "kid";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for key ID header claim (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.claim("kid") {
            Some(Value::String(val)) => Some(val.as_str()),
            _ => None,
        }
    }

    /// Set a value for token type header claim (typ).
    ///
    /// # Arguments
    ///
    /// * `value` - a token type (e.g. "JWT")
    pub fn set_token_type(&mut self, value: impl Into<String>, protection: bool) {
        let key = "typ";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for token type header claim (typ).
    pub fn token_type(&self) -> Option<&str> {
        match self.claim("typ") {
            Some(Value::String(val)) => Some(val.as_str()),
            _ => None,
        }
    }

    /// Set a value for content type header claim (cty).
    ///
    /// # Arguments
    ///
    /// * `value` - a content type (e.g. "JWT")
    pub fn set_content_type(&mut self, value: impl Into<String>, protection: bool) {
        let key = "cty";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for content type header claim (cty).
    pub fn content_type(&self) -> Option<&str> {
        match self.claim("cty") {
            Some(Value::String(val)) => Some(val.as_str()),
            _ => None,
        }
    }

    /// Set values for critical header claim (crit).
    ///
    /// # Arguments
    ///
    /// * `values` - critical claim names
    pub fn set_critical(&mut self, values: &Vec<impl AsRef<str>>) {
        let key = "crit";
        let vec = values
            .iter()
            .map(|v| Value::String(v.as_ref().to_string()))
            .collect();
        self.unprotected.remove(key);
        self.protected.insert(key.to_string(), Value::Array(vec));
    }

    /// Return values for critical header claim (crit).
    pub fn critical(&self) -> Option<Vec<&str>> {
        match self.claim("crit") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => vec.push(val2.as_str()),
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    /// Set a value for base64url-encode payload header claim (b64).
    ///
    /// # Arguments
    ///
    /// * `value` - is base64url-encode payload
    pub fn set_base64url_encode_payload(&mut self, value: bool) {
        let key = "b64";
        self.unprotected.remove(key);
        self.protected.insert(key.to_string(), Value::Bool(value));
    }

    /// Return the value for base64url-encode payload header claim (b64).
    pub fn base64url_encode_payload(&self) -> Option<bool> {
        match self.claim("b64") {
            Some(Value::Bool(val)) => Some(*val),
            _ => None,
        }
    }

    /// Set a value for url header claim (url).
    ///
    /// # Arguments
    ///
    /// * `value` - a url
    pub fn set_url(&mut self, value: impl Into<String>, protection: bool) {
        let key = "url";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for url header claim (url).
    pub fn url(&self) -> Option<&str> {
        match self.claim("url") {
            Some(Value::String(val)) => Some(val.as_str()),
            _ => None,
        }
    }

    /// Set a value for a nonce header claim (nonce).
    ///
    /// # Arguments
    ///
    /// * `value` - A nonce
    pub fn set_nonce(&mut self, value: impl AsRef<[u8]>, protection: bool) {
        let key = "nonce";
        let value = BASE64_STANDARD_NO_PAD.encode(value);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for nonce header claim (nonce).
    pub fn nonce(&self) -> Option<Vec<u8>> {
        match self.claim("nonce") {
            Some(Value::String(val)) => match BASE64_URL_SAFE_NO_PAD.decode(val) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_claim(
        &mut self,
        key: &str,
        value: Option<Value>,
        protection: bool,
    ) -> Result<(), SigneableError> {
        match value {
            Some(val) => {
                check_claim(key, &val)?;
                if protection {
                    self.unprotected.remove(key);
                    self.protected.insert(key.to_string(), val);
                } else {
                    self.protected.remove(key);
                    self.unprotected.insert(key.to_string(), val);
                }
            }
            None => {
                self.protected.remove(key);
                self.unprotected.remove(key);
            }
        }

        Ok(())
    }

    /// Return values for header claims set
    pub fn claims_set(&self, protection: bool) -> &Map<String, Value> {
        if protection {
            &self.protected
        } else {
            &self.unprotected
        }
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut map = self.protected.clone();
        for (key, value) in &self.unprotected {
            map.insert(key.clone(), value.clone());
        }
        map
    }

    fn len(&self) -> usize {
        self.protected.len() + self.unprotected.len()
    }

    fn claim(&self, key: &str) -> Option<&Value> {
        if let Some(val) = self.protected.get(key) {
            Some(val)
        } else {
            self.unprotected.get(key)
        }
    }
}

impl Display for HeaderSet {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let protected = serde_json::to_string(&self.protected).map_err(|_e| std::fmt::Error {})?;
        let unprotected =
            serde_json::to_string(&self.unprotected).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str("{\"protected\":")?;
        fmt.write_str(&protected)?;
        fmt.write_str(",\"unprotected\":")?;
        fmt.write_str(&unprotected)?;
        fmt.write_str("}")?;
        Ok(())
    }
}

pub(crate) fn check_claim(key: &str, value: &Value) -> Result<(), SigneableError> {
    (|| -> anyhow::Result<()> {
        match key {
            "alg" | "jku" | "x5u" | "kid" | "typ" | "cty" | "url" => match &value {
                Value::String(_) => {}
                _ => bail!("The JWS {} header claim must be string.", key),
            },
            "crit" => match &value {
                Value::Array(vals) => {
                    for val in vals {
                        match val {
                            Value::String(_) => {}
                            _ => bail!(
                                "An element of the JWS {} header claim must be a string.",
                                key
                            ),
                        }
                    }
                }
                _ => bail!("The JWS {} header claim must be a array.", key),
            },
            "x5t" | "x5t#S256" | "nonce" => match &value {
                Value::String(val) => {
                    if !is_base64_urlsafe_nopad(val) {
                        bail!("The JWS {} header claim must be a base64 string.", key);
                    }
                }
                _ => bail!("The JWS {} header claim must be a string.", key),
            },
            "x5c" => match &value {
                Value::Array(vals) => {
                    for val in vals {
                        match val {
                            Value::String(val) => {
                                if !is_base64_standard(val) {
                                    bail!("The JWS {} header claim must be a base64 string.", key);
                                }
                            }
                            _ => bail!(
                                "An element of the JWS {} header claim must be a string.",
                                key
                            ),
                        }
                    }
                }
                _ => bail!("The JWS {} header claim must be a array.", key),
            },
            _ => {}
        }

        Ok(())
    })()
    .map_err(|err| SigneableError::InvalidHeaderFormat(err.to_string()))
}

pub(crate) fn is_base64_standard(input: &str) -> bool {
    static RE_BASE64_STANDARD: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$",
        )
        .unwrap()
    });

    RE_BASE64_STANDARD.is_match(input)
}

pub(crate) fn is_base64_urlsafe_nopad(input: &str) -> bool {
    static RE_BASE64_URL_SAFE_NOPAD: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$",
        )
        .unwrap()
    });

    RE_BASE64_URL_SAFE_NOPAD.is_match(input)
}
