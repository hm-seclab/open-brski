use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(feature = "json")]
#[derive(Debug, Clone)]
pub struct DecodedJWS<T: Serialize + DeserializeOwned + std::clone::Clone> {
    pub payload: T,
    pub(crate) header_set: Option<josekit::jws::JwsHeaderSet>,
    pub header: Option<josekit::jws::JwsHeader>,
}

#[cfg(not(feature = "json"))]
#[derive(Debug, Clone)]
pub struct DecodedJWS<T: Serialize + DeserializeOwned + std::clone::Clone> {
    pub payload: T,
}
