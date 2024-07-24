#[derive(Debug, Clone)]
pub struct ValidityCtx<'a> {
    pub serial: Option<&'a str>,
    pub idevid_isser_kid: Option<&'a str>,
    pub nonce: Option<&'a str>,
}

impl core::default::Default for ValidityCtx<'_> {
    fn default() -> Self {
        Self {
            serial: None,
            idevid_isser_kid: None,
            nonce: None,
        }
    }
}
