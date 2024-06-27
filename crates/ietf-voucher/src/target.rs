pub struct PledgeValidityInfo<'a> {
    pub serial: &'a str,
    pub idevid_isser_kid: Option<&'a str>,
    pub nonce: Option<&'a str>,
}

pub enum VoucherTarget<'a> {
    MASA,
    Pledge(PledgeValidityInfo<'a>),
    Registrar,
    RegistrarAgent,
    Other,
}
