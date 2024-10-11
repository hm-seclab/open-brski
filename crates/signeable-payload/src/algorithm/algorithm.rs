use core::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    ES256,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::ES256 => write!(f, "ES256"),
        }
    }
}
