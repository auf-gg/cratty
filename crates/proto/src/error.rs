use core::fmt;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Format(&'static str),
    Body(String),
    EnvelopeMismatch(&'static str),
    Vault(vault::Error),
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(what) => write!(f, "record format could not be parsed: {what}"),
            Self::Body(what) => write!(f, "record body could not be parsed: {what}"),
            Self::EnvelopeMismatch(what) => write!(
                f,
                "record envelope does not match the encrypted content: {what}"
            ),
            Self::Vault(error) => write!(f, "{error}"),
            Self::Rng => f.write_str("the operating system did not provide random bytes"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Vault(error) => Some(error),
            _ => None,
        }
    }
}

impl From<vault::Error> for Error {
    fn from(error: vault::Error) -> Self {
        Self::Vault(error)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
