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
            Self::Format(what) => write!(f, "формат записи не разобран: {what}"),
            Self::Body(what) => write!(f, "тело записи не разобрано: {what}"),
            Self::EnvelopeMismatch(what) => write!(
                f,
                "конверт записи не совпадает с зашифрованным содержимым: {what}"
            ),
            Self::Vault(error) => write!(f, "{error}"),
            Self::Rng => f.write_str("операционная система не выдала случайные байты"),
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
