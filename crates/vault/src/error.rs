use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Decrypt,
    Rng,
    Kdf(&'static str),
    Params(&'static str),
    Format(&'static str),
    RecoveryCode(&'static str),
    Signature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decrypt => {
                f.write_str("decryption failed: wrong key or corrupted data")
            }
            Self::Rng => f.write_str("the operating system did not provide random bytes"),
            Self::Kdf(what) => write!(f, "password key derivation failed: {what}"),
            Self::Params(what) => write!(f, "invalid Argon2id parameters: {what}"),
            Self::Format(what) => write!(f, "format could not be parsed: {what}"),
            Self::RecoveryCode(what) => write!(f, "recovery code rejected: {what}"),
            Self::Signature => f.write_str("invalid signature"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
