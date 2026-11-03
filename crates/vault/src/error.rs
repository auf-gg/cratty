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
                f.write_str("не удалось расшифровать: неверный ключ или данные повреждены")
            }
            Self::Rng => f.write_str("операционная система не выдала случайные байты"),
            Self::Kdf(what) => write!(f, "вывод ключа из пароля не удался: {what}"),
            Self::Params(what) => write!(f, "недопустимые параметры Argon2id: {what}"),
            Self::Format(what) => write!(f, "формат не разобран: {what}"),
            Self::RecoveryCode(what) => write!(f, "код восстановления не принят: {what}"),
            Self::Signature => f.write_str("подпись неверна"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
