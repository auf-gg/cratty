#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Trailing,
    Empty,
    NotUtf8,
    TooLong { len: usize },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("кадр агента обрезан"),
            Self::Trailing => f.write_str("в кадре агента лишние байты"),
            Self::Empty => f.write_str("пустой кадр агента"),
            Self::NotUtf8 => f.write_str("имя в кадре агента не является текстом"),
            Self::TooLong { len } => {
                write!(f, "кадр агента длиной {len} байт больше допустимого")
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
