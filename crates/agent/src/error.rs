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
            Self::Truncated => f.write_str("agent frame truncated"),
            Self::Trailing => f.write_str("extra bytes in the agent frame"),
            Self::Empty => f.write_str("empty agent frame"),
            Self::NotUtf8 => f.write_str("name in the agent frame is not text"),
            Self::TooLong { len } => {
                write!(f, "agent frame of {len} bytes exceeds the allowed size")
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
