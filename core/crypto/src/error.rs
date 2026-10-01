use std::fmt;

#[derive(Debug)]
pub enum Error {
    Kdf,
    Encrypt,
    Decrypt,
    Format(&'static str),
    Otp(&'static str),
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Kdf => write!(f, "key derivation failed"),
            Error::Encrypt => write!(f, "encryption failed"),
            Error::Decrypt => write!(f, "decryption failed (wrong password or corrupted data)"),
            Error::Format(m) => write!(f, "invalid data format: {m}"),
            Error::Otp(m) => write!(f, "invalid one-time-password data: {m}"),
            Error::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
