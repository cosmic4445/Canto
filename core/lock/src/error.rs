use std::fmt;

#[derive(Debug)]
pub enum LockError {
    Crypto(canto_crypto::Error),
    Io(std::io::Error),
    AlreadyLocked,
    NotLocked,
    WrongPassword,
    Unsafe(&'static str),
    Corrupt(&'static str),
}

pub type Result<T> = std::result::Result<T, LockError>;

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Crypto(e) => write!(f, "{e}"),
            LockError::Io(e) => write!(f, "i/o error: {e}"),
            LockError::AlreadyLocked => write!(f, "folder is already locked"),
            LockError::NotLocked => write!(f, "folder is not locked"),
            LockError::WrongPassword => write!(f, "wrong password"),
            LockError::Unsafe(m) => write!(f, "refusing to continue: {m}"),
            LockError::Corrupt(m) => write!(f, "lock data is corrupt: {m}"),
        }
    }
}

impl std::error::Error for LockError {}

impl From<std::io::Error> for LockError {
    fn from(e: std::io::Error) -> Self {
        LockError::Io(e)
    }
}

impl From<canto_crypto::Error> for LockError {
    fn from(e: canto_crypto::Error) -> Self {
        LockError::Crypto(e)
    }
}
