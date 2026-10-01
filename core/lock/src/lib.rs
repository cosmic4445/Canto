pub mod error;
pub mod folder;
pub mod shred;

pub use error::{LockError, Result};
pub use folder::{is_locked, lock_folder, unlock_folder, LockOptions, LockReport, UnlockReport};
