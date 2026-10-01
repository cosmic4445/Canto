use crate::error::{Error, Result};
use crate::util::random_bytes;
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < 8
            || self.memory_kib > 1024 * 1024
            || self.iterations == 0
            || self.iterations > 32
            || self.parallelism == 0
            || self.parallelism > 16
        {
            return Err(Error::Format("unsupported key derivation parameters"));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.memory_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.iterations.to_le_bytes());
        out[8..12].copy_from_slice(&self.parallelism.to_le_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 12 {
            return Err(Error::Format("truncated key derivation parameters"));
        }
        let p = KdfParams {
            memory_kib: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            iterations: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            parallelism: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        };
        p.validate()?;
        Ok(p)
    }
}

pub fn random_salt() -> [u8; SALT_LEN] {
    random_bytes::<SALT_LEN>()
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    params.validate()?;
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut out[..])
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}
