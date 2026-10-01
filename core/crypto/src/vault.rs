use crate::aead;
use crate::error::{Error, Result};
use crate::kdf::{derive_key, random_salt, KdfParams, KEY_LEN, SALT_LEN};
use crate::otpauth;
use crate::totp::{decode_secret, encode_secret, Algorithm, Totp};
use crate::util::{random_bytes, to_hex};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"CNTV";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl Entry {
    pub fn totp(&self) -> Result<Totp> {
        Totp::new(
            decode_secret(&self.secret)?,
            self.algorithm,
            self.digits,
            self.period,
        )
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Payload {
    entries: Vec<Entry>,
}

pub struct Vault {
    entries: Vec<Entry>,
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    params: KdfParams,
}

impl Vault {
    pub fn create(password: &[u8], params: KdfParams) -> Result<Self> {
        let salt = random_salt();
        let key = derive_key(password, &salt, params)?;
        Ok(Vault {
            entries: Vec::new(),
            key,
            salt,
            params,
        })
    }

    pub fn open(data: &[u8], password: &[u8]) -> Result<Self> {
        if data.len() < HEADER_LEN {
            return Err(Error::Format("vault too short"));
        }
        if &data[..4] != MAGIC {
            return Err(Error::Format("not a Canto vault"));
        }
        if data[4] != VERSION {
            return Err(Error::Format("unsupported vault version"));
        }
        let params = KdfParams::from_bytes(&data[5..17])?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[17..HEADER_LEN]);
        let key = derive_key(password, &salt, params)?;
        let plain = Zeroizing::new(aead::open(&key, &data[HEADER_LEN..], &data[..HEADER_LEN])?);
        let payload: Payload =
            serde_json::from_slice(&plain).map_err(|_| Error::Format("corrupt vault payload"))?;
        Ok(Vault {
            entries: payload.entries,
            key,
            salt,
            params,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&self.params.to_bytes());
        header.extend_from_slice(&self.salt);
        let plain = Zeroizing::new(
            serde_json::to_vec(&Payload {
                entries: self.entries.clone(),
            })
            .map_err(|_| Error::Encrypt)?,
        );
        let sealed = aead::seal(&self.key, &plain, &header)?;
        header.extend_from_slice(&sealed);
        Ok(header)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn add_totp(
        &mut self,
        issuer: &str,
        account: &str,
        totp: &Totp,
    ) -> String {
        let id = to_hex(&random_bytes::<8>());
        self.entries.push(Entry {
            id: id.clone(),
            issuer: issuer.to_string(),
            account: account.to_string(),
            secret: encode_secret(&totp.secret),
            algorithm: totp.algorithm,
            digits: totp.digits,
            period: totp.period,
        });
        id
    }

    pub fn add_uri(&mut self, uri: &str) -> Result<String> {
        let parsed = otpauth::parse(uri)?;
        Ok(self.add_totp(&parsed.issuer, &parsed.account, &parsed.totp))
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() != before
    }

    pub fn change_password(&mut self, new_password: &[u8]) -> Result<()> {
        let salt = random_salt();
        let key = derive_key(new_password, &salt, self.params)?;
        self.salt = salt;
        self.key = key;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn create_save_open_roundtrip() {
        let mut v = Vault::create(b"hunter2", fast()).unwrap();
        let id = v
            .add_uri("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example")
            .unwrap();
        let bytes = v.to_bytes().unwrap();
        let reopened = Vault::open(&bytes, b"hunter2").unwrap();
        assert_eq!(reopened.entries().len(), 1);
        assert_eq!(reopened.entries()[0].id, id);
        assert_eq!(reopened.entries()[0].issuer, "Example");
        assert_eq!(
            reopened.entries()[0].totp().unwrap().code_at(59).len(),
            6
        );
    }

    #[test]
    fn wrong_password_fails() {
        let v = Vault::create(b"right", fast()).unwrap();
        let bytes = v.to_bytes().unwrap();
        assert!(Vault::open(&bytes, b"wrong").is_err());
    }

    #[test]
    fn header_tampering_is_detected() {
        let v = Vault::create(b"pw", fast()).unwrap();
        let mut bytes = v.to_bytes().unwrap();
        bytes[6] ^= 1;
        assert!(Vault::open(&bytes, b"pw").is_err());
    }

    #[test]
    fn rejects_hostile_kdf_params() {
        let v = Vault::create(b"pw", fast()).unwrap();
        let mut bytes = v.to_bytes().unwrap();
        bytes[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Vault::open(&bytes, b"pw").is_err());
    }

    #[test]
    fn remove_and_change_password() {
        let mut v = Vault::create(b"old", fast()).unwrap();
        let id = v
            .add_uri("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP")
            .unwrap();
        v.change_password(b"new").unwrap();
        let bytes = v.to_bytes().unwrap();
        assert!(Vault::open(&bytes, b"old").is_err());
        let mut reopened = Vault::open(&bytes, b"new").unwrap();
        assert!(reopened.remove(&id));
        assert!(!reopened.remove(&id));
        assert!(reopened.entries().is_empty());
    }
}
