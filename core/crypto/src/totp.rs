use crate::error::{Error, Result};
use crate::util::constant_time_eq;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            _ => Err(Error::Otp("unsupported algorithm")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

macro_rules! hmac_digest {
    ($hash:ty, $key:expr, $msg:expr) => {{
        let mut mac = <Hmac<$hash> as Mac>::new_from_slice($key).expect("hmac accepts any key length");
        mac.update($msg);
        mac.finalize().into_bytes().to_vec()
    }};
}

pub fn decode_secret(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(Error::Otp("empty secret"));
    }
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .filter(|v| !v.is_empty())
        .ok_or(Error::Otp("invalid base32 secret"))
}

pub fn encode_secret(secret: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Totp {
    pub fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u32, period: u64) -> Result<Self> {
        if secret.is_empty() {
            return Err(Error::Otp("empty secret"));
        }
        if !(6..=8).contains(&digits) {
            return Err(Error::Otp("digits must be between 6 and 8"));
        }
        if period == 0 {
            return Err(Error::Otp("period must be positive"));
        }
        Ok(Totp {
            secret,
            algorithm,
            digits,
            period,
        })
    }

    pub fn standard(secret: Vec<u8>) -> Result<Self> {
        Totp::new(secret, Algorithm::Sha1, 6, 30)
    }

    fn hotp(&self, counter: u64) -> String {
        let msg = counter.to_be_bytes();
        let digest = match self.algorithm {
            Algorithm::Sha1 => hmac_digest!(Sha1, &self.secret, &msg),
            Algorithm::Sha256 => hmac_digest!(Sha256, &self.secret, &msg),
            Algorithm::Sha512 => hmac_digest!(Sha512, &self.secret, &msg),
        };
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin = ((digest[offset] as u32 & 0x7f) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);
        let modulus = 10u32.pow(self.digits);
        format!("{:0width$}", bin % modulus, width = self.digits as usize)
    }

    pub fn code_at(&self, unix_time: u64) -> String {
        self.hotp(unix_time / self.period)
    }

    pub fn code_now(&self) -> String {
        self.code_at(unix_now())
    }

    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        self.period - (unix_time % self.period)
    }

    pub fn verify(&self, code: &str, unix_time: u64, window: u64) -> bool {
        let counter = unix_time / self.period;
        let start = counter.saturating_sub(window);
        let mut ok = false;
        for c in start..=counter.saturating_add(window) {
            if constant_time_eq(self.hotp(c).as_bytes(), code.as_bytes()) {
                ok = true;
            }
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha1() -> Totp {
        Totp::new(b"12345678901234567890".to_vec(), Algorithm::Sha1, 8, 30).unwrap()
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let t = sha1();
        assert_eq!(t.code_at(59), "94287082");
        assert_eq!(t.code_at(1111111109), "07081804");
        assert_eq!(t.code_at(1111111111), "14050471");
        assert_eq!(t.code_at(1234567890), "89005924");
        assert_eq!(t.code_at(2000000000), "69279037");
        assert_eq!(t.code_at(20000000000), "65353130");
    }

    #[test]
    fn rfc6238_sha256_vector() {
        let t = Totp::new(
            b"12345678901234567890123456789012".to_vec(),
            Algorithm::Sha256,
            8,
            30,
        )
        .unwrap();
        assert_eq!(t.code_at(59), "46119246");
        assert_eq!(t.code_at(1111111109), "68084774");
    }

    #[test]
    fn rfc6238_sha512_vector() {
        let t = Totp::new(
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
            Algorithm::Sha512,
            8,
            30,
        )
        .unwrap();
        assert_eq!(t.code_at(59), "90693936");
        assert_eq!(t.code_at(1111111109), "25091201");
    }

    #[test]
    fn verify_respects_window() {
        let t = Totp::standard(b"12345678901234567890".to_vec()).unwrap();
        let code = t.code_at(1_000_000);
        assert!(t.verify(&code, 1_000_000, 0));
        assert!(t.verify(&code, 1_000_030, 1));
        assert!(!t.verify(&code, 1_000_090, 1));
        assert!(!t.verify("000000", 1_000_000, 0) || code == "000000");
    }

    #[test]
    fn secret_codec() {
        let raw = b"hello world secret";
        let enc = encode_secret(raw);
        assert_eq!(decode_secret(&enc).unwrap(), raw);
        assert_eq!(decode_secret(&enc.to_lowercase()).unwrap(), raw);
        assert!(decode_secret("!!!").is_err());
        assert!(decode_secret("").is_err());
    }

    #[test]
    fn seconds_remaining_counts_down() {
        let t = Totp::standard(vec![1, 2, 3]).unwrap();
        assert_eq!(t.seconds_remaining(0), 30);
        assert_eq!(t.seconds_remaining(29), 1);
        assert_eq!(t.seconds_remaining(30), 30);
    }
}
