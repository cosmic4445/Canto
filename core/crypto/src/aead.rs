use crate::error::{Error, Result};
use crate::util::random_bytes;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| Error::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Format("ciphertext too short"));
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let (nonce_bytes, ct) = data.split_at(NONCE_LEN);
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"hello canto", b"ctx").unwrap();
        assert_eq!(open(&key, &sealed, b"ctx").unwrap(), b"hello canto");
    }

    #[test]
    fn rejects_wrong_key_aad_and_tampering() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"hello canto", b"ctx").unwrap();
        assert!(open(&[8u8; 32], &sealed, b"ctx").is_err());
        assert!(open(&key, &sealed, b"other").is_err());
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(&key, &bad, b"ctx").is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let key = [1u8; 32];
        let a = seal(&key, b"x", b"").unwrap();
        let b = seal(&key, b"x", b"").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }
}
