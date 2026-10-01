use crate::aead::{NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::util::random_bytes;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::io::{ErrorKind, Read, Write};

pub const CHUNK_SIZE: usize = 1 << 20;
const MAGIC: &[u8; 4] = b"CNTS";
const PREFIX_LEN: usize = NONCE_LEN - 8;

fn chunk_nonce(prefix: &[u8; PREFIX_LEN], counter: u64) -> XNonce {
    let mut n = [0u8; NONCE_LEN];
    n[..PREFIX_LEN].copy_from_slice(prefix);
    n[PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    XNonce::clone_from_slice(&n)
}

fn chunk_aad(aad: &[u8], last: bool) -> Vec<u8> {
    let mut a = Vec::with_capacity(aad.len() + 1);
    a.extend_from_slice(aad);
    a.push(last as u8);
    a
}

fn read_full<R: Read>(r: &mut R, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(k) => filled += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

pub fn encrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
    aad: &[u8],
) -> Result<()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let prefix = random_bytes::<PREFIX_LEN>();
    writer.write_all(MAGIC)?;
    writer.write_all(&prefix)?;

    let mut cur = read_full(reader, CHUNK_SIZE)?;
    let mut counter = 0u64;
    loop {
        let next = if cur.len() == CHUNK_SIZE {
            read_full(reader, CHUNK_SIZE)?
        } else {
            Vec::new()
        };
        let last = next.is_empty();
        let ct = cipher
            .encrypt(
                &chunk_nonce(&prefix, counter),
                Payload {
                    msg: &cur,
                    aad: &chunk_aad(aad, last),
                },
            )
            .map_err(|_| Error::Encrypt)?;
        writer.write_all(&ct)?;
        if last {
            break;
        }
        cur = next;
        counter += 1;
    }
    writer.flush()?;
    Ok(())
}

pub fn decrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
    aad: &[u8],
) -> Result<()> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let header = read_full(reader, MAGIC.len() + PREFIX_LEN)?;
    if header.len() != MAGIC.len() + PREFIX_LEN || &header[..MAGIC.len()] != MAGIC {
        return Err(Error::Format("not a Canto encrypted stream"));
    }
    let mut prefix = [0u8; PREFIX_LEN];
    prefix.copy_from_slice(&header[MAGIC.len()..]);

    let full = CHUNK_SIZE + TAG_LEN;
    let mut cur = read_full(reader, full)?;
    if cur.len() < TAG_LEN {
        return Err(Error::Format("stream truncated"));
    }
    let mut counter = 0u64;
    loop {
        let next = if cur.len() == full {
            read_full(reader, full)?
        } else {
            Vec::new()
        };
        let last = next.is_empty();
        let pt = cipher
            .decrypt(
                &chunk_nonce(&prefix, counter),
                Payload {
                    msg: &cur,
                    aad: &chunk_aad(aad, last),
                },
            )
            .map_err(|_| Error::Decrypt)?;
        writer.write_all(&pt)?;
        if last {
            break;
        }
        cur = next;
        counter += 1;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) {
        let key = [3u8; 32];
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &data[..], &mut enc, b"file-a").unwrap();
        let mut dec = Vec::new();
        decrypt_stream(&key, &mut &enc[..], &mut dec, b"file-a").unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn roundtrips_edge_sizes() {
        roundtrip(0);
        roundtrip(1);
        roundtrip(CHUNK_SIZE - 1);
        roundtrip(CHUNK_SIZE);
        roundtrip(CHUNK_SIZE + 1);
        roundtrip(CHUNK_SIZE * 2);
        roundtrip(CHUNK_SIZE * 2 + 17);
    }

    #[test]
    fn detects_truncation_at_chunk_boundary() {
        let key = [3u8; 32];
        let data = vec![9u8; CHUNK_SIZE * 2 + 5];
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &data[..], &mut enc, b"").unwrap();
        let cut = 4 + PREFIX_LEN + (CHUNK_SIZE + TAG_LEN);
        let truncated = &enc[..cut];
        let mut dec = Vec::new();
        assert!(decrypt_stream(&key, &mut &truncated[..], &mut dec, b"").is_err());
    }

    #[test]
    fn detects_reordered_or_tampered_chunks() {
        let key = [3u8; 32];
        let data = vec![1u8; CHUNK_SIZE * 2];
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &data[..], &mut enc, b"").unwrap();
        let mut bad = enc.clone();
        bad[30] ^= 0x40;
        let mut dec = Vec::new();
        assert!(decrypt_stream(&key, &mut &bad[..], &mut dec, b"").is_err());
    }

    #[test]
    fn rejects_wrong_key_and_aad() {
        let key = [3u8; 32];
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &b"secret"[..], &mut enc, b"a").unwrap();
        let mut out = Vec::new();
        assert!(decrypt_stream(&[4u8; 32], &mut &enc[..], &mut out, b"a").is_err());
        assert!(decrypt_stream(&key, &mut &enc[..], &mut out, b"b").is_err());
    }
}
