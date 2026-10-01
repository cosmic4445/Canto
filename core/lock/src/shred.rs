use crate::error::Result;
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const BLOCK: usize = 1 << 20;

pub fn shred_file(path: &Path) -> Result<()> {
    let len = fs::metadata(path)?.len();
    {
        let mut f = OpenOptions::new().write(true).open(path)?;
        let mut buf = vec![0u8; BLOCK];
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(BLOCK as u64) as usize;
            OsRng.fill_bytes(&mut buf[..n]);
            f.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        f.sync_all()?;
        f.set_len(0)?;
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    Ok(())
}
