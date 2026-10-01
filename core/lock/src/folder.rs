use crate::error::{LockError, Result};
use crate::shred::shred_file;
use canto_crypto::aead;
use canto_crypto::kdf::{derive_key, random_salt, KdfParams, SALT_LEN};
use canto_crypto::stream::{decrypt_stream, encrypt_stream};
use canto_crypto::util::{random_bytes, to_hex};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

pub const HEADER_FILE: &str = ".canto-lock";
pub const DATA_DIR: &str = ".canto-data";
const MAGIC: &[u8; 4] = b"CNTL";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN;

#[derive(Clone, Copy, Debug)]
pub struct LockOptions {
    pub kdf: KdfParams,
    pub shred_originals: bool,
}

impl Default for LockOptions {
    fn default() -> Self {
        LockOptions {
            kdf: KdfParams::default(),
            shred_originals: true,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct LockReport {
    pub files: usize,
    pub directories: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct UnlockReport {
    pub restored: usize,
    pub already_present: usize,
    pub missing: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Item {
    stored: String,
    original: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    files: Vec<Item>,
    dirs: Vec<String>,
}

pub fn is_locked(dir: &Path) -> bool {
    dir.join(HEADER_FILE).is_file()
}

fn relative_string(base: &Path, full: &Path) -> Result<String> {
    let rel = full
        .strip_prefix(base)
        .map_err(|_| LockError::Unsafe("path escaped the folder"))?;
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => parts.push(
                s.to_str()
                    .ok_or(LockError::Unsafe("file name is not valid UTF-8"))?
                    .to_string(),
            ),
            _ => return Err(LockError::Unsafe("unexpected path component")),
        }
    }
    Ok(parts.join("/"))
}

fn safe_join(base: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() {
        return Err(LockError::Corrupt("empty path in manifest"));
    }
    let mut out = base.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains('\\') || part.contains(':') {
            return Err(LockError::Corrupt("unsafe path in manifest"));
        }
        out.push(part);
    }
    Ok(out)
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".canto-tmp");
    path.with_file_name(name)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn encrypt_file(key: &[u8; 32], src: &Path, dst: &Path, aad: &[u8]) -> Result<()> {
    let tmp = tmp_path(dst);
    {
        let mut reader = BufReader::new(File::open(src)?);
        let mut writer = BufWriter::new(File::create(&tmp)?);
        encrypt_stream(key, &mut reader, &mut writer, aad)?;
        let f = writer.into_inner().map_err(|e| LockError::Io(e.into_error()))?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dst)?;
    Ok(())
}

fn decrypt_file(key: &[u8; 32], src: &Path, dst: &Path, aad: &[u8]) -> Result<()> {
    let tmp = tmp_path(dst);
    let result = (|| -> Result<()> {
        let mut reader = BufReader::new(File::open(src)?);
        let mut writer = BufWriter::new(File::create(&tmp)?);
        decrypt_stream(key, &mut reader, &mut writer, aad)?;
        let f = writer.into_inner().map_err(|e| LockError::Io(e.into_error()))?;
        f.sync_all()?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            fs::rename(&tmp, dst)?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn scan(dir: &Path) -> Result<Manifest> {
    let mut manifest = Manifest::default();
    for entry in WalkDir::new(dir).min_depth(1).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(|e| LockError::Io(e.into()))?;
        let ft = entry.file_type();
        if ft.is_symlink() {
            return Err(LockError::Unsafe("symbolic links are not supported"));
        }
        let rel = relative_string(dir, entry.path())?;
        if ft.is_dir() {
            manifest.dirs.push(rel);
        } else if ft.is_file() {
            let stored = format!("{}.cnto", to_hex(&random_bytes::<16>()));
            manifest.files.push(Item { stored, original: rel });
        } else {
            return Err(LockError::Unsafe("unsupported file type"));
        }
    }
    Ok(manifest)
}

pub fn lock_folder(dir: &Path, password: &[u8], opts: &LockOptions) -> Result<LockReport> {
    if !dir.is_dir() {
        return Err(LockError::Unsafe("not a directory"));
    }
    if is_locked(dir) {
        return Err(LockError::AlreadyLocked);
    }
    let manifest = scan(dir)?;

    let salt = random_salt();
    let key = derive_key(password, &salt, opts.kdf)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&opts.kdf.to_bytes());
    header.extend_from_slice(&salt);
    let plain = serde_json::to_vec(&manifest).map_err(|_| LockError::Corrupt("manifest encode"))?;
    let sealed = aead::seal(&key, &plain, &header)?;
    header.extend_from_slice(&sealed);
    write_atomic(&dir.join(HEADER_FILE), &header)?;
    let data_dir = dir.join(DATA_DIR);
    fs::create_dir_all(&data_dir)?;

    for item in &manifest.files {
        let src = safe_join(dir, &item.original)?;
        let dst = data_dir.join(&item.stored);
        encrypt_file(&key, &src, &dst, item.stored.as_bytes())?;
        if opts.shred_originals {
            shred_file(&src)?;
        } else {
            fs::remove_file(&src)?;
        }
    }

    let mut dirs = manifest.dirs.clone();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.matches('/').count()));
    for d in &dirs {
        let _ = fs::remove_dir(safe_join(dir, d)?);
    }

    Ok(LockReport {
        files: manifest.files.len(),
        directories: manifest.dirs.len(),
    })
}

pub fn unlock_folder(dir: &Path, password: &[u8]) -> Result<UnlockReport> {
    let header_path = dir.join(HEADER_FILE);
    if !header_path.is_file() {
        return Err(LockError::NotLocked);
    }
    let data = fs::read(&header_path)?;
    if data.len() < HEADER_LEN || &data[..4] != MAGIC {
        return Err(LockError::Corrupt("bad header"));
    }
    if data[4] != VERSION {
        return Err(LockError::Corrupt("unsupported version"));
    }
    let params = KdfParams::from_bytes(&data[5..17])?;
    let salt = &data[17..HEADER_LEN];
    let key = derive_key(password, salt, params)?;
    let plain = aead::open(&key, &data[HEADER_LEN..], &data[..HEADER_LEN])
        .map_err(|_| LockError::WrongPassword)?;
    let manifest: Manifest =
        serde_json::from_slice(&plain).map_err(|_| LockError::Corrupt("manifest decode"))?;

    let mut dirs = manifest.dirs.clone();
    dirs.sort_by_key(|d| d.matches('/').count());
    for d in &dirs {
        fs::create_dir_all(safe_join(dir, d)?)?;
    }

    let data_dir = dir.join(DATA_DIR);
    let mut report = UnlockReport::default();
    for item in &manifest.files {
        if item.stored.contains('/') || item.stored.contains('\\') || item.stored.contains("..") {
            return Err(LockError::Corrupt("unsafe stored name"));
        }
        let src = data_dir.join(&item.stored);
        let dst = safe_join(dir, &item.original)?;
        if src.is_file() {
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)?;
            }
            decrypt_file(&key, &src, &dst, item.stored.as_bytes())?;
            fs::remove_file(&src)?;
            report.restored += 1;
        } else if dst.is_file() {
            report.already_present += 1;
        } else {
            report.missing.push(item.original.clone());
        }
    }

    if report.missing.is_empty() {
        fs::remove_file(&header_path)?;
        let _ = fs::remove_dir(&data_dir);
    }
    Ok(report)
}
