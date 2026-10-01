use canto_crypto::kdf::KdfParams;
use canto_lock::{is_locked, lock_folder, unlock_folder, LockError, LockOptions};
use std::fs;
use std::path::Path;

fn fast() -> LockOptions {
    LockOptions {
        kdf: KdfParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
        shred_originals: true,
    }
}

fn populate(root: &Path) {
    fs::create_dir_all(root.join("docs/tax/2025")).unwrap();
    fs::create_dir_all(root.join("empty_dir")).unwrap();
    fs::write(root.join("passwords.txt"), b"bank: hunter2").unwrap();
    fs::write(root.join("docs/tax/2025/return.pdf"), vec![42u8; 3_000_000]).unwrap();
    fs::write(root.join("docs/notes.md"), b"").unwrap();
}

fn names(root: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    v.sort();
    v
}

#[test]
fn lock_hides_everything_and_unlock_restores() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    populate(root);

    let report = lock_folder(root, b"correct horse", &fast()).unwrap();
    assert_eq!(report.files, 3);
    assert!(is_locked(root));

    assert_eq!(names(root), vec![".canto-data", ".canto-lock"]);
    for name in names(&root.join(".canto-data")) {
        assert!(name.ends_with(".cnto"), "leaked name: {name}");
    }
    assert_eq!(names(&root.join(".canto-data")).len(), 3);

    let unlock = unlock_folder(root, b"correct horse").unwrap();
    assert_eq!(unlock.restored, 3);
    assert!(unlock.missing.is_empty());
    assert!(!is_locked(root));

    assert_eq!(fs::read(root.join("passwords.txt")).unwrap(), b"bank: hunter2");
    assert_eq!(
        fs::read(root.join("docs/tax/2025/return.pdf")).unwrap(),
        vec![42u8; 3_000_000]
    );
    assert_eq!(fs::read(root.join("docs/notes.md")).unwrap(), b"");
    assert!(root.join("empty_dir").is_dir());
    assert_eq!(names(root), vec!["docs", "empty_dir", "passwords.txt"]);
}

#[test]
fn wrong_password_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    populate(root);
    lock_folder(root, b"right", &fast()).unwrap();
    let before = names(root);

    assert!(matches!(
        unlock_folder(root, b"wrong"),
        Err(LockError::WrongPassword)
    ));
    assert_eq!(names(root), before);
    assert!(is_locked(root));
}

#[test]
fn double_lock_and_unlock_of_plain_folder_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    populate(root);
    assert!(matches!(
        unlock_folder(root, b"x"),
        Err(LockError::NotLocked)
    ));
    lock_folder(root, b"pw", &fast()).unwrap();
    assert!(matches!(
        lock_folder(root, b"pw", &fast()),
        Err(LockError::AlreadyLocked)
    ));
}

#[test]
fn tampered_file_is_detected_and_original_not_clobbered() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("a.txt"), b"important").unwrap();
    lock_folder(root, b"pw", &fast()).unwrap();

    let data = root.join(".canto-data");
    let stored = names(&data)
        .into_iter()
        .find(|n| n.ends_with(".cnto"))
        .unwrap();
    let path = data.join(&stored);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, bytes).unwrap();

    assert!(unlock_folder(root, b"pw").is_err());
    assert!(!root.join("a.txt").exists());
    assert!(is_locked(root));
}

#[cfg(unix)]
#[test]
fn symlinks_are_refused_before_anything_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("a.txt"), b"x").unwrap();
    std::os::unix::fs::symlink("/etc/hostname", root.join("link")).unwrap();
    assert!(matches!(
        lock_folder(root, b"pw", &fast()),
        Err(LockError::Unsafe(_))
    ));
    assert!(!is_locked(root));
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"x");
}
