use canto_lock::{is_locked, lock_folder, unlock_folder, LockOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

fn usage() {
    eprintln!("usage: canto-lock <lock|unlock|status> [--pause] <folder>");
}

fn pause() {
    print!("\nPress Enter to close...");
    let _ = io::stdout().flush();
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
}

fn prompt(label: &str) -> io::Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(label)?))
}

fn run(args: &[String]) -> Result<(), String> {
    let mut command = None;
    let mut folder = None;
    for a in args {
        if a == "--pause" {
            continue;
        }
        if command.is_none() {
            command = Some(a.clone());
        } else if folder.is_none() {
            folder = Some(PathBuf::from(a));
        } else {
            return Err("too many arguments".into());
        }
    }
    let command = command.ok_or("missing command")?;
    let folder = folder.ok_or("missing folder")?;

    match command.as_str() {
        "status" => {
            println!(
                "{}",
                if is_locked(&folder) {
                    "locked"
                } else {
                    "unlocked"
                }
            );
            Ok(())
        }
        "lock" => {
            let pw = prompt("Password: ").map_err(|e| e.to_string())?;
            if pw.is_empty() {
                return Err("password must not be empty".into());
            }
            let again = prompt("Repeat password: ").map_err(|e| e.to_string())?;
            if *pw != *again {
                return Err("passwords do not match".into());
            }
            let report = lock_folder(&folder, pw.as_bytes(), &LockOptions::default())
                .map_err(|e| e.to_string())?;
            println!(
                "Locked {} files in {} folders.",
                report.files, report.directories
            );
            Ok(())
        }
        "unlock" => {
            let pw = prompt("Password: ").map_err(|e| e.to_string())?;
            let report = unlock_folder(&folder, pw.as_bytes()).map_err(|e| e.to_string())?;
            println!("Restored {} files.", report.restored);
            if !report.missing.is_empty() {
                for m in &report.missing {
                    eprintln!("missing: {m}");
                }
                return Err("some files were missing; lock header kept".into());
            }
            Ok(())
        }
        _ => Err("unknown command".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pause_at_end = args.iter().any(|a| a == "--pause");
    if args.is_empty() {
        usage();
        return ExitCode::from(2);
    }
    let code = match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    };
    if pause_at_end {
        pause();
    }
    code
}
