#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod oauth;

use canto_crypto::kdf::KdfParams;
use canto_crypto::totp::unix_now;
use canto_crypto::util::{constant_time_eq, random_bytes, to_hex};
use canto_crypto::vault::Vault;
use canto_lock::{lock_folder, unlock_folder, LockOptions};
use include_dir::{include_dir, Dir};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

static WEB: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../dist");

const CSP: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.pwnedpasswords.com; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

struct State {
    vault: Mutex<Option<Vault>>,
    path: PathBuf,
    dir: PathBuf,
    token: String,
    host: String,
    last_ping: AtomicU64,
    mode: String,
    target: String,
    pending: Mutex<HashMap<String, oauth::Pending>>,
    oauth_result: Mutex<Option<Result<Value, String>>>,
}

#[cfg(windows)]
const STUB_NAME: &str = "Unlock this folder.exe";
#[cfg(not(windows))]
const STUB_NAME: &str = "Unlock this folder";
const INI_MARK: &str = "; canto-lock";

fn hidden(program: &str) -> Command {
    #[allow(unused_mut)]
    let mut c = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    c
}

fn attrib(args: &[&str]) {
    if cfg!(windows) {
        let _ = hidden("attrib").args(args).status();
    }
}

fn remove_stub(path: &Path) {
    if fs::remove_file(path).is_ok() {
        return;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = hidden("cmd")
            .raw_arg(format!("/C ping -n 4 127.0.0.1 >nul & del /f /q \"{}\"", path.display()))
            .spawn();
    }
}

fn decorate_locked(dir: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let stub = dir.join(STUB_NAME);
    fs::copy(&exe, &stub).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&stub, fs::Permissions::from_mode(0o755));
    }
    if cfg!(windows) {
        let ini = format!(
            "[.ShellClassInfo]\r\nInfoTip=Password protected with Canto\r\nIconResource=%SystemRoot%\\System32\\imageres.dll,54\r\n{INI_MARK}\r\n"
        );
        fs::write(dir.join("desktop.ini"), ini).map_err(|e| e.to_string())?;
        attrib(&["+s", "+r", &dir.to_string_lossy()]);
        for name in ["desktop.ini", ".canto-data", ".canto-lock"] {
            attrib(&["+h", "+s", &dir.join(name).to_string_lossy()]);
        }
    }
    Ok(())
}

fn undecorate(dir: &Path) {
    attrib(&["-s", "-r", &dir.to_string_lossy()]);
    let ini = dir.join("desktop.ini");
    if fs::read_to_string(&ini).map(|t| t.contains(INI_MARK)).unwrap_or(false) {
        attrib(&["-h", "-s", &ini.to_string_lossy()]);
        let _ = fs::remove_file(&ini);
    }
    remove_stub(&dir.join(STUB_NAME));
}

fn launch_mode() -> (String, String) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let requested = match (args.first().map(|s| s.as_str()), args.get(1)) {
        (Some("lock"), Some(p)) => Some(("lock", p.clone())),
        (Some("unlock"), Some(p)) => Some(("unlock", p.clone())),
        _ => None,
    };
    if let Some((mode, path)) = requested {
        let locked = canto_lock::is_locked(Path::new(&path));
        let mode = if mode == "lock" && locked { "unlock" } else { mode };
        return (mode.to_string(), path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if dir.join(".canto-lock").is_file() {
                return ("unlock".into(), dir.to_string_lossy().to_string());
            }
        }
    }
    ("main".into(), String::new())
}

fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("CANTO_DATA_DIR") {
        return PathBuf::from(p);
    }
    if let Some(p) = std::env::var_os("APPDATA") {
        return PathBuf::from(p).join("Canto");
    }
    if let Some(p) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(p).join("canto");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".local").join("share").join("canto")
}

fn hdr(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

fn reply(status: u16, ctype: &str, body: Vec<u8>) -> Response<Cursor<Vec<u8>>> {
    Response::from_data(body)
        .with_status_code(StatusCode(status))
        .with_header(hdr("Content-Type", ctype))
        .with_header(hdr("Cache-Control", "no-store"))
        .with_header(hdr("X-Content-Type-Options", "nosniff"))
        .with_header(hdr("X-Frame-Options", "DENY"))
        .with_header(hdr("Referrer-Policy", "no-referrer"))
        .with_header(hdr("Content-Security-Policy", CSP))
}

fn json_reply(status: u16, value: Value) -> Response<Cursor<Vec<u8>>> {
    reply(status, "application/json", value.to_string().into_bytes())
}

fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "json" => "application/json",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn header_value(req: &Request, name: &'static str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
}

fn text(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Missing field: {key}"))
}

fn persist(state: &State, vault: &Vault) -> Result<(), String> {
    let bytes = vault.to_bytes().map_err(|e| e.to_string())?;
    let tmp = state.path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &state.path).map_err(|e| e.to_string())
}

fn api(state: &State, cmd: &str, args: &Value) -> Result<Value, String> {
    let busy = || "Internal error".to_string();
    match cmd {
        "ping" => {
            state.last_ping.store(unix_now(), Ordering::Relaxed);
            Ok(Value::Null)
        }
        "vault_exists" => Ok(json!(state.path.is_file())),
        "unlock" => {
            let password = text(args, "password")?;
            if password.is_empty() {
                return Err("Password required".into());
            }
            let vault = if state.path.is_file() {
                let data = fs::read(&state.path).map_err(|e| e.to_string())?;
                Vault::open(&data, password.as_bytes()).map_err(|_| "Wrong password".to_string())?
            } else {
                let v = Vault::create(password.as_bytes(), KdfParams::default()).map_err(|e| e.to_string())?;
                persist(state, &v)?;
                v
            };
            *state.vault.lock().map_err(|_| busy())? = Some(vault);
            Ok(json!(true))
        }
        "lock" => {
            *state.vault.lock().map_err(|_| busy())? = None;
            Ok(Value::Null)
        }
        "list_codes" => {
            let guard = state.vault.lock().map_err(|_| busy())?;
            let vault = guard.as_ref().ok_or("Vault is locked")?;
            let now = unix_now();
            let mut out = Vec::new();
            for e in vault.entries() {
                let totp = e.totp().map_err(|err| err.to_string())?;
                out.push(json!({
                    "id": e.id,
                    "issuer": e.issuer,
                    "account": e.account,
                    "code": totp.code_at(now),
                    "remaining": totp.seconds_remaining(now),
                    "period": totp.period,
                }));
            }
            Ok(Value::Array(out))
        }
        "add_uri" => {
            let uri = text(args, "uri")?;
            let mut guard = state.vault.lock().map_err(|_| busy())?;
            let vault = guard.as_mut().ok_or("Vault is locked")?;
            vault.add_uri(&uri).map_err(|e| e.to_string())?;
            persist(state, vault)?;
            Ok(Value::Null)
        }
        "remove_entry" => {
            let id = text(args, "id")?;
            let mut guard = state.vault.lock().map_err(|_| busy())?;
            let vault = guard.as_mut().ok_or("Vault is locked")?;
            vault.remove(&id);
            persist(state, vault)?;
            Ok(Value::Null)
        }
        "change_password" => {
            let old = text(args, "old")?;
            let new = text(args, "new")?;
            if new.is_empty() {
                return Err("New password required".into());
            }
            let data = fs::read(&state.path).map_err(|e| e.to_string())?;
            Vault::open(&data, old.as_bytes()).map_err(|_| "Current password is wrong".to_string())?;
            let mut guard = state.vault.lock().map_err(|_| busy())?;
            let vault = guard.as_mut().ok_or("Vault is locked")?;
            vault.change_password(new.as_bytes()).map_err(|e| e.to_string())?;
            persist(state, vault)?;
            Ok(Value::Null)
        }
        "export_backup" => {
            if state.vault.lock().map_err(|_| busy())?.is_none() {
                return Err("Vault is locked".into());
            }
            let data = fs::read(&state.path).map_err(|e| e.to_string())?;
            Ok(json!(to_hex(&data)))
        }
        "lock_folder" => {
            let dir = PathBuf::from(text(args, "path")?);
            let password = text(args, "password")?;
            if password.is_empty() {
                return Err("Password required".into());
            }
            if dir.parent().is_none() {
                return Err("Choose a folder, not a whole drive".into());
            }
            if std::env::current_exe().map(|e| e.starts_with(&dir)).unwrap_or(false) {
                return Err("Canto can't lock the folder it is running from".into());
            }
            let report = lock_folder(&dir, password.as_bytes(), &LockOptions::default()).map_err(|e| e.to_string())?;
            decorate_locked(&dir)?;
            Ok(json!(format!("Locked {} files", report.files)))
        }
        "unlock_folder" => {
            let dir = PathBuf::from(text(args, "path")?);
            let password = text(args, "password")?;
            let report = unlock_folder(&dir, password.as_bytes()).map_err(|e| e.to_string())?;
            if !report.missing.is_empty() {
                return Err(format!("{} files were missing; lock header kept", report.missing.len()));
            }
            undecorate(&dir);
            Ok(json!(format!("Restored {} files", report.restored)))
        }
        "launch_context" => Ok(json!({ "mode": state.mode, "path": state.target })),
        "providers" => Ok(oauth::providers(&state.dir)),
        "profile" => Ok(fs::read_to_string(state.dir.join("profile.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .unwrap_or(Value::Null)),
        "save_profile" => {
            let name = text(args, "name")?.trim().to_string();
            let email = text(args, "email").unwrap_or_default().trim().to_string();
            let provider = text(args, "provider").unwrap_or_else(|_| "local".into());
            if name.is_empty() || name.len() > 100 || email.len() > 200 {
                return Err("Enter a name (and a valid email)".into());
            }
            let profile = json!({ "name": name, "email": email, "provider": provider });
            fs::write(state.dir.join("profile.json"), profile.to_string()).map_err(|e| e.to_string())?;
            Ok(profile)
        }
        "oauth_start" => {
            let provider = text(args, "provider")?;
            let redirect = format!("http://{}/oauth/callback", state.host);
            let (url, st, pending) = oauth::start(&state.dir, &provider, &redirect)?;
            state.pending.lock().map_err(|_| busy())?.insert(st, pending);
            *state.oauth_result.lock().map_err(|_| busy())? = None;
            Ok(json!(url))
        }
        "oauth_result" => match state.oauth_result.lock().map_err(|_| busy())?.take() {
            None => Ok(Value::Null),
            Some(r) => r,
        },
        "quit" => {
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(250));
                std::process::exit(0);
            });
            Ok(Value::Null)
        }
        _ => Err("Unknown command".into()),
    }
}

fn handle(state: &State, mut req: Request) {
    let host_ok = header_value(&req, "Host").map(|h| h == state.host).unwrap_or(false);
    if !host_ok {
        let _ = req.respond(reply(403, "text/plain", b"forbidden".to_vec()));
        return;
    }
    let url = req.url().split('?').next().unwrap_or("/").to_string();

    if let Some(cmd) = url.strip_prefix("/api/") {
        let cmd = cmd.to_string();
        if *req.method() != Method::Post {
            let _ = req.respond(json_reply(405, json!({ "error": "POST required" })));
            return;
        }
        let origin_ok = match header_value(&req, "Origin") {
            Some(o) => o == format!("http://{}", state.host),
            None => true,
        };
        let token_ok = header_value(&req, "X-Canto-Token")
            .map(|t| constant_time_eq(t.as_bytes(), state.token.as_bytes()))
            .unwrap_or(false);
        if !origin_ok || !token_ok {
            let _ = req.respond(json_reply(403, json!({ "error": "Forbidden" })));
            return;
        }
        let mut body = String::new();
        let reader = req.as_reader();
        if reader.take(1 << 20).read_to_string(&mut body).is_err() {
            let _ = req.respond(json_reply(400, json!({ "error": "Bad request body" })));
            return;
        }
        let args: Value = if body.trim().is_empty() {
            json!({})
        } else {
            match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => {
                    let _ = req.respond(json_reply(400, json!({ "error": "Invalid JSON" })));
                    return;
                }
            }
        };
        let response = match api(state, &cmd, &args) {
            Ok(v) => json_reply(200, v),
            Err(e) => json_reply(400, json!({ "error": e })),
        };
        let _ = req.respond(response);
        return;
    }

    if *req.method() != Method::Get {
        let _ = req.respond(reply(405, "text/plain", b"method not allowed".to_vec()));
        return;
    }
    if url == "/oauth/callback" {
        let full = req.url().to_string();
        let st = oauth::query_param(&full, "state").unwrap_or_default();
        let pending = state.pending.lock().ok().and_then(|mut m| m.remove(&st));
        let message = match pending {
            None => "This sign-in link is no longer valid. Return to Canto and try again.".to_string(),
            Some(p) => {
                let redirect = format!("http://{}/oauth/callback", state.host);
                let outcome = match (oauth::query_param(&full, "code"), oauth::query_param(&full, "error")) {
                    (_, Some(e)) => Err(format!("Sign-in was cancelled ({e})")),
                    (Some(code), None) => oauth::finish(&state.dir, &p, &code, &redirect),
                    _ => Err("Sign-in failed: no code returned".to_string()),
                };
                let ok = outcome.is_ok();
                if let Ok(mut slot) = state.oauth_result.lock() {
                    *slot = Some(outcome);
                }
                if ok {
                    "Signed in. You can close this window and return to Canto.".to_string()
                } else {
                    "Sign-in did not complete. Return to Canto for details.".to_string()
                }
            }
        };
        let html = format!("<!doctype html><meta charset=\"utf-8\"><title>Canto</title><body style=\"font-family:system-ui;background:#0e1014;color:#eceff4;display:grid;place-items:center;height:100vh\"><p>{message}</p>");
        let _ = req.respond(reply(200, "text/html; charset=utf-8", html.into_bytes()));
        return;
    }
    let rel = match url.trim_start_matches('/') {
        "" => "index.html",
        p => p,
    };
    if rel.contains("..") {
        let _ = req.respond(reply(404, "text/plain", b"not found".to_vec()));
        return;
    }
    match WEB.get_file(rel) {
        Some(f) => {
            let _ = req.respond(reply(200, mime(rel), f.contents().to_vec()));
        }
        None => {
            let _ = req.respond(reply(404, "text/plain", b"not found".to_vec()));
        }
    }
}

fn try_run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .spawn()
        .map(|mut c| {
            thread::sleep(Duration::from_millis(300));
            !matches!(c.try_wait(), Ok(Some(status)) if !status.success())
        })
        .unwrap_or(false)
}

fn open_app(url: &str) {
    let app_flag = format!("--app={url}");
    if cfg!(windows) {
        let edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        let candidates = [edge, "msedge", "chrome"];
        for c in candidates {
            if try_run(c, &[&app_flag]) {
                return;
            }
        }
        let _ = Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn();
    } else {
        for c in ["google-chrome", "chromium", "chromium-browser", "microsoft-edge"] {
            if try_run(c, &[&app_flag]) {
                return;
            }
        }
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

fn main() {
    let dir = data_dir();
    fs::create_dir_all(&dir).expect("cannot create data directory");

    let server = Server::http("127.0.0.1:47821")
        .or_else(|_| Server::http("127.0.0.1:0"))
        .expect("cannot bind local port");
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .expect("no local port");
    let token = to_hex(&random_bytes::<32>());
    let (mode, target) = launch_mode();
    let state = Arc::new(State {
        vault: Mutex::new(None),
        path: dir.join("vault.cnto"),
        dir: dir.clone(),
        mode,
        target,
        pending: Mutex::new(HashMap::new()),
        oauth_result: Mutex::new(None),
        token: token.clone(),
        host: format!("127.0.0.1:{port}"),
        last_ping: AtomicU64::new(0),
    });

    let url = format!("http://127.0.0.1:{port}/#t={token}");
    println!("Canto is running. If no window opened, visit:\n{url}");
    if std::env::var_os("CANTO_NO_BROWSER").is_none() {
        open_app(&url);
    }

    let watch = state.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        let last = watch.last_ping.load(Ordering::Relaxed);
        if last > 0 && unix_now().saturating_sub(last) > 20 {
            std::process::exit(0);
        }
    });

    for req in server.incoming_requests() {
        let st = state.clone();
        thread::spawn(move || handle(&st, req));
    }
}
