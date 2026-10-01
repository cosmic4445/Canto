use canto_crypto::util::random_bytes;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub struct Pending {
    pub provider: String,
    pub verifier: String,
}

struct Spec {
    auth: String,
    token: String,
    info: String,
    scope: &'static str,
    client_id: String,
    client_secret: Option<String>,
}

pub const PROVIDERS: [(&str, &str); 5] = [
    ("google", "Google"),
    ("apple", "Apple"),
    ("github", "GitHub"),
    ("discord", "Discord"),
    ("microsoft", "Microsoft"),
];

fn config(dir: &Path) -> Value {
    fs::read_to_string(dir.join("providers.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

fn configured(cfg: &Value, id: &str) -> bool {
    cfg.get(id)
        .and_then(|p| p.get("client_id"))
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

pub fn providers(dir: &Path) -> Value {
    let cfg = config(dir);
    Value::Array(
        PROVIDERS
            .iter()
            .map(|(id, label)| json!({ "id": id, "label": label, "configured": *id != "apple" && configured(&cfg, id) }))
            .collect(),
    )
}

fn spec(dir: &Path, id: &str) -> Result<Spec, String> {
    let (auth, token, info, scope) = match id {
        "google" => (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://openidconnect.googleapis.com/v1/userinfo",
            "openid email profile",
        ),
        "github" => (
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
            "read:user user:email",
        ),
        "discord" => (
            "https://discord.com/oauth2/authorize",
            "https://discord.com/api/oauth2/token",
            "https://discord.com/api/users/@me",
            "identify email",
        ),
        "microsoft" => (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "https://graph.microsoft.com/v1.0/me",
            "User.Read openid profile email",
        ),
        "apple" => return Err("Apple sign-in needs an Apple developer account and a server, so it is not available yet".into()),
        _ => return Err("Unknown provider".into()),
    };
    let cfg = config(dir);
    if !configured(&cfg, id) {
        return Err(format!("{id} sign-in is not set up yet. Add its client ID to providers.json"));
    }
    let p = &cfg[id];
    let get = |k: &str, d: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or(d).to_string();
    Ok(Spec {
        auth: get("auth_url", auth),
        token: get("token_url", token),
        info: get("userinfo_url", info),
        scope,
        client_id: get("client_id", ""),
        client_secret: p.get("client_secret").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string()),
    })
}

fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| pct_decode(v))
    })
}

pub fn start(dir: &Path, id: &str, redirect: &str) -> Result<(String, String, Pending), String> {
    let spec = spec(dir, id)?;
    let verifier = b64url(&random_bytes::<48>());
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    let state = b64url(&random_bytes::<18>());
    let url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        spec.auth,
        pct(&spec.client_id),
        pct(redirect),
        pct(spec.scope),
        pct(&state),
        challenge
    );
    Ok((url, state, Pending { provider: id.to_string(), verifier }))
}

fn pick(v: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()))
        .unwrap_or("")
        .to_string()
}

pub fn finish(dir: &Path, pending: &Pending, code: &str, redirect: &str) -> Result<Value, String> {
    let spec = spec(dir, &pending.provider)?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect),
        ("client_id", spec.client_id.as_str()),
        ("code_verifier", pending.verifier.as_str()),
    ];
    if let Some(secret) = &spec.client_secret {
        form.push(("client_secret", secret.as_str()));
    }
    let tok: Value = ureq::post(&spec.token)
        .set("Accept", "application/json")
        .send_form(&form)
        .map_err(|e| format!("Sign-in failed: {e}"))?
        .into_json()
        .map_err(|_| "Sign-in failed: unreadable response".to_string())?;
    let access = tok
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("Sign-in failed: provider returned no access token")?;
    let info: Value = ureq::get(&spec.info)
        .set("Authorization", &format!("Bearer {access}"))
        .set("Accept", "application/json")
        .call()
        .map_err(|e| format!("Could not read your profile: {e}"))?
        .into_json()
        .map_err(|_| "Could not read your profile".to_string())?;
    Ok(json!({
        "name": pick(&info, &["name", "global_name", "displayName", "username", "login"]),
        "email": pick(&info, &["email", "mail", "userPrincipalName"]),
        "provider": pending.provider,
    }))
}
