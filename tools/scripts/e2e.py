import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

binary = sys.argv[1] if len(sys.argv) > 1 else "target/release/canto"
data_dir = tempfile.mkdtemp()
env = dict(os.environ, CANTO_DATA_DIR=data_dir, CANTO_NO_BROWSER="1")
token_bodies = []


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, obj):
        raw = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        token_bodies.append(dict(urllib.parse.parse_qsl(body)))
        self.reply({"access_token": "tok123"})

    def do_GET(self):
        if self.headers.get("Authorization") == "Bearer tok123":
            self.reply({"name": "Ada Lovelace", "email": "ada@example.com"})
        else:
            self.send_response(401)
            self.end_headers()


mock = HTTPServer(("127.0.0.1", 0), Mock)
threading.Thread(target=mock.serve_forever, daemon=True).start()
mock_base = f"http://127.0.0.1:{mock.server_port}"
with open(os.path.join(data_dir, "providers.json"), "w") as f:
    json.dump({"google": {"client_id": "test-client", "auth_url": mock_base + "/auth", "token_url": mock_base + "/token", "userinfo_url": mock_base + "/userinfo"}}, f)


def start_proc(cmd):
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, text=True)
    line = ""
    while "http://" not in line:
        line = proc.stdout.readline()
    m = re.search(r"http://127\.0\.0\.1:(\d+)/#t=([0-9a-f]{64})", line)
    return proc, int(m.group(1)), m.group(2)


def start():
    return start_proc([binary])


def parse(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode()


def call(port, token, cmd, args=None, host=None, origin=None, method="POST", use_token=True):
    headers = {"Content-Type": "application/json"}
    if use_token:
        headers["X-Canto-Token"] = token
    if host:
        headers["Host"] = host
    if origin:
        headers["Origin"] = origin
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/{cmd}",
        data=json.dumps(args or {}).encode() if method == "POST" else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, parse(r.read())
    except urllib.error.HTTPError as e:
        return e.code, parse(e.read())


failures = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


proc, port, token = start()
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as r:
        body = r.read().decode()
        check("serves index.html", r.status == 200 and "<div id=\"app\">" in body)
        check("sets CSP header", "default-src 'self'" in (r.headers.get("Content-Security-Policy") or ""))
    js = re.search(r'src="(/assets/[^"]+\.js)"', body).group(1)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{js}") as r:
        check("serves js asset", r.status == 200 and "javascript" in r.headers["Content-Type"])

    s, _ = call(port, token, "vault_exists", use_token=False)
    check("rejects missing token", s == 403)
    s, _ = call(port, "0" * 64, "vault_exists")
    check("rejects wrong token", s == 403)
    s, _ = call(port, token, "vault_exists", host="evil.example:80")
    check("rejects foreign Host (DNS rebinding)", s == 403)
    s, _ = call(port, token, "vault_exists", origin="http://evil.example")
    check("rejects foreign Origin", s == 403)
    s, _ = call(port, token, "vault_exists", method="GET")
    check("rejects GET on api", s in (403, 405))

    s, b = call(port, token, "vault_exists")
    check("no vault at first", s == 200 and b is False)
    s, b = call(port, token, "list_codes")
    check("locked vault refuses codes", s == 400 and "locked" in b["error"].lower())
    s, b = call(port, token, "unlock", {"password": ""})
    check("empty password refused", s == 400)
    s, b = call(port, token, "unlock", {"password": "hunter2"})
    check("first unlock creates vault", s == 200)
    s, b = call(port, token, "vault_exists")
    check("vault now exists", b is True)

    uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    s, b = call(port, token, "add_uri", {"uri": uri})
    check("adds otpauth uri", s == 200)
    s, b = call(port, token, "add_uri", {"uri": "https://nope"})
    check("rejects bad uri", s == 400)
    s, b = call(port, token, "list_codes")
    check("lists one code with 6 digits", s == 200 and len(b) == 1 and re.fullmatch(r"\d{6}", b[0]["code"]) is not None)
    entry_id = b[0]["id"]

    s, b = call(port, token, "export_backup")
    check("exports encrypted backup", s == 200 and bytes.fromhex(b)[:4] == b"CNTV" and b"JBSWY3DPEHPK3PXP" not in bytes.fromhex(b))

    s, b = call(port, token, "change_password", {"old": "wrong", "new": "newpass"})
    check("change password needs correct current", s == 400)
    s, b = call(port, token, "change_password", {"old": "hunter2", "new": "newpass"})
    check("change password works", s == 200)

    call(port, token, "lock")
    s, b = call(port, token, "list_codes")
    check("lock clears session", s == 400)
    s, b = call(port, token, "unlock", {"password": "hunter2"})
    check("old password rejected after change", s == 400 and "wrong" in b["error"].lower())
    s, b = call(port, token, "unlock", {"password": "newpass"})
    check("new password accepted", s == 200)
    s, b = call(port, token, "list_codes")
    check("entries survive restart of session", s == 200 and len(b) == 1)

    s, b = call(port, token, "launch_context")
    check("default launch mode is main", s == 200 and b["mode"] == "main")
    s, b = call(port, token, "profile")
    check("no profile at first", s == 200 and b is None)
    s, b = call(port, token, "save_profile", {"name": "Ada", "email": "ada@example.com", "provider": "local"})
    check("saves profile", s == 200)
    s, b = call(port, token, "profile")
    check("reads profile back", b["name"] == "Ada" and b["provider"] == "local")
    s, b = call(port, token, "save_profile", {"name": "  ", "email": ""})
    check("rejects empty name", s == 400)

    s, b = call(port, token, "providers")
    cfg = {p["id"]: p["configured"] for p in b}
    check("provider list reflects config", cfg["google"] is True and cfg["github"] is False and cfg["apple"] is False)
    s, b = call(port, token, "oauth_start", {"provider": "github"})
    check("unconfigured provider explains itself", s == 400 and "providers.json" in b["error"])
    s, b = call(port, token, "oauth_start", {"provider": "apple"})
    check("apple is refused honestly", s == 400 and "Apple" in b["error"])
    s, b = call(port, token, "oauth_start", {"provider": "google"})
    q = urllib.parse.parse_qs(urllib.parse.urlparse(b).query)
    check("oauth url has PKCE and state", s == 200 and q["code_challenge_method"] == ["S256"] and len(q["state"][0]) > 16)
    redirect = q["redirect_uri"][0]
    check("redirect is loopback callback", redirect == f"http://127.0.0.1:{port}/oauth/callback")
    s, b = call(port, token, "oauth_result")
    check("oauth pending before callback", s == 200 and b is None)
    with urllib.request.urlopen(f"{redirect}?code=abc%2F123&state=wrong") as r:
        check("bad state is rejected", "no longer valid" in r.read().decode())
    with urllib.request.urlopen(f"{redirect}?code=abc%2F123&state={urllib.parse.quote(q['state'][0])}") as r:
        check("callback page shows success", "Signed in" in r.read().decode())
    s, b = call(port, token, "oauth_result")
    check("oauth returns provider profile", s == 200 and b["name"] == "Ada Lovelace" and b["email"] == "ada@example.com" and b["provider"] == "google")
    sent = token_bodies[-1]
    import base64, hashlib
    digest = base64.urlsafe_b64encode(hashlib.sha256(sent["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    check("PKCE verifier matches challenge", digest == q["code_challenge"][0])
    check("code decoded and client id sent", sent["code"] == "abc/123" and sent["client_id"] == "test-client" and sent["redirect_uri"] == redirect)
    s, b = call(port, token, "oauth_result")
    check("oauth result is single-use", b is None)

    s, b = call(port, token, "lock_folder", {"path": "/", "password": "pw"})
    check("refuses to lock a whole drive", s == 400 and "drive" in b["error"])
    s, b = call(port, token, "lock_folder", {"path": os.path.dirname(os.path.abspath(binary)), "password": "pw"})
    check("refuses to lock the folder Canto runs from", s == 400 and "running from" in b["error"])

    folder = tempfile.mkdtemp()
    os.makedirs(os.path.join(folder, "sub"))
    with open(os.path.join(folder, "sub", "secret.txt"), "w") as f:
        f.write("top secret")
    s, b = call(port, token, "lock_folder", {"path": folder, "password": "pw"})
    check("locks a folder", s == 200 and "Locked 1" in b)
    stub_name = "Unlock this folder.exe" if os.name == "nt" else "Unlock this folder"
    listing = sorted(os.listdir(folder))
    expected = [".canto-data", ".canto-lock", stub_name] + (["desktop.ini"] if os.name == "nt" else [])
    check("locked folder shows only the unlock stub and hidden internals", listing == sorted(expected))
    if os.name == "nt":
        with open(os.path.join(folder, "desktop.ini")) as f:
            check("desktop.ini labels folder as password protected", "Password protected" in f.read())
    else:
        check("stub is executable", os.access(os.path.join(folder, stub_name), os.X_OK))
    check("original file gone", not os.path.exists(os.path.join(folder, "sub")))
    s, b = call(port, token, "unlock_folder", {"path": folder, "password": "bad"})
    check("wrong folder password refused", s == 400)

    stub = os.path.join(folder, stub_name)
    stub_proc, sport, stoken = start_proc([stub])
    try:
        s, b = call(sport, stoken, "launch_context")
        check("running the stub opens unlock mode for its folder", s == 200 and b["mode"] == "unlock" and os.path.samefile(b["path"], folder))
        s, b = call(sport, stoken, "unlock_folder", {"path": b["path"], "password": "pw"})
        check("stub unlocks the folder", s == 200)
        check("stub and desktop.ini cleaned up", sorted(os.listdir(folder)) == ["sub"])
        with open(os.path.join(folder, "sub", "secret.txt")) as f:
            check("contents restored", f.read() == "top secret")
    finally:
        stub_proc.terminate()

    folder2 = tempfile.mkdtemp()
    lock_proc, lport, ltoken = start_proc([binary, "lock", folder2])
    try:
        s, b = call(lport, ltoken, "launch_context")
        check("context-menu launch opens lock mode", b["mode"] == "lock" and b["path"] == folder2)
    finally:
        lock_proc.terminate()

    s, b = call(port, token, "remove_entry", {"id": entry_id})
    s, b = call(port, token, "list_codes")
    check("removes entry", s == 200 and b == [])
    s, b = call(port, token, "nonsense")
    check("unknown command refused", s == 400)
finally:
    proc.terminate()

proc, port, token = start()
try:
    s, b = call(port, token, "unlock", {"password": "newpass"})
    check("vault persists across app restarts", s == 200)
finally:
    proc.terminate()

print("\n%d failure(s)" % len(failures))
sys.exit(1 if failures else 0)
