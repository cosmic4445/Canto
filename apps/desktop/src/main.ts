import "./style.css";
import { bridge, native, type Code, type Profile, type Provider } from "./bridge";

const app = document.getElementById("app") as HTMLElement;
const THEMES: [string, string][] = [
  ["canto", "Canto"], ["black", "Black"], ["midnight", "Midnight"], ["ruby", "Ruby"], ["emerald", "Emerald"],
  ["light", "Light"], ["nord", "Nord"], ["violet", "Violet"], ["sunset", "Sunset"], ["ocean", "Ocean"],
];
const PROVIDER_COLORS: Record<string, string> = { google: "#ea4335", apple: "#a0a0a0", github: "#8b5cf6", discord: "#5865f2", microsoft: "#00a4ef" };

type Tab = "codes" | "tools" | "folders" | "settings";
let tab: Tab = "codes";
let ticker: number | undefined;
let idleTimer: number | undefined;
let filter = "";
let profile: Profile | null = null;
let autoLockMinutes = Number(localStorage.getItem("canto.autolock") ?? 5);

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const baseName = (p: string) => p.split(/[\\/]/).filter(Boolean).pop() ?? p;

const ICONS: Record<string, string> = {
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  tools: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
  folder: '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>',
  settings: '<path d="M4 8h10M18 8h2M4 16h2M10 16h10"/><circle cx="16" cy="8" r="2"/><circle cx="8" cy="16" r="2"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
  check: '<path d="M5 13l4 4L19 7"/>',
};
const icon = (name: string, size = 20) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;

const logo = (size: number) => `
<svg width="${size}" height="${size}" viewBox="0 0 100 100" aria-label="Canto">
  <circle cx="50" cy="50" r="48" fill="#111214"/>
  <path d="M69 33 A25 25 0 1 0 69 67" fill="none" stroke="#f4f4f5" stroke-width="11" stroke-linecap="round"/>
  <circle cx="47" cy="50" r="4.6" fill="#ef4444"/>
  <circle cx="62" cy="50" r="4.6" fill="#22c55e"/>
  <circle cx="74" cy="50" r="4.6" fill="#3b82f6"/>
</svg>`;

function applyTheme(name: string) {
  const id = THEMES.some(([t]) => t === name) ? name : "canto";
  document.documentElement.dataset.theme = id;
  localStorage.setItem("canto.theme", id);
}

function toast(text: string) {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = text;
  document.body.append(el);
  setTimeout(() => el.remove(), 1800);
}

function stopTimers() {
  if (ticker) clearInterval(ticker);
  if (idleTimer) clearTimeout(idleTimer);
  ticker = undefined;
  idleTimer = undefined;
}

function socialButtons(providers: Provider[]) {
  return `<div class="social">${providers
    .map((p) => `<button type="button" class="${p.configured ? "" : "off"}" data-provider="${p.id}"><span class="dot" style="background:${PROVIDER_COLORS[p.id] ?? "#888"}"></span>${esc(p.label)}</button>`)
    .join("")}</div>`;
}

async function waitForOAuth(): Promise<Profile> {
  for (let i = 0; i < 180; i++) {
    await sleep(1000);
    const result = await bridge.oauthResult();
    if (result) return result;
  }
  throw new Error("Sign-in timed out");
}

async function showLogin() {
  stopTimers();
  const [exists, saved, providers] = await Promise.all([bridge.vaultExists(), bridge.profile(), bridge.providers()]);
  profile = saved;
  let provider = saved?.provider ?? "local";
  if (exists) {
    app.innerHTML = `
    <div class="center"><form class="card" id="f">
      <div class="hero" style="font-size:34px;font-weight:700">${esc((saved?.name ?? "C")[0].toUpperCase())}</div>
      <h1>${saved ? `Welcome back, ${esc(saved.name.split(" ")[0])}` : "Welcome back"}</h1>
      <div class="muted">Enter your master password to unlock Canto</div>
      <input id="pw" type="password" placeholder="Master password" autofocus>
      <div class="error" id="err"></div>
      <button type="submit">Unlock</button>
      ${native ? "" : `<div class="muted">Preview mode: any password works</div>`}
    </form></div>`;
    $<HTMLFormElement>("f").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      try {
        await bridge.unlock($<HTMLInputElement>("pw").value);
        showShell();
      } catch (e) {
        $("err").textContent = msg(e);
      }
    });
    return;
  }
  app.innerHTML = `
  <div class="center"><form class="card" id="f">
    <div style="display:grid;place-items:center">${logo(76)}</div>
    <h1>Create your account</h1>
    <div class="muted" id="hint">Your vault is encrypted with the master password you choose</div>
    ${socialButtons(providers)}
    <div class="divider">or fill in manually</div>
    <input id="name" placeholder="Your name" autocomplete="name">
    <input id="email" type="email" placeholder="Email" autocomplete="email">
    <input id="pw" type="password" placeholder="Master password">
    <input id="pw2" type="password" placeholder="Repeat master password">
    <div class="error" id="err"></div>
    <button type="submit">Create account</button>
  </form></div>`;
  app.querySelectorAll<HTMLButtonElement>("[data-provider]").forEach((b) =>
    b.addEventListener("click", async () => {
      $("err").textContent = "";
      try {
        const url = await bridge.oauthStart(b.dataset.provider ?? "");
        window.open(url, "_blank");
        $("hint").textContent = "Finish signing in in the window that just opened…";
        const p = await waitForOAuth();
        $<HTMLInputElement>("name").value = p.name;
        $<HTMLInputElement>("email").value = p.email;
        provider = p.provider;
        $("hint").textContent = `Signed in with ${p.provider}. Now choose a master password.`;
        $("hint").className = "muted ok";
      } catch (e) {
        $("err").textContent = msg(e);
        $("hint").textContent = "Your vault is encrypted with the master password you choose";
      }
    }),
  );
  $<HTMLFormElement>("f").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const name = $<HTMLInputElement>("name").value.trim();
    const email = $<HTMLInputElement>("email").value.trim();
    const pw = $<HTMLInputElement>("pw").value;
    if (!name) return void ($("err").textContent = "Enter your name");
    if (!pw) return void ($("err").textContent = "Choose a master password");
    if (pw !== $<HTMLInputElement>("pw2").value) return void ($("err").textContent = "Passwords do not match");
    try {
      await bridge.unlock(pw);
      profile = { name, email, provider };
      await bridge.saveProfile(profile);
      showShell();
    } catch (e) {
      $("err").textContent = msg(e);
    }
  });
}

async function finishFolderScreen(title: string) {
  app.innerHTML = `<div class="center"><div class="card"><div class="hero">${icon("check", 44)}</div><h1>${esc(title)}</h1><div class="muted">You can close this window.</div></div></div>`;
  await sleep(1200);
  bridge.quit();
}

function showFolderUnlock(path: string) {
  app.innerHTML = `
  <div class="center"><form class="card" id="f">
    <div class="hero">${icon("lock", 44)}</div>
    <h1 class="big">Password protected</h1>
    <div class="muted">${esc(baseName(path))} is locked by Canto</div>
    <div class="path">${esc(path)}</div>
    <input id="pw" type="password" placeholder="Enter password:" autofocus>
    <div class="error" id="err"></div>
    <button type="submit">Unlock folder</button>
  </form></div>`;
  $<HTMLFormElement>("f").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = app.querySelector("button") as HTMLButtonElement;
    btn.disabled = true;
    $("err").textContent = "";
    try {
      await bridge.unlockFolder(path, $<HTMLInputElement>("pw").value);
      await finishFolderScreen("Folder unlocked");
    } catch (e) {
      $("err").textContent = msg(e);
      btn.disabled = false;
      $<HTMLInputElement>("pw").select();
    }
  });
}

function showFolderLock(path: string) {
  app.innerHTML = `
  <div class="center"><form class="card" id="f">
    <div class="hero">${icon("lock", 44)}</div>
    <h1>Lock this folder</h1>
    <div class="path">${esc(path)}</div>
    <div class="muted">Everything inside is encrypted. Opening the folder will ask for this password.</div>
    <input id="pw" type="password" placeholder="Choose a password" autofocus>
    <input id="pw2" type="password" placeholder="Repeat password">
    <div class="error" id="err"></div>
    <button type="submit">Lock folder</button>
  </form></div>`;
  $<HTMLFormElement>("f").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const pw = $<HTMLInputElement>("pw").value;
    if (!pw) return void ($("err").textContent = "Choose a password");
    if (pw !== $<HTMLInputElement>("pw2").value) return void ($("err").textContent = "Passwords do not match");
    const btn = app.querySelector("button") as HTMLButtonElement;
    btn.disabled = true;
    try {
      await bridge.lockFolder(path, pw);
      await finishFolderScreen("Folder locked");
    } catch (e) {
      $("err").textContent = msg(e);
      btn.disabled = false;
    }
  });
}

async function lockNow() {
  await bridge.lock();
  showLogin();
}

function armIdle() {
  if (idleTimer) clearTimeout(idleTimer);
  if (autoLockMinutes > 0) idleTimer = window.setTimeout(lockNow, autoLockMinutes * 60000);
}

function showShell() {
  stopTimers();
  const nav = (t: Tab, label: string, ic: string) => `<button class="nav ${tab === t ? "on" : ""}" data-tab="${t}">${icon(ic)}${label}</button>`;
  const who = profile
    ? `<div class="me"><div class="avatar">${esc(profile.name[0]?.toUpperCase() ?? "?")}</div><div><b>${esc(profile.name)}</b><span class="muted">${esc(profile.provider === "local" ? profile.email || "Local account" : `via ${profile.provider}`)}</span></div></div>`
    : "";
  app.innerHTML = `
  <div class="shell">
    <aside class="side">
      <div class="brand">${logo(32)}<span>Canto</span></div>
      ${nav("codes", "Authenticator", "shield")}${nav("tools", "Security tools", "tools")}${nav("folders", "Folders", "folder")}${nav("settings", "Settings", "settings")}
      <div class="spacer"></div>
      ${who}
      <button class="ghost" id="lock">Lock vault</button>
    </aside>
    <main class="main" id="main"></main>
  </div>`;
  app.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach((b) =>
    b.addEventListener("click", () => {
      tab = b.dataset.tab as Tab;
      showShell();
    }),
  );
  $("lock").addEventListener("click", lockNow);
  armIdle();
  if (tab === "codes") renderCodes();
  else if (tab === "tools") renderTools();
  else if (tab === "folders") renderFolders();
  else renderSettings();
}

function codeCard(c: Code) {
  const digits = c.code.length === 8 ? `${c.code.slice(0, 4)} ${c.code.slice(4)}` : `${c.code.slice(0, 3)} ${c.code.slice(3)}`;
  return `
  <div class="code" data-copy="${esc(c.code)}">
    <button class="x" data-rm="${esc(c.id)}" title="Remove">✕</button>
    <div class="issuer">${esc(c.issuer || "Unnamed")}</div>
    <div class="muted">${esc(c.account)}</div>
    <div class="num">${digits}</div>
    <div class="bar"><i style="width:${(c.remaining / c.period) * 100}%"></i></div>
  </div>`;
}

async function refreshCodes() {
  const list = document.getElementById("list");
  if (!list) return;
  try {
    const all = await bridge.codes();
    const q = filter.trim().toLowerCase();
    const codes = q ? all.filter((c) => `${c.issuer} ${c.account}`.toLowerCase().includes(q)) : all;
    list.innerHTML = codes.length ? codes.map(codeCard).join("") : `<div class="note">${all.length ? "No matches." : "No accounts yet. Paste an otpauth:// link above."}</div>`;
    list.querySelectorAll<HTMLElement>("[data-copy]").forEach((el) =>
      el.addEventListener("click", () => {
        navigator.clipboard.writeText(el.dataset.copy ?? "");
        toast("Code copied");
      }),
    );
    list.querySelectorAll<HTMLElement>("[data-rm]").forEach((el) =>
      el.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        await bridge.remove(el.dataset.rm ?? "");
        refreshCodes();
      }),
    );
  } catch {
    showLogin();
  }
}

function renderCodes() {
  $("main").innerHTML = `
    <h2>Authenticator</h2>
    <form class="row" id="add"><input id="uri" placeholder="Paste an otpauth://totp/... link"><button type="submit">Add</button></form>
    <div class="error" id="err"></div>
    <div class="row"><input id="q" placeholder="Search accounts" value="${esc(filter)}"></div>
    <div class="list" id="list"></div>`;
  $<HTMLInputElement>("q").addEventListener("input", (e) => {
    filter = (e.target as HTMLInputElement).value;
    refreshCodes();
  });
  $<HTMLFormElement>("add").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const input = $<HTMLInputElement>("uri");
    try {
      await bridge.add(input.value);
      input.value = "";
      $("err").textContent = "";
      refreshCodes();
    } catch (e) {
      $("err").textContent = msg(e);
    }
  });
  refreshCodes();
  ticker = window.setInterval(refreshCodes, 1000);
}

const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?",
};

function randomBelow(n: number): number {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf);
  while (buf[0] >= limit);
  return buf[0] % n;
}

function generatePassword(length: number, sets: string[]): string {
  const pool = sets.join("");
  const chars = sets.map((s) => s[randomBelow(s.length)]);
  while (chars.length < length) chars.push(pool[randomBelow(pool.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.slice(0, length).join("");
}

function strengthLabel(bits: number): string {
  return bits < 40 ? "Weak" : bits < 60 ? "Fair" : bits < 80 ? "Good" : bits < 110 ? "Strong" : "Excellent";
}

function estimateBits(pw: string): number {
  if (!pw) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  let bits = pw.length * Math.log2(Math.max(pool, 2));
  if (/(.)\1{2,}/.test(pw) || /(0123|1234|2345|abcd|qwer|asdf|password|letmein|welcome)/i.test(pw)) bits *= 0.5;
  return Math.round(bits);
}

async function pwnedCount(password: string): Promise<number> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password)));
  const hex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const res = await fetch(`https://api.pwnedpasswords.com/range/${hex.slice(0, 5)}`, { headers: { "Add-Padding": "true" } });
  if (!res.ok) throw new Error("Breach service unavailable");
  for (const line of (await res.text()).split("\n")) {
    const [suffix, count] = line.trim().split(":");
    if (suffix === hex.slice(5)) return Number(count);
  }
  return 0;
}

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function aesKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt as BufferSource, iterations: 600000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encryptText(text: string, password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(password, salt), new TextEncoder().encode(text)));
  return `CANTO1.${b64(salt)}.${b64(iv)}.${b64(ct)}`;
}

async function decryptText(token: string, password: string): Promise<string> {
  const parts = token.trim().split(".");
  if (parts[0] !== "CANTO1" || parts.length !== 4) throw new Error("Not text encrypted by Canto");
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(parts[2]) as BufferSource }, await aesKey(password, unb64(parts[1])), unb64(parts[3]) as BufferSource);
    return new TextDecoder().decode(pt);
  } catch {
    throw new Error("Wrong password or damaged text");
  }
}

async function digestHex(algo: string, data: ArrayBuffer): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest(algo, data))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function renderTools() {
  $("main").innerHTML = `
    <h2>Security tools</h2>
    <div class="grid">
      <div class="panel">
        <b>Password generator</b>
        <input id="gen" readonly>
        <div class="meter"><i id="gbar" style="width:0"></i></div>
        <div class="note" id="meter"></div>
        <label>Length: <span id="lenv">20</span><input id="len" type="range" min="8" max="64" value="20"></label>
        <div class="row" style="margin:0;flex-wrap:wrap">
          <label class="inline"><input type="checkbox" id="c-lower" checked> a-z</label>
          <label class="inline"><input type="checkbox" id="c-upper" checked> A-Z</label>
          <label class="inline"><input type="checkbox" id="c-digits" checked> 0-9</label>
          <label class="inline"><input type="checkbox" id="c-symbols" checked> !@#</label>
        </div>
        <div class="row" style="margin:0"><button id="regen">Generate</button><button class="ghost" id="cpy">Copy</button></div>
      </div>
      <div class="panel">
        <b>Password check</b>
        <div class="note">Strength is estimated on this device. The breach lookup sends only the first 5 characters of the password's SHA-1 hash.</div>
        <input id="chk" type="password" placeholder="Password to check">
        <div class="meter"><i id="cbar" style="width:0"></i></div>
        <div class="note" id="cstr"></div>
        <button id="chkb">Check for breaches</button>
        <div class="note" id="chkr"></div>
      </div>
      <div class="panel">
        <b>Encrypt or decrypt text</b>
        <div class="note">AES-256-GCM with a key stretched from your password (PBKDF2, 600,000 rounds).</div>
        <textarea id="txt" placeholder="Text, or a CANTO1.… message to decrypt"></textarea>
        <input id="tpw" type="password" placeholder="Password">
        <div class="row" style="margin:0"><button id="enc">Encrypt</button><button class="ghost" id="dec">Decrypt</button><button class="ghost" id="tcp">Copy result</button></div>
        <textarea id="tout" readonly placeholder="Result"></textarea>
        <div class="error" id="terr"></div>
      </div>
      <div class="panel">
        <b>File hash checker</b>
        <div class="note">Verify a download matches the hash its publisher lists. The file never leaves this device.</div>
        <input id="fil" type="file">
        <input id="exp" placeholder="Expected hash (optional)">
        <div class="path" id="h256">SHA-256: –</div>
        <div class="path" id="h512">SHA-512: –</div>
        <div class="note" id="hres"></div>
      </div>
    </div>`;

  const out = $<HTMLInputElement>("gen");
  const regen = () => {
    const len = Number($<HTMLInputElement>("len").value);
    $("lenv").textContent = String(len);
    const sets = (Object.keys(SETS) as (keyof typeof SETS)[]).filter((k) => $<HTMLInputElement>(`c-${k}`).checked).map((k) => SETS[k]);
    if (!sets.length) return void (out.value = "");
    out.value = generatePassword(len, sets);
    const bits = Math.round(len * Math.log2(sets.join("").length));
    $("meter").textContent = `${strengthLabel(bits)} · about ${bits} bits`;
    $("gbar").style.width = `${Math.min(100, (bits / 128) * 100)}%`;
  };
  ["len", "c-lower", "c-upper", "c-digits", "c-symbols"].forEach((id) => $(id).addEventListener("input", regen));
  $("regen").addEventListener("click", regen);
  $("cpy").addEventListener("click", () => {
    if (!out.value) return;
    navigator.clipboard.writeText(out.value);
    toast("Password copied");
  });

  $<HTMLInputElement>("chk").addEventListener("input", (e) => {
    const bits = estimateBits((e.target as HTMLInputElement).value);
    $("cstr").textContent = bits ? `${strengthLabel(bits)} · about ${bits} bits` : "";
    $("cbar").style.width = `${Math.min(100, (bits / 110) * 100)}%`;
  });
  $("chkb").addEventListener("click", async () => {
    const pw = $<HTMLInputElement>("chk").value;
    if (!pw) return void ($("chkr").textContent = "Enter a password first");
    $("chkr").textContent = "Checking…";
    try {
      const n = await pwnedCount(pw);
      $("chkr").textContent = n ? `Found in ${n.toLocaleString()} known breaches. Do not use it.` : "Not found in known breaches.";
    } catch (e) {
      $("chkr").textContent = msg(e);
    }
  });

  const runText = (fn: (t: string, p: string) => Promise<string>) => async () => {
    $("terr").textContent = "";
    const text = $<HTMLTextAreaElement>("txt").value;
    const pw = $<HTMLInputElement>("tpw").value;
    if (!text || !pw) return void ($("terr").textContent = "Enter text and a password");
    try {
      $<HTMLTextAreaElement>("tout").value = await fn(text, pw);
    } catch (e) {
      $("terr").textContent = msg(e);
    }
  };
  $("enc").addEventListener("click", runText(encryptText));
  $("dec").addEventListener("click", runText(decryptText));
  $("tcp").addEventListener("click", () => {
    navigator.clipboard.writeText($<HTMLTextAreaElement>("tout").value);
    toast("Copied");
  });

  const compare = (h256: string, h512: string) => {
    const want = $<HTMLInputElement>("exp").value.trim().toLowerCase();
    if (!want) return void ($("hres").textContent = "");
    const match = want === h256 || want === h512;
    $("hres").textContent = match ? "Matches the expected hash." : "Does NOT match. Do not trust this file.";
    $("hres").className = match ? "note ok" : "error";
  };
  let hashes = ["", ""];
  $<HTMLInputElement>("fil").addEventListener("change", async (e) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    if (file.size > 1.5 * 1024 ** 3) return void ($("hres").textContent = "File is too large to hash here (limit 1.5 GB)");
    $("h256").textContent = "SHA-256: hashing…";
    const data = await file.arrayBuffer();
    hashes = [await digestHex("SHA-256", data), await digestHex("SHA-512", data)];
    $("h256").textContent = `SHA-256: ${hashes[0]}`;
    $("h512").textContent = `SHA-512: ${hashes[1]}`;
    compare(hashes[0], hashes[1]);
  });
  $<HTMLInputElement>("exp").addEventListener("input", () => compare(hashes[0], hashes[1]));
  regen();
}

function renderFolders() {
  $("main").innerHTML = `
    <h2>Folders</h2>
    <div class="panel narrow">
      <div class="note">Locking encrypts everything inside and leaves one "Unlock this folder" file. Opening it shows a password prompt. You can also right-click a folder in Explorer once the Explorer menu is installed.</div>
      <input id="path" placeholder="Folder path, e.g. C:\\Users\\you\\Private">
      <input id="fpw" type="password" placeholder="Folder password">
      <div class="row" style="margin:0"><button id="lk">Lock folder</button><button class="ghost" id="ul">Unlock folder</button></div>
      <div class="error" id="ferr"></div>
    </div>`;
  const run = (fn: (p: string, w: string) => Promise<string>) => async () => {
    const path = $<HTMLInputElement>("path").value.trim().replace(/^"|"$/g, "");
    const pw = $<HTMLInputElement>("fpw").value;
    if (!path || !pw) return void ($("ferr").textContent = "Path and password required");
    try {
      $("ferr").textContent = "Working…";
      toast(await fn(path, pw));
      $("ferr").textContent = "";
    } catch (e) {
      $("ferr").textContent = msg(e);
    }
  };
  $("lk").addEventListener("click", run(bridge.lockFolder));
  $("ul").addEventListener("click", run(bridge.unlockFolder));
}

function renderSettings() {
  const current = document.documentElement.dataset.theme ?? "canto";
  $("main").innerHTML = `
    <h2>Settings</h2>
    <div class="panel narrow">
      <b>Account</b>
      <div class="note">${profile ? `${esc(profile.name)}${profile.email ? ` · ${esc(profile.email)}` : ""} · ${esc(profile.provider === "local" ? "local account" : `signed in with ${profile.provider}`)}` : "No account details saved"}</div>
    </div>
    <div class="panel narrow">
      <b>Theme</b>
      <div class="themes">${THEMES.map(([id, label]) => `<button class="sw ${id === current ? "on" : ""}" data-theme="${id}" data-pick="${id}"><i></i>${label}</button>`).join("")}</div>
    </div>
    <div class="panel narrow">
      <label>Auto-lock after idle (minutes, 0 = never)<input id="al" type="number" min="0" max="240" value="${autoLockMinutes}"></label>
    </div>
    <div class="panel narrow">
      <b>Master password</b>
      <input id="op" type="password" placeholder="Current password">
      <input id="np" type="password" placeholder="New password">
      <button id="cp">Change password</button>
      <div class="error" id="serr"></div>
    </div>
    <div class="panel narrow">
      <b>Backup</b>
      <div class="note">Downloads your vault as an encrypted file. It is useless without your master password.</div>
      <button class="ghost" id="bk">Download backup</button>
    </div>`;
  app.querySelectorAll<HTMLElement>("[data-pick]").forEach((b) =>
    b.addEventListener("click", () => {
      applyTheme(b.dataset.pick ?? "canto");
      renderSettings();
    }),
  );
  $<HTMLInputElement>("al").addEventListener("change", (e) => {
    autoLockMinutes = Math.max(0, Number((e.target as HTMLInputElement).value) || 0);
    localStorage.setItem("canto.autolock", String(autoLockMinutes));
    armIdle();
  });
  $("cp").addEventListener("click", async () => {
    const op = $<HTMLInputElement>("op");
    const np = $<HTMLInputElement>("np");
    try {
      await bridge.changePassword(op.value, np.value);
      op.value = "";
      np.value = "";
      $("serr").textContent = "";
      toast("Password changed");
    } catch (e) {
      $("serr").textContent = msg(e);
    }
  });
  $("bk").addEventListener("click", async () => {
    try {
      const bytes = await bridge.exportBackup();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([bytes as BlobPart], { type: "application/octet-stream" }));
      a.download = "canto-backup.cnto";
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) {
      toast(msg(e));
    }
  });
}

["pointerdown", "keydown"].forEach((ev) => window.addEventListener(ev, () => idleTimer !== undefined && armIdle()));

async function boot() {
  applyTheme(localStorage.getItem("canto.theme") ?? "canto");
  if (native) {
    bridge.ping();
    setInterval(() => bridge.ping(), 5000);
  }
  const ctx = await bridge.launch();
  if (ctx.mode === "unlock") return showFolderUnlock(ctx.path);
  if (ctx.mode === "lock") return showFolderLock(ctx.path);
  showLogin();
}

boot();
