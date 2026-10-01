export interface Code {
  id: string;
  issuer: string;
  account: string;
  code: string;
  remaining: number;
  period: number;
}

export interface Profile {
  name: string;
  email: string;
  provider: string;
}

export interface Provider {
  id: string;
  label: string;
  configured: boolean;
}

export interface Launch {
  mode: "main" | "lock" | "unlock";
  path: string;
}

export interface Bridge {
  launch(): Promise<Launch>;
  profile(): Promise<Profile | null>;
  saveProfile(profile: Profile): Promise<void>;
  providers(): Promise<Provider[]>;
  oauthStart(provider: string): Promise<string>;
  oauthResult(): Promise<Profile | null>;
  quit(): Promise<void>;
  vaultExists(): Promise<boolean>;
  unlock(password: string): Promise<boolean>;
  lock(): Promise<void>;
  codes(): Promise<Code[]>;
  add(uri: string): Promise<void>;
  remove(id: string): Promise<void>;
  lockFolder(path: string, password: string): Promise<string>;
  unlockFolder(path: string, password: string): Promise<string>;
  changePassword(oldPassword: string, newPassword: string): Promise<void>;
  exportBackup(): Promise<Uint8Array>;
  ping(): Promise<void>;
}

function sessionToken(): string | null {
  const m = /[#&]t=([0-9a-f]{64})/.exec(location.hash);
  if (!m) return null;
  history.replaceState(null, "", location.pathname);
  return m[1];
}

function httpBridge(token: string): Bridge {
  const call = async <T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> => {
    const res = await fetch(`/api/${cmd}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Canto-Token": token },
      body: JSON.stringify(args),
    });
    const data = await res.json().catch(() => ({ error: "Bad response" }));
    if (!res.ok) throw new Error(data.error ?? "Request failed");
    return data as T;
  };
  return {
    launch: () => call<Launch>("launch_context"),
    profile: () => call<Profile | null>("profile"),
    saveProfile: async (p) => void (await call("save_profile", { ...p })),
    providers: () => call<Provider[]>("providers"),
    oauthStart: (provider) => call<string>("oauth_start", { provider }),
    oauthResult: () => call<Profile | null>("oauth_result"),
    quit: () => call<void>("quit"),
    vaultExists: () => call<boolean>("vault_exists"),
    unlock: (password) => call<boolean>("unlock", { password }),
    lock: () => call<void>("lock"),
    codes: () => call<Code[]>("list_codes"),
    add: (uri) => call<void>("add_uri", { uri }),
    remove: (id) => call<void>("remove_entry", { id }),
    lockFolder: (path, password) => call<string>("lock_folder", { path, password }),
    unlockFolder: (path, password) => call<string>("unlock_folder", { path, password }),
    changePassword: (oldPassword, newPassword) => call<void>("change_password", { old: oldPassword, new: newPassword }),
    exportBackup: async () => {
      const hex = await call<string>("export_backup");
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      return out;
    },
    ping: () => call<void>("ping"),
  };
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function b32decode(input: string): Uint8Array {
  const clean = input.replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("Invalid secret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function hotp(secret: Uint8Array, counter: number, digits: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", secret as BufferSource, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(counter));
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const o = h[h.length - 1] & 15;
  const n = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** digits;
  return String(n).padStart(digits, "0");
}

interface Entry {
  id: string;
  issuer: string;
  account: string;
  secret: Uint8Array;
  digits: number;
  period: number;
}

function previewBridge(): Bridge {
  let unlocked = false;
  const entries: Entry[] = [
    { id: "1", issuer: "GitHub", account: "you@example.com", secret: b32decode("JBSWY3DPEHPK3PXP"), digits: 6, period: 30 },
    { id: "2", issuer: "Google", account: "you@gmail.com", secret: b32decode("GEZDGNBVGY3TQOJQ"), digits: 6, period: 30 },
    { id: "3", issuer: "Microsoft", account: "you@outlook.com", secret: b32decode("MFRGGZDFMZTWQ2LK"), digits: 6, period: 30 },
  ];
  const hash = new URLSearchParams(location.hash.slice(1));
  const preview = hash.get("preview");
  const saved = localStorage.getItem("canto.preview.profile");
  return {
    launch: async () => ({ mode: preview === "lock" || preview === "unlock" ? preview : "main", path: "C:\\Users\\you\\Private" }),
    profile: async () => (saved ? (JSON.parse(saved) as Profile) : null),
    saveProfile: async (p) => localStorage.setItem("canto.preview.profile", JSON.stringify(p)),
    providers: async () => ["google", "apple", "github", "discord", "microsoft"].map((id) => ({ id, label: id[0].toUpperCase() + id.slice(1), configured: false })),
    oauthStart: async () => {
      throw new Error("Social sign-in is available in the desktop app");
    },
    oauthResult: async () => null,
    quit: async () => {},
    vaultExists: async () => preview !== "create",
    unlock: async (pw) => (unlocked = pw.length > 0),
    lock: async () => {
      unlocked = false;
    },
    codes: async () => {
      if (!unlocked) throw new Error("Vault is locked");
      const now = Math.floor(Date.now() / 1000);
      return Promise.all(
        entries.map(async (e) => ({
          id: e.id,
          issuer: e.issuer,
          account: e.account,
          code: await hotp(e.secret, Math.floor(now / e.period), e.digits),
          remaining: e.period - (now % e.period),
          period: e.period,
        })),
      );
    },
    add: async (uri) => {
      const u = new URL(uri.trim());
      if (u.protocol !== "otpauth:" || u.hostname !== "totp") throw new Error("Expected an otpauth://totp/ link");
      const secret = u.searchParams.get("secret");
      if (!secret) throw new Error("Link has no secret");
      const label = decodeURIComponent(u.pathname.slice(1));
      const [labelIssuer, account] = label.includes(":") ? label.split(":", 2) : ["", label];
      entries.push({
        id: String(Date.now()),
        issuer: u.searchParams.get("issuer") || labelIssuer.trim(),
        account: account.trim(),
        secret: b32decode(secret),
        digits: Number(u.searchParams.get("digits") || 6),
        period: Number(u.searchParams.get("period") || 30),
      });
    },
    remove: async (id) => {
      const i = entries.findIndex((e) => e.id === id);
      if (i >= 0) entries.splice(i, 1);
    },
    lockFolder: async () => {
      throw new Error("Folder locking is available in the desktop app");
    },
    unlockFolder: async (_path, pw) => {
      if (pw !== "demo") throw new Error("Wrong password");
      return "Restored 0 files";
    },
    changePassword: async () => {
      throw new Error("Available in the desktop app");
    },
    exportBackup: async () => {
      throw new Error("Available in the desktop app");
    },
    ping: async () => {},
  };
}

const token = sessionToken();
export const native = token !== null;
export const bridge: Bridge = token ? httpBridge(token) : previewBridge();
