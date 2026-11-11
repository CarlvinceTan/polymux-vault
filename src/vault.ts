// Vault core: a KeePass-compatible store for passwords, TOTP seeds and recovery
// codes. Pure logic, no OpenCode dependency, so it can be tested on its own.
//
// The file is a normal .kdbx, so KeePassXC and KeePass apps on a phone read it.
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import * as kdbxweb from "kdbxweb";
import { argon2d, argon2id } from "hash-wasm";
import * as OTPAuth from "otpauth";

// kdbxweb ships no Argon2 of its own, so it is wired to hash-wasm here. kdbxweb
// has already converted the header's byte count to KiB before calling this.
kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type) => {
  // Argon2id is 2, Argon2d is 0; KeePass writes Argon2d.
  const derive = type === 2 ? argon2id : argon2d;
  const hash = await derive({
    password: new Uint8Array(password),
    salt: new Uint8Array(salt),
    parallelism,
    iterations,
    memorySize: memory,
    hashLength: length,
    outputType: "binary",
  });
  return hash.buffer;
});

// The cost a vault created here uses. kdbxweb's own defaults are 1 MiB and two
// iterations, which is far too cheap to attack offline; this matches KeePassXC.
const ARGON2_MEMORY_BYTES = 64 * 1024 * 1024;
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 2;

const ROOT_GROUP = "Vault";

export interface EntrySummary {
  title: string;
  username?: string;
  url?: string;
  notes?: string;
  /** Path from the root, for example "Vault/Work". */
  group: string;
  hasPassword?: boolean;
  hasTOTP?: boolean;
  hasRecoveryCodes?: boolean;
}

export interface WriteOptions {
  title: string;
  username?: string;
  url?: string;
  notes?: string;
  /** Omitted means leave an existing password alone. */
  password?: string;
  totpSeed?: string;
  recoveryCodes?: string[];
}

function text(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  const protectedValue = value as { getText?: () => string };
  return typeof protectedValue.getText === "function" ? protectedValue.getText() : String(value);
}

function protect(value: string): kdbxweb.ProtectedValue | string {
  return kdbxweb.ProtectedValue.fromString(value);
}

export class Vault {
  private constructor(
    readonly path: string,
    private password: string,
    private db: kdbxweb.Kdbx,
  ) {}

  static async create(file: string, password: string): Promise<Vault> {
    if (!password) throw new Error("a password is required");
    if (await exists(file)) throw new Error(`${file} already exists; refusing to overwrite`);
    const db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password)), ROOT_GROUP);
    db.groups[0].name = ROOT_GROUP;
    hardenKdf(db);
    const vault = new Vault(file, password, db);
    await vault.save();
    return vault;
  }

  static async open(file: string, password: string): Promise<Vault> {
    const raw = await fs.readFile(file);
    const buffer = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength);
    const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password));
    const db = await kdbxweb.Kdbx.load(buffer as ArrayBuffer, credentials);
    return new Vault(file, password, db);
  }

  private eachGroup(visit: (group: kdbxweb.KdbxGroup, path: string) => void): void {
    const walk = (group: kdbxweb.KdbxGroup, prefix: string) => {
      const groupPath = prefix ? `${prefix}/${group.name}` : group.name;
      visit(group, groupPath);
      for (const child of group.groups) walk(child, groupPath);
    };
    walk(this.db.groups[0], "");
  }

  private describe(group: string, entry: kdbxweb.KdbxEntry): EntrySummary {
    const has = (key: string) => text(entry.fields.get(key)) !== "";
    return {
      title: text(entry.fields.get("Title")),
      username: text(entry.fields.get("UserName")) || undefined,
      url: text(entry.fields.get("URL")) || undefined,
      notes: text(entry.fields.get("Notes")) || undefined,
      group,
      hasPassword: has("Password") || undefined,
      hasTOTP: (has("otp") || has("otpauth")) || undefined,
      hasRecoveryCodes: has("recovery.codes") || undefined,
    };
  }

  entries(): EntrySummary[] {
    const found: EntrySummary[] = [];
    this.eachGroup((group, groupPath) => {
      for (const entry of group.entries) found.push(this.describe(groupPath, entry));
    });
    return found.sort((a, b) => a.title.localeCompare(b.title));
  }

  private locate(title: string): { entry: kdbxweb.KdbxEntry; group: kdbxweb.KdbxGroup; path: string } | undefined {
    const wanted = title.trim().toLowerCase();
    let hit: { entry: kdbxweb.KdbxEntry; group: kdbxweb.KdbxGroup; path: string } | undefined;
    this.eachGroup((group, groupPath) => {
      if (hit) return;
      for (const entry of group.entries) {
        if (text(entry.fields.get("Title")).toLowerCase() === wanted) {
          hit = { entry, group, path: groupPath };
          return;
        }
      }
    });
    return hit;
  }

  passwordFor(title: string): { title: string; username?: string; password: string } {
    const found = this.locate(title);
    if (!found) throw new Error(`no entry named "${title}"`);
    const password = text(found.entry.fields.get("Password"));
    if (password === "") throw new Error(`"${title}" has no password stored`);
    return {
      title: text(found.entry.fields.get("Title")),
      username: text(found.entry.fields.get("UserName")) || undefined,
      password,
    };
  }

  totpFor(title: string, now: Date = new Date()): { title: string; code: string; secondsUntilExpiry: number } {
    const found = this.locate(title);
    if (!found) throw new Error(`no entry named "${title}"`);
    const seed = text(found.entry.fields.get("otp")).trim();
    const uri = text(found.entry.fields.get("otpauth")).trim();
    if (!seed && !uri) throw new Error(`"${title}" has no TOTP seed stored`);
    const totp = uri
      ? (OTPAuth.URI.parse(uri) as OTPAuth.TOTP)
      : new OTPAuth.TOTP({
          secret: OTPAuth.Secret.fromBase32(seed.replace(/\s+/g, "").toUpperCase()),
          digits: 6,
          period: 30,
          algorithm: "SHA1",
        });
    const period = totp.period || 30;
    const secondsUntilExpiry = period - (Math.floor(now.getTime() / 1000) % period);
    return { title: text(found.entry.fields.get("Title")), code: totp.generate({ timestamp: now.getTime() }), secondsUntilExpiry };
  }

  recoveryCodesFor(title: string): { title: string; codes: string[] } {
    const found = this.locate(title);
    if (!found) throw new Error(`no entry named "${title}"`);
    const raw = text(found.entry.fields.get("recovery.codes")).trim();
    if (raw === "") throw new Error(`"${title}" has no recovery codes stored`);
    return {
      title: text(found.entry.fields.get("Title")),
      codes: raw.split("\n").map((line) => line.trim()).filter(Boolean),
    };
  }

  async put(options: WriteOptions): Promise<EntrySummary> {
    const title = options.title?.trim();
    if (!title) throw new Error("an entry needs a title");
    const found = this.locate(title);
    const entry = found ? found.entry : this.db.createEntry(this.db.groups[0]);
    // Only the fields the caller supplied are written, so storing a TOTP seed
    // does not clear an existing password.
    entry.fields.set("Title", title);
    if (options.username?.trim()) entry.fields.set("UserName", options.username.trim());
    if (options.url?.trim()) entry.fields.set("URL", options.url.trim());
    if (options.notes?.trim()) entry.fields.set("Notes", options.notes.trim());
    if (options.password !== undefined) entry.fields.set("Password", protect(options.password));
    const seed = options.totpSeed?.trim();
    if (seed) {
      if (seed.toLowerCase().startsWith("otpauth://")) {
        entry.fields.set("otpauth", protect(seed));
        entry.fields.delete("otp");
      } else {
        entry.fields.set("otp", protect(seed.toUpperCase()));
        entry.fields.delete("otpauth");
      }
    }
    if (options.recoveryCodes?.length) {
      entry.fields.set("recovery.codes", protect(options.recoveryCodes.join("\n")));
    }
    await this.save();
    const after = this.locate(title);
    return after ? this.describe(after.path, after.entry) : { title, group: ROOT_GROUP };
  }

  async delete(title: string): Promise<boolean> {
    const found = this.locate(title);
    if (!found) return false;
    const index = found.group.entries.indexOf(found.entry);
    if (index >= 0) found.group.entries.splice(index, 1);
    await this.save();
    return true;
  }

  async changePassword(current: string, next: string): Promise<void> {
    if (current !== this.password) throw new Error("the current password is wrong");
    if (!next?.trim()) throw new Error("a new password is required");
    this.db.credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(next));
    this.password = next;
    await this.save();
  }

  async destroy(): Promise<void> {
    await fs.rm(this.path, { force: true });
  }

  async save(): Promise<void> {
    const data = Buffer.from(await this.db.save());
    const directory = path.dirname(this.path);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const temporary = path.join(directory, `.${path.basename(this.path)}.${crypto.randomBytes(6).toString("hex")}.tmp`);
    await fs.writeFile(temporary, data, { mode: 0o600 });
    await fs.rename(temporary, this.path);
  }
}

// Raises a freshly created header from kdbxweb's cheap defaults to a modern cost.
// The parameters live in the file header, so KeePassXC reads them without caring.
function hardenKdf(db: kdbxweb.Kdbx): void {
  const parameters = db.header.kdfParameters;
  if (!parameters) return;
  const valueType = kdbxweb.VarDictionary.ValueType;
  parameters.set("M", valueType.UInt64, new kdbxweb.Int64(ARGON2_MEMORY_BYTES));
  parameters.set("I", valueType.UInt64, new kdbxweb.Int64(ARGON2_ITERATIONS));
  parameters.set("P", valueType.UInt32, ARGON2_PARALLELISM);
}

export async function exists(file: string): Promise<boolean> {
  try {
    const info = await fs.stat(file);
    return info.isFile();
  } catch {
    return false;
  }
}

export const DEFAULT_PATH = path.join(
  process.env.HOME ?? ".",
  "Library/Application Support/vault/vault.kdbx",
);

// The vault path lives in one small JSON file so the TUI menu and the server
// tools always mean the same database when the user changes it.
const CONFIG_FILE = path.join(process.env.HOME ?? ".", ".config/opencode/vault.json");

export async function configuredPath(): Promise<string> {
  try {
    const raw = JSON.parse(await fs.readFile(CONFIG_FILE, "utf8")) as { path?: unknown };
    if (typeof raw?.path === "string" && raw.path.trim()) return raw.path.trim();
  } catch {
    // not configured yet; fall through to the default
  }
  return process.env.VAULT_FILE ?? DEFAULT_PATH;
}

export async function setConfiguredPath(value: string): Promise<void> {
  await fs.mkdir(path.dirname(CONFIG_FILE), { recursive: true, mode: 0o700 });
  await fs.writeFile(CONFIG_FILE, `${JSON.stringify({ path: value }, null, 2)}\n`, { mode: 0o600 });
}

// The master password is never typed: it lives in the macOS Keychain, keyed by
// the vault path, and VAULT_PASSWORD overrides it when set.
const KEYCHAIN_SERVICE = "OpenCode Vault";

export function storePassword(file: string, password: string): void {
  if (process.platform !== "darwin") throw new Error("keychain storage is only available on macOS");
  execFileSync(
    "/usr/bin/security",
    ["add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", file, "-w", password],
    { stdio: ["ignore", "ignore", "ignore"] },
  );
}

export function keychainPassword(file: string): string | undefined {
  if (process.platform !== "darwin") return undefined;
  try {
    const value = execFileSync(
      "/usr/bin/security",
      ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", file, "-w"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    ).trim();
    return value === "" ? undefined : value;
  } catch {
    return undefined;
  }
}

export function resolvePassword(file: string): string | undefined {
  return process.env.VAULT_PASSWORD?.trim() || keychainPassword(file);
}
