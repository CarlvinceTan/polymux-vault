// Agent-facing tools for the vault. Same tool surface the OpenCode plugin
// exposed, minus the plugin-only `{{vault:...}}` substitution: an MCP server
// has no hook that can rewrite another tool's arguments, so the skills document
// how to keep secrets out of the conversation instead.
//
// One open vault per OpenCode session, keyed by the sessionID the client sends
// in _meta. Locking one session's vault does not disturb another.
import type { ToolDefinition } from "./mcp.ts";
import { Vault, configuredPath, exists, resolvePassword, storePassword, type WriteOptions } from "./vault.ts";
import { chromiumDriver, fillLogin, geckoDriver, safariDriver } from "./driver.ts";

// Level 2 reaches whichever browser is actually open: Chromium over the DevTools
// protocol, Gecko (Firefox, Zen) over WebDriver BiDi, Safari over AppleScript.
// Another engine is another adapter here.
const CDP = process.env.VAULT_CDP ?? "http://127.0.0.1:9222";
const BIDI = process.env.VAULT_BIDI ?? "http://127.0.0.1:9444";
const drivers = [chromiumDriver(CDP), geckoDriver(BIDI), safariDriver()];

const opened = new Map<string, Vault>();

async function vaultFor(sessionID: string): Promise<Vault> {
  const cached = opened.get(sessionID);
  if (cached) return cached;
  const path = await configuredPath();
  if (!(await exists(path))) throw new Error(`vault: no vault at ${path}`);
  const password = resolvePassword(path);
  if (!password) {
    throw new Error(
      `vault: no master password stored for ${path}; add one with ` +
        `security add-generic-password -U -s "OpenCode Vault" -a "${path}" -w`,
    );
  }
  const vault = await Vault.open(path, password);
  opened.set(sessionID, vault);
  return vault;
}

const json = (value: unknown) => JSON.stringify(value, null, 2);

const titleInput = {
  type: "object",
  properties: { title: { type: "string", description: "entry title" } },
  required: ["title"],
  additionalProperties: false,
} as const;

const emptyInput = { type: "object", properties: {}, additionalProperties: false } as const;

export const INSTRUCTIONS = [
  "A KeePass (.kdbx) vault of account passwords, TOTP seeds and recovery codes.",
  "The master password comes from the macOS Keychain, so opening is silent.",
  "Prefer vault_login, which fills a browser page without returning the secret.",
  "Never write a secret into a file, a log, a report or a commit, and never echo",
  "one back to the user unless they asked for that entry.",
].join(" ");

export const tools: ToolDefinition[] = [
  {
    name: "status",
    description: "Report where the vault is, whether it exists, and whether this session has it open.",
    inputSchema: emptyInput,
    run: async (_input, context) => {
      const path = await configuredPath();
      const vault = opened.get(context.sessionID ?? "shared");
      return json({
        path,
        exists: await exists(path),
        open: Boolean(vault),
        passwordAvailable: Boolean(resolvePassword(path)),
        entries: vault?.entries().length,
      });
    },
  },

  {
    name: "unlock",
    description: "Open the vault for this session. The master password is read from the Keychain when omitted.",
    inputSchema: {
      type: "object",
      properties: { password: { type: "string", description: "optional override; usually omitted" } },
      additionalProperties: false,
    },
    run: async (input, context) => {
      const override = (input as { password?: string }).password?.trim();
      const path = await configuredPath();
      if (!(await exists(path))) throw new Error(`vault: no vault at ${path}`);
      const password = override || resolvePassword(path);
      if (!password) throw new Error(`vault: no master password stored for ${path}`);
      const vault = await Vault.open(path, password);
      opened.set(context.sessionID ?? "shared", vault);
      return json({ path, entries: vault.entries().length });
    },
  },

  {
    name: "lock",
    description: "Forget the open vault in this session. The next tool call opens it again.",
    inputSchema: emptyInput,
    run: async (_input, context) => {
      const key = context.sessionID ?? "shared";
      const vault = opened.get(key);
      opened.delete(key);
      return json({ path: await configuredPath(), entries: vault?.entries().length ?? 0 });
    },
  },

  {
    name: "create",
    description:
      "Create a new empty vault. Refuses when one already exists, and stores the master password in the Keychain.",
    inputSchema: {
      type: "object",
      properties: { password: { type: "string", description: "the master password to use" } },
      required: ["password"],
      additionalProperties: false,
    },
    run: async (input, context) => {
      const { password } = input as { password: string };
      const path = await configuredPath();
      const vault = await Vault.create(path, password);
      opened.set(context.sessionID ?? "shared", vault);
      return json({ path, entries: 0 });
    },
  },

  {
    name: "list",
    description: "List stored entries with what each holds (password, TOTP, recovery codes). Never returns a secret.",
    inputSchema: emptyInput,
    run: async (_input, context) => json({ entries: (await vaultFor(context.sessionID ?? "shared")).entries() }),
  },

  {
    name: "password",
    description:
      "Return a stored password, or the username or recovery codes. This puts the secret in the conversation, so reach for it only when there is no route that keeps it out: prefer login for a browser page, and prefer letting the user type it or read it from the vault themselves. Never repeat the value in a summary, a file or a log.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "entry title" },
        field: {
          type: "string",
          enum: ["password", "username", "recovery"],
          description: "which value to return, defaults to password",
        },
      },
      required: ["title"],
      additionalProperties: false,
    },
    run: async (input, context) => {
      const request = input as { title: string; field?: "password" | "username" | "recovery" };
      const vault = await vaultFor(context.sessionID ?? "shared");
      switch (request.field ?? "password") {
        case "username":
          return json({ title: request.title, username: vault.passwordFor(request.title).username ?? "" });
        case "recovery":
          return json(vault.recoveryCodesFor(request.title));
        default:
          return json(vault.passwordFor(request.title));
      }
    },
  },

  {
    name: "totp",
    description: "Return the current one-time code for an entry and how long it stays valid.",
    inputSchema: titleInput,
    run: async (input, context) =>
      json((await vaultFor(context.sessionID ?? "shared")).totpFor((input as { title: string }).title)),
  },

  {
    name: "recovery_codes",
    description: "Return the stored recovery codes for an entry.",
    inputSchema: titleInput,
    run: async (input, context) =>
      json((await vaultFor(context.sessionID ?? "shared")).recoveryCodesFor((input as { title: string }).title)),
  },

  {
    name: "login",
    description:
      "Fill this entry's saved credentials into the open browser page whose host matches the entry's stored URL, without the secret entering the conversation. Works with Chromium (DevTools endpoint), Gecko such as Firefox or Zen (WebDriver BiDi) and Safari. The page is chosen from the entry, never by the caller; if no matching page is open, nothing is filled. This is the preferred way to use a credential.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "entry title" },
        username: { type: "boolean", description: "also fill the account name (default true)" },
        totp: { type: "boolean", description: "also fill a one-time code when the entry has a seed" },
      },
      required: ["title"],
      additionalProperties: false,
    },
    run: async (input, context) => {
      const request = input as { title: string; username?: boolean; totp?: boolean };
      const vault = await vaultFor(context.sessionID ?? "shared");
      const wanted = request.title.trim().toLowerCase();
      const entry = vault.entries().find((candidate) => candidate.title.toLowerCase() === wanted);
      if (!entry) throw new Error(`vault: no entry named "${request.title}"`);
      if (!entry.url) {
        throw new Error(`vault: "${entry.title}" has no stored URL, so the destination cannot be verified`);
      }
      const report = await fillLogin(drivers, entry.url, {
        password: vault.passwordFor(entry.title).password,
        username: request.username === false ? "" : (entry.username ?? ""),
        totp: request.totp && entry.hasTOTP ? vault.totpFor(entry.title).code : "",
      });
      return json({ title: entry.title, ...report });
    },
  },

  {
    name: "put",
    description:
      "Create or update an entry. Only the fields provided change, so adding a TOTP seed does not clear a password. Ask the user before storing a secret you did not generate.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "entry title, created when it does not exist" },
        username: { type: "string" },
        url: { type: "string" },
        notes: { type: "string" },
        password: { type: "string", description: "omit to leave an existing password alone" },
        totpSeed: { type: "string", description: "a bare seed or an otpauth:// URL" },
        recoveryCodes: { type: "array", items: { type: "string" } },
      },
      required: ["title"],
      additionalProperties: false,
    },
    run: async (input, context) => json(await (await vaultFor(context.sessionID ?? "shared")).put(input as WriteOptions)),
  },

  {
    name: "delete",
    description: "Delete one entry. Ask the user first: this is not reversible.",
    inputSchema: titleInput,
    run: async (input, context) => {
      const title = (input as { title: string }).title;
      const removed = await (await vaultFor(context.sessionID ?? "shared")).delete(title);
      if (!removed) throw new Error(`vault: no entry named "${title}"`);
      return json({ title, removed: true });
    },
  },

  {
    name: "change_password",
    description: "Re-encrypt the whole database with a new master password, and store it in the Keychain.",
    inputSchema: {
      type: "object",
      properties: { current: { type: "string" }, next: { type: "string" } },
      required: ["current", "next"],
      additionalProperties: false,
    },
    run: async (input, context) => {
      const { current, next } = input as { current: string; next: string };
      const path = await configuredPath();
      await (await vaultFor(context.sessionID ?? "shared")).changePassword(current, next);
      storePassword(path, next);
      return json({ path, reencrypted: true });
    },
  },

  {
    name: "destroy",
    description: "Delete the vault file itself. Only on an explicit instruction naming the vault.",
    inputSchema: {
      type: "object",
      properties: { confirm: { type: "string", description: "the vault path, typed out to confirm" } },
      required: ["confirm"],
      additionalProperties: false,
    },
    run: async (input, context) => {
      const confirm = (input as { confirm: string }).confirm?.trim();
      const path = await configuredPath();
      if (confirm !== path) throw new Error(`vault: confirm must repeat the vault path exactly (${path})`);
      await (await vaultFor(context.sessionID ?? "shared")).destroy();
      opened.delete(context.sessionID ?? "shared");
      return json({ path, destroyed: true });
    },
  },
];
