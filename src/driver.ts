// Putting a credential into a live page, without the value ever reaching the
// model, and without tying the plugin to one browser.
//
// Adapters: Chromium over the DevTools protocol, Gecko (Firefox, Zen) over
// WebDriver BiDi, Safari over AppleScript. The page is always chosen by hostname
// derived from the entry's stored URL, never from anything the caller supplies —
// that is what stops a tricked agent from aiming a secret at another site.
//
// Discovery and fill happen in one adapter call on purpose: a BiDi browsing
// context id is only valid inside the session that produced it.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

interface Target {
  id: string;
  type: string;
  url: string;
  webSocketDebuggerUrl?: string;
}

interface FillReport {
  driver: string;
  host: string;
  page: string;
  filled: string[];
}

interface Values {
  password: string;
  username?: string;
  totp?: string;
}

interface Filled {
  page: string;
  filled: string[];
}

interface Driver {
  readonly name: string;
  /** Fill the first open page on this host, or undefined when none is open. */
  fill(host: string, values: Values): Promise<Filled | undefined>;
  /** Every host with an open page, so a refusal can say what is open. */
  hosts(): Promise<string[]>;
}

/** The bare hostname of an http(s) URL, or "" when there is not one. */
function hostOf(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

// Runs inside the page. It receives the values as arguments rather than having
// them baked into the script text, and reports only what it filled.
const FILL_BODY = `(secret, username, totp) => {
  const set = (element, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const visible = (element) => !!(element.offsetParent || element.getClientRects().length);
  const password = [...document.querySelectorAll('input[type="password"]')].find(visible);
  if (!password) return JSON.stringify({ ok: false, reason: "no visible password field on the page" });
  const form = password.form || document;
  const fields = [...form.querySelectorAll("input")].filter((element) => element.type !== "hidden");
  const before = fields.slice(0, fields.indexOf(password)).reverse();
  const userField = before.find((element) => /text|email|tel|search/.test(element.type) || element.autocomplete === "username");
  const codeField = fields.find((element) => element !== password &&
    (element.autocomplete === "one-time-code" || /otp|code|token|2fa/i.test(element.name + element.id)));
  const filled = [];
  if (username && userField) { set(userField, username); filled.push("username"); }
  set(password, secret);
  filled.push("password");
  if (totp && codeField) { set(codeField, totp); filled.push("totp"); }
  return JSON.stringify({ ok: true, filled });
}`;

/** Every adapter reports the same shape; the engines differ in how they hand it back. */
function outcomeOf(raw: unknown): { ok: boolean; filled?: string[]; reason?: string } {
  // An engine may hand back the JSON string as-is, or a string containing a JSON
  // string, so this unwraps until it reaches the object.
  let value: unknown = raw;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (value && typeof value === "object") return value as { ok: boolean; filled?: string[]; reason?: string };
    if (typeof value !== "string") break;
    try {
      value = JSON.parse(value);
    } catch {
      break;
    }
  }
  throw new Error("vault: the page did not return a usable result");
}

/* ------------------------------------------------------------------ Chromium */

async function listTargets(endpoint: string): Promise<Target[]> {
  const response = await fetch(new URL("/json/list", endpoint), { signal: AbortSignal.timeout(4000) });
  if (!response.ok) throw new Error(`cdp: ${endpoint} answered ${response.status}`);
  return (await response.json()) as Target[];
}

class CdpSession {
  private socket: WebSocket;
  private next = 1;
  private pending = new Map<number, { resolve: (value: any) => void; timer: ReturnType<typeof setTimeout> }>();

  private constructor(socket: WebSocket) {
    this.socket = socket;
    socket.addEventListener("message", (event: MessageEvent) => {
      let message: any;
      try {
        message = JSON.parse(String(event.data));
      } catch {
        return;
      }
      const entry = this.pending.get(message.id);
      if (!entry) return;
      clearTimeout(entry.timer);
      this.pending.delete(message.id);
      entry.resolve(message.error ? { error: message.error } : message.result);
    });
  }

  static open(url: string): Promise<CdpSession> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(url);
      const timer = setTimeout(() => reject(new Error("cdp: the page did not answer")), 5000);
      socket.addEventListener("open", () => {
        clearTimeout(timer);
        resolve(new CdpSession(socket));
      });
      socket.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error("cdp: could not open the page connection"));
      });
    });
  }

  send(method: string, params: Record<string, unknown> = {}): Promise<any> {
    const id = this.next++;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve({ error: { message: `${method} timed out` } });
      }, 8000);
      this.pending.set(id, { resolve, timer });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  close(): void {
    try {
      this.socket.close();
    } catch {
      // already gone
    }
  }
}

export function chromiumDriver(endpoint: string): Driver {
  const pages = async (): Promise<Target[]> => (await listTargets(endpoint)).filter((t) => t.type === "page" && t.webSocketDebuggerUrl);
  return {
    name: "chromium",
    fill: async (host, values) => {
      const page = (await pages()).find((target) => hostOf(target.url) === host);
      if (!page) return undefined;
      const session = await CdpSession.open(page.webSocketDebuggerUrl!);
      try {
        const document = await session.send("Runtime.evaluate", { expression: "document" });
        if (document?.error || !document?.result?.objectId) throw new Error("cdp: the page did not expose a document");
        const result = await session.send("Runtime.callFunctionOn", {
          objectId: document.result.objectId,
          functionDeclaration: `function fill${FILL_BODY.replace(" =>", "")}`,
          arguments: [{ value: values.password }, { value: values.username ?? "" }, { value: values.totp ?? "" }],
          returnByValue: true,
        });
        const outcome = outcomeOf(result?.result?.value);
        if (!outcome.ok) throw new Error(`vault: ${outcome.reason ?? "could not fill the form"}`);
        return { page: page.url, filled: outcome.filled ?? [] };
      } finally {
        session.close();
      }
    },
    hosts: async () => [...new Set((await pages()).map((target) => hostOf(target.url)).filter(Boolean))],
  };
}

/* -------------------------------------------------------------------- Safari */

// Safari has no automation protocol. It does expose `do JavaScript`, which works
// on an existing tab and needs only the "Allow JavaScript from Apple Events"
// setting.
function osascript(script: string): string {
  try {
    return execFileSync("/usr/bin/osascript", ["-e", script], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 15000,
    });
  } catch (error) {
    const stderr = String((error as { stderr?: unknown })?.stderr ?? "").trim();
    throw new Error(`safari: ${stderr || (error as Error).message}`);
  }
}

interface SafariTab {
  window: number;
  tab: number;
  url: string;
}

function safariTabs(): SafariTab[] {
  const script = `set output to ""
tell application "Safari"
  repeat with w from 1 to count of windows
    repeat with t from 1 to count of tabs of window w
      set output to output & (w as text) & "\\t" & (t as text) & "\\t" & (URL of tab t of window w) & "\\n"
    end repeat
  end repeat
end tell
return output`;
  return osascript(script)
    .split("\n")
    .map((line) => line.split("\t"))
    .filter((parts) => parts.length >= 3)
    .map((parts) => ({ window: Number(parts[0]), tab: Number(parts[1]), url: parts.slice(2).join("\t") }))
    .filter((tab) => Number.isFinite(tab.window) && Number.isFinite(tab.tab));
}

export function safariDriver(): Driver {
  return {
    name: "safari",
    fill: async (host, values) => {
      const tab = safariTabs().find((candidate) => hostOf(candidate.url) === host);
      if (!tab) return undefined;
      // The payload holds the value, so it goes in a private file rather than the
      // command line, and is removed immediately afterwards.
      // FILL_BODY already returns a JSON string, so it is the whole payload here;
      // wrapping it again would double-encode it and the result would not parse.
      const source = `(${FILL_BODY})(${JSON.stringify(values.password)}, ${JSON.stringify(
        values.username ?? "",
      )}, ${JSON.stringify(values.totp ?? "")})`;
      const file = path.join(os.tmpdir(), `vault-safari-${Date.now()}-${Math.floor(Math.random() * 1e6)}.js`);
      try {
        await fs.writeFile(file, source, { mode: 0o600 });
        const script = `set payload to read (POSIX file ${JSON.stringify(file)}) as «class utf8»
tell application "Safari" to do JavaScript payload in tab ${tab.tab} of window ${tab.window}`;
        const outcome = outcomeOf(osascript(script).trim());
        if (!outcome.ok) throw new Error(`vault: ${outcome.reason ?? "could not fill the form"}`);
        return { page: tab.url, filled: outcome.filled ?? [] };
      } finally {
        await fs.rm(file, { force: true });
      }
    },
    hosts: async () => [...new Set(safariTabs().map((tab) => hostOf(tab.url)).filter(Boolean))],
  };
}

/* ------------------------------------------------------ Firefox / Zen (BiDi) */

// Gecko exposes WebDriver BiDi instead of the DevTools protocol: connect to
// /session, create a session, then address a browsing context inside it.
class BidiSession {
  private socket: WebSocket;
  private next = 1;
  private pending = new Map<number, (value: any) => void>();

  private constructor(socket: WebSocket) {
    this.socket = socket;
    socket.addEventListener("message", (event: MessageEvent) => {
      let message: any;
      try {
        message = JSON.parse(String(event.data));
      } catch {
        return;
      }
      const resolve = this.pending.get(message.id);
      if (resolve) {
        this.pending.delete(message.id);
        resolve(message);
      }
    });
  }

  static async open(socketUrl: string): Promise<BidiSession> {
    // Gecko allows a single BiDi session at a time, and a previous one may still
    // be tearing down, so a retry here is normal rather than exceptional.
    for (let attempt = 0; ; attempt += 1) {
      const socket = new WebSocket(socketUrl);
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("bidi: the browser did not answer")), 5000);
        socket.addEventListener("open", () => {
          clearTimeout(timer);
          resolve();
        });
        socket.addEventListener("error", () => {
          clearTimeout(timer);
          reject(new Error("bidi: could not open the browser connection"));
        });
      });
      const session = new BidiSession(socket);
      const created = await session.send("session.new", { capabilities: {} });
      if (created?.type !== "error") return session;
      try {
        socket.close();
      } catch {
        // already gone
      }
      const message = String(created?.message ?? "");
      if (attempt < 3 && /maximum number of active sessions/i.test(message)) {
        await new Promise((resolve) => setTimeout(resolve, 400 * (attempt + 1)));
        continue;
      }
      throw new Error(`bidi: ${message || "could not start a session"}`);
    }
  }

  send(method: string, params: Record<string, unknown> = {}): Promise<any> {
    const id = this.next++;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.socket.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.delete(id)) resolve({ type: "error", message: `${method} timed out` });
      }, 8000);
    });
  }

  // Ending the session explicitly matters: Gecko permits only one, and dropping
  // the socket does not release it promptly.
  async close(): Promise<void> {
    try {
      await this.send("session.end");
    } catch {
      // nothing to end
    }
    try {
      this.socket.close();
    } catch {
      // already gone
    }
  }
}

export function geckoDriver(endpoint: string): Driver {
  const socketUrl = new URL("/session", endpoint).toString().replace(/^http/, "ws");
  return {
    name: "firefox",
    fill: async (host, values) => {
      const session = await BidiSession.open(socketUrl);
      try {
        const tree = await session.send("browsingContext.getTree", { maxDepth: 1 });
        const contexts = (tree?.result?.contexts ?? []) as { context: string; url: string }[];
        const page = contexts.find((entry) => hostOf(entry.url ?? "") === host);
        if (!page) return undefined;
        const response = await session.send("script.callFunction", {
          functionDeclaration: FILL_BODY,
          arguments: [
            { type: "string", value: values.password },
            { type: "string", value: values.username ?? "" },
            { type: "string", value: values.totp ?? "" },
          ],
          target: { context: page.context },
          awaitPromise: true,
          resultOwnership: "none",
        });
        if (response?.type === "error") throw new Error(`vault: ${response.message ?? "could not fill the form"}`);
        const outcome = outcomeOf(response?.result?.result?.value);
        if (!outcome.ok) throw new Error(`vault: ${outcome.reason ?? "could not fill the form"}`);
        return { page: page.url, filled: outcome.filled ?? [] };
      } finally {
        await session.close();
      }
    },
    hosts: async () => {
      const session = await BidiSession.open(socketUrl);
      try {
        const tree = await session.send("browsingContext.getTree", { maxDepth: 1 });
        const contexts = (tree?.result?.contexts ?? []) as { url: string }[];
        return [...new Set(contexts.map((entry) => hostOf(entry.url ?? "")).filter(Boolean))];
      } finally {
        await session.close();
      }
    },
  };
}

/* ---------------------------------------------------------------------- fill */

export async function fillLogin(drivers: Driver[], entryUrl: string, values: Values): Promise<FillReport> {
  const host = hostOf(entryUrl);
  if (!host) throw new Error("vault: this entry has no http(s) URL, so the destination cannot be verified");

  const problems: string[] = [];
  const open: string[] = [];
  for (const driver of drivers) {
    let filled: Filled | undefined;
    try {
      filled = await driver.fill(host, values);
    } catch (error) {
      problems.push(`${driver.name}: ${(error as Error).message}`);
      continue;
    }
    if (filled) return { driver: driver.name, host, page: filled.page, filled: filled.filled };
    try {
      open.push(...(await driver.hosts()));
    } catch {
      // that browser is not running; nothing to report
    }
  }

  const seen = [...new Set(open)];
  throw new Error(
    `vault: no open page on ${host}, so nothing was filled.` +
      (seen.length ? ` Open pages: ${seen.join(", ")}.` : "") +
      (problems.length ? ` (${problems.join("; ")})` : ""),
  );
}
