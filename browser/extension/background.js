// Passes a page's requests to the vault autofill host, naming the page by the frame Chrome says asked,
// never by anything the page itself claims.
const HOST = "dev.vault.autofill";
const ACCOUNTS_KEEP = 60_000;
const accounts = new Map();
const typed = new Map();
// A login being checked against the vault: the page after a sign-in asks before the check is done.
const typedChecks = new Map();
const TYPED_KEEP = 60_000;
// Chromium stops an idle extension worker after 30 seconds and doesn't always manage to start it
// again, and a page asking a stopped worker waits for good. A small call every 20 seconds keeps it up.
const KEEP_AWAKE = 20_000;
const b64url = (data) => {
  let text = "";
  for (const byte of new Uint8Array(data)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
setInterval(() => chrome.runtime.getPlatformInfo(() => {}), KEEP_AWAKE);

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  const url = sender.url;
  if (!url || !/^https?:/.test(url)) return false;
  const ask = (request) => chrome.runtime.sendNativeMessage(HOST, { ...request, url });
  (async () => {
    if (message.type === "accounts") {
      // Names only, so they're kept a minute; a password is fetched, after Touch ID, each time.
      const site = new URL(url).host;
      const kept = accounts.get(site);
      if (kept && Date.now() - kept.at < ACCOUNTS_KEEP) return kept.value;
      const value = await ask({ type: "accounts" });
      if (!value.error) accounts.set(site, { at: Date.now(), value });
      return value;
    }
    if (message.type === "fill" || message.type === "code") return ask({ type: message.type, title: message.title });
    // A typed login waits here (never in the page) for the page's offer to save it.
    if (message.type === "typed") {
      const site = new URL(url).host;
      const check = (async () => {
        const known = await ask({ type: "known", username: message.username, password: message.password });
        if (known.same || known.error) typed.delete(site);
        else typed.set(site, { username: message.username, password: message.password, update: !!known.update, at: Date.now() });
      })();
      typedChecks.set(site, check);
      await check;
      if (typedChecks.get(site) === check) typedChecks.delete(site);
      return typed.has(site) ? { pending: true } : {};
    }
    if (message.type === "pending") {
      await typedChecks.get(new URL(url).host);
      const login = typed.get(new URL(url).host);
      if (!login || Date.now() - login.at > TYPED_KEEP) return {};
      // The page had the password already: it was typed there. The offer shows it to edit.
      return { username: login.username, password: login.password, update: login.update };
    }
    if (message.type === "save") {
      const site = new URL(url).host, login = typed.get(site);
      typed.delete(site);
      if (!login) return { error: "nothing to save" };
      accounts.delete(site);
      // What the offer's fields hold, edited or not.
      const username = typeof message.username === "string" ? message.username : login.username;
      const password = typeof message.password === "string" && message.password ? message.password : login.password;
      return ask({ type: "save", username, password });
    }
    if (message.type === "dismiss") {
      typed.delete(new URL(url).host);
      return {};
    }
    if (message.type === "messages" || message.type === "addresses" || message.type === "cards") return ask({ type: message.type });
    if (message.type === "card") return ask({ type: "card", title: message.title });
    // Passkeys: the page gives the site's challenge and which passkey; the client data the
    // signature covers names the page's real origin, as Chromium's would.
    if (message.type === "passkeys") return ask({ type: "passkeys", rpId: String(message.rpId ?? "") });
    if (message.type === "passkey-create" || message.type === "passkey-sign") {
      if (sender.frameId !== 0) return { error: "passkeys are for the page itself, not its frames" };
      if (typeof message.challenge !== "string" || !/^[A-Za-z0-9_-]+$/.test(message.challenge)) return { error: "no challenge" };
      const create = message.type === "passkey-create";
      const clientData = new TextEncoder().encode(JSON.stringify({
        type: create ? "webauthn.create" : "webauthn.get", challenge: message.challenge, origin: new URL(url).origin, crossOrigin: false,
      }));
      const answer = create
        ? await ask({
          type: "passkey-create", rpId: String(message.rpId ?? ""), userName: String(message.userName ?? ""),
          userHandle: String(message.userHandle ?? ""), excludeCredentials: Array.isArray(message.excludeCredentials) ? message.excludeCredentials : [],
        })
        : await ask({
          type: "passkey-sign", rpId: String(message.rpId ?? ""), credentialId: String(message.credentialId ?? ""),
          clientDataHash: b64url(await crypto.subtle.digest("SHA-256", clientData)),
        });
      return answer.error ? answer : { ...answer, clientDataJSON: b64url(clientData) };
    }
    return { error: "unknown request" };
  })().then(reply, (error) => reply({ error: String(error) }));
  return true;
});
