// Vault Autofill in the page: a menu of the vault's accounts under a login field (one account fills
// straight away), and a verification code for a code field. Filling asks Touch ID first.
(() => {
  if (window.__vaultAutofill) return;
  window.__vaultAutofill = true;

  // Right after the browser starts, the extension's worker may not be up yet; ask again shortly.
  // A lookup that hangs gives up rather than leaving the page waiting; a fill waits for Touch ID.
  const LOOKUP_WAIT = 5_000;
  const TOUCH_ID_WAIT = 130_000;
  const ASKS_FOR_TOUCH_ID = new Set(["fill", "code", "card", "passkey-create", "passkey-sign"]);
  async function ask(message) {
    const wait = ASKS_FOR_TOUCH_ID.has(message.type) ? TOUCH_ID_WAIT : LOOKUP_WAIT;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const answer = await Promise.race([chrome.runtime.sendMessage(message), new Promise((ok) => setTimeout(() => ok(undefined), wait))]);
        if (answer !== undefined) return answer;
      } catch {}
      await new Promise((ok) => setTimeout(ok, 400));
    }
    return {};
  }
  const MENU_GAP = 4;
  const CODE_HINT = /(otp|totp|2fa|one.?time|verification|security.?code|auth.?code|passcode)/;
  const USER_HINT = /(user|email|e-mail|login|account|identifier)/;
  // Each kind (a login, a code, an address, a card) fills by itself once per form a page load, so a
  // cancelled Touch ID doesn't come back on every focus, and an address doesn't stop the card.
  const offered = new WeakMap();
  function firstOffer(scope, what) {
    const kinds = offered.get(scope) ?? new Set();
    if (kinds.has(what)) return false;
    offered.set(scope, kinds.add(what));
    return true;
  }
  let menu = null;
  // Focus moved by filling isn't a person asking for the menu.
  let filling = false;

  const visible = (el) => el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
  const hint = (el) => `${el.name} ${el.id} ${el.placeholder} ${el.getAttribute("aria-label") ?? ""}`.toLowerCase();
  const passwords = (scope) => [...scope.querySelectorAll("input[type=password]")]
    .filter((el) => visible(el) && !el.disabled && !(el.autocomplete ?? "").includes("new-password"));

  // Checkout fields by their autocomplete token, or failing that by their name, id or label.
  const ADDRESS_TOKENS = new Set(["name", "given-name", "family-name", "organization", "street-address", "address-line1",
    "address-line2", "address-level2", "address-level1", "postal-code", "country", "country-name"]);
  const TOKEN_HINTS = [
    ["cc-number", /(card.?number|cardnum|cc.?num|card.?no\b)/],
    ["cc-csc", /(cvc|cvv|csc|security.?code|card.?code)/],
    ["cc-exp-month", /(exp\w*.?month|cc.?month|card.?month)/],
    ["cc-exp-year", /(exp\w*.?year|cc.?year|card.?year)/],
    ["cc-exp", /(expir|exp.?date|mm.?yy)/],
    ["cc-name", /(name.?on.?card|card.?holder|cc.?name)/],
    ["given-name", /(first.?name|given.?name|fname)/],
    ["family-name", /(last.?name|family.?name|surname|lname)/],
    ["address-line2", /(address.?2|address.?line.?2|apartment|suite|\bapt\b|\bunit\b)/],
    ["address-line1", /(address.?1|address.?line.?1|street|address)/],
    ["address-level2", /(city|town|suburb)/],
    ["address-level1", /(state|province|region|county)/],
    ["postal-code", /(zip|postal|post.?code)/],
    ["country", /country/],
    ["organization", /(company|organi[sz]ation)/],
    ["tel", /(phone|mobile|\btel\b)/],
    ["email", /e.?mail/],
    ["name", /(full.?name|^name$|\bname\b)/],
  ];

  function token(el) {
    const tokens = (el.autocomplete ?? "").toLowerCase().split(/\s+/).filter((part) => part && !/^(section-|shipping|billing|home|work|on|off)/.test(part));
    if (tokens.length) return tokens[tokens.length - 1];
    const label = el.labels?.[0]?.textContent ?? "";
    const text = `${hint(el)} ${label.toLowerCase()}`;
    return TOKEN_HINTS.find(([, pattern]) => pattern.test(text))?.[0] ?? null;
  }

  function kind(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return null;
    const auto = (el.autocomplete ?? "").toLowerCase();
    if (auto.includes("one-time-code") || (el.type !== "password" && CODE_HINT.test(hint(el)))) return "code";
    if (el.type !== "password") {
      const which = token(el);
      if (which?.startsWith("cc-")) return "card";
      if (ADDRESS_TOKENS.has(which) && !passwords(el.form ?? document).length) return "address";
    }
    if (el.type === "password") return auto.includes("new-password") ? null : "password";
    if (!["text", "email", "tel", ""].includes(el.type)) return null;
    if (auto.includes("username") || el.type === "email" || auto === "email") return "username";
    if (USER_HINT.test(hint(el)) && passwords(el.form ?? document).length) return "username";
    return null;
  }

  // Through the page's own value setter, so frameworks that watch input events notice.
  function setValue(el, value) {
    filling = true;
    el.focus();
    filling = false;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function usernameFor(scope, field) {
    if (kind(field) === "username") return field;
    const candidates = [...scope.querySelectorAll("input")].filter((el) => visible(el) && kind(el) === "username");
    return candidates[0] ?? null;
  }

  async function fillLogin(field, account) {
    hide();
    const got = await ask({ type: "fill", title: account.title });
    if (got?.error || !got) return;
    const scope = field.form ?? document;
    const user = usernameFor(scope, field);
    const pass = kind(field) === "password" ? field : passwords(scope)[0];
    if (user && got.username) setValue(user, got.username);
    if (pass && got.password) setValue(pass, got.password);
    lastFilled = { username: got.username ?? "", password: got.password ?? "" };
  }

  // A code split across one-character boxes goes in box by box.
  function codeBoxes(field) {
    return field.maxLength === 1
      ? [...(field.form ?? field.parentElement?.parentElement ?? document).querySelectorAll("input")].filter((el) => el.maxLength === 1 && visible(el))
      : [field];
  }

  function fillCode(field, code) {
    const boxes = codeBoxes(field);
    if (boxes.length > 1) [...code].forEach((digit, i) => boxes[i] && setValue(boxes[i], digit));
    else setValue(field, code);
  }

  async function codeFrom(field, account, submit = false) {
    hide();
    const got = await ask({ type: "code", title: account.title });
    if (!got?.code) return;
    fillCode(field, got.code);
    if (submit) submitCode(field, account);
  }

  // A code the page rejects: it clears the field or shows why. Offer the code
  // again, and this time fill only: the person presses Verify themselves.
  const CODE_RETRY_MS = 8_000;
  const CODE_REJECTED = /(didn'?t work|incorrect|invalid|wrong|expired|not valid|try again|code.*(?:error|fail)|error.*code)/i;
  function submitCode(field, account) {
    const form = field.form ?? field.closest("form");
    const scope = form ?? document.body;
    let done = false;
    const offerAgain = () => {
      if (done) return;
      done = true;
      stop();
      const boxes = codeBoxes(field);
      for (const box of boxes) if (box.value) setValue(box, "");
      if (boxes.includes(document.activeElement)) {
        setTimeout(() => show(field, [{ label: "Use verification code", pick: () => codeFrom(field, account) }]), 0);
      }
    };
    const onInput = () => { if (!field.value) offerAgain(); };
    const observer = new MutationObserver((mutations) => {
      // Only what the page adds after the submit: an "Error" already on it isn't this code's.
      const text = mutations
        .flatMap((m) => [...m.addedNodes].map((n) => n.textContent ?? "").concat(m.type === "characterData" ? m.target.textContent ?? "" : []))
        .join(" ");
      if (text && CODE_REJECTED.test(text)) offerAgain();
    });
    const timer = setTimeout(stop, CODE_RETRY_MS);
    function stop() {
      field.removeEventListener("input", onInput);
      observer.disconnect();
      clearTimeout(timer);
    }
    field.addEventListener("input", onInput);
    observer.observe(scope, { childList: true, subtree: true, characterData: true });
    // What the person does: submit the form (Enter or the Verify button).
    const button = form?.querySelector('input[type="submit"], button[type="submit"], button:not([type])');
    if (button) button.click();
    else if (form) form.requestSubmit();
  }

  // A code field: the site's vault codes, and a recent one from Messages. One that's plainly this
  // site's fills straight away; a Messages code that might be another site's waits for a click.
  async function onCodeField(field, accounts) {
    const scope = field.form ?? document;
    const fromMessages = await ask({ type: "messages" });
    if (document.activeElement !== field) return;
    const totp = accounts.filter((account) => account.totp);
    if (fromMessages?.code && fromMessages.forSite && firstOffer(scope, "code")) return fillCode(field, fromMessages.code);
    if (!fromMessages?.code && totp.length === 1 && firstOffer(scope, "code")) return codeFrom(field, totp[0], true);
    const rows = totp.map((account) => ({
      // This menu only fills the code field: say so, instead of looking like another account.
      label: totp.length === 1 ? "Use verification code" : `Use code from ${account.title}`,
      pick: () => codeFrom(field, account),
    }));
    if (fromMessages?.code) rows.unshift({ label: `${fromMessages.code} · From Messages`, pick: () => { hide(); fillCode(field, fromMessages.code); } });
    if (rows.length) show(field, rows);
  }

  // What a checkout field gets from an address entry's fields.
  function addressValue(which, fields) {
    const [given = "", ...family] = (fields.name ?? "").split(" ");
    return {
      "name": fields.name, "given-name": given, "family-name": family.join(" "), "organization": fields.organization,
      "street-address": [fields.street, fields.street2].filter(Boolean).join("\n"), "address-line1": fields.street,
      "address-line2": fields.street2, "address-level2": fields.city, "address-level1": fields.state,
      "postal-code": fields.postcode, "country": fields.country, "country-name": fields.country, "tel": fields.phone, "email": fields.email,
    }[which];
  }

  // A card's expiry, stored MM/YY, written as the field wants it.
  function cardValue(which, fields, el) {
    const [month = "", year = ""] = (fields.expiry ?? "").split("/").map((part) => part.trim());
    const fullYear = year.length === 2 ? `20${year}` : year;
    const wantsFull = el.maxLength >= 4 && el.maxLength < 6 ? false : el.maxLength === 4 || /yyyy/i.test(el.placeholder);
    return {
      "cc-name": fields.cardholder, "cc-number": fields.number, "cc-csc": fields.cvc,
      "cc-exp": el.maxLength === 7 || /yyyy/i.test(el.placeholder) ? `${month}/${fullYear}` : `${month}/${year.slice(-2)}`,
      "cc-exp-month": month, "cc-exp-year": el instanceof HTMLSelectElement || wantsFull ? fullYear : year.slice(-2),
    }[which];
  }

  // A choice in a select: by value or by shown text, so "IL" or "Illinois", "08" or "8" or "August".
  function choose(select, value) {
    const want = String(value).toLowerCase();
    const option = [...select.options].find((o) => o.value.toLowerCase() === want || o.text.trim().toLowerCase() === want)
      ?? [...select.options].find((o) => /^\d+$/.test(want) && Number(o.value) === Number(want))
      ?? [...select.options].find((o) => o.text.trim().toLowerCase().startsWith(want))
      ?? [...select.options].find((o) => /^\d{2}$/.test(want) && (o.value.endsWith(want) || o.text.trim().endsWith(want)));
    if (!option) return;
    select.value = option.value;
    select.dispatchEvent(new Event("input", { bubbles: true }));
    select.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fillForm(field, valueFor) {
    const scope = field.form ?? document;
    for (const el of scope.querySelectorAll("input, select, textarea")) {
      if (!visible(el) || el.disabled || el.readOnly) continue;
      const value = valueFor(token(el), el);
      if (!value) continue;
      if (el instanceof HTMLSelectElement) choose(el, value);
      else if (!el.value) setValue(el, value);
    }
  }

  async function onAddressField(field) {
    const { addresses = [] } = await ask({ type: "addresses" });
    if (document.activeElement !== field || !addresses.length) return;
    const scope = field.form ?? document;
    const pick = (address) => { hide(); fillForm(field, (which) => addressValue(which, address.fields)); };
    if (addresses.length === 1 && firstOffer(scope, "address")) return pick(addresses[0]);
    show(field, addresses.map((address) => ({ label: address.title, pick: () => pick(address) })));
  }

  async function onCardField(field) {
    const { cards = [] } = await ask({ type: "cards" });
    if (document.activeElement !== field || !cards.length) return;
    const scope = field.form ?? document;
    const pick = async (card) => {
      hide();
      const got = await ask({ type: "card", title: card.title });
      if (got?.fields) fillForm(field, (which, el) => cardValue(which, got.fields, el));
    };
    if (cards.length === 1 && firstOffer(scope, "card")) return pick(cards[0]);
    show(field, cards.map((card) => ({ label: card.title, pick: () => pick(card) })));
  }

  async function onFocus(event) {
    const field = event.target;
    const webauthn = field instanceof HTMLInputElement && (field.autocomplete ?? "").toLowerCase().includes("webauthn");
    const what = filling ? null : kind(field) ?? (webauthn && conditional ? "username" : null);
    if (!what) return;
    if (what === "address") return onAddressField(field);
    if (what === "card") return onCardField(field);
    const { accounts = [] } = await ask({ type: "accounts" });
    if (document.activeElement !== field) return;
    if (what === "code") return onCodeField(field, accounts);
    const scope = field.form ?? document;
    // A site waiting for a passkey (conditional mediation) has its passkeys first; picking one
    // signs in, so it never happens by itself.
    const keys = conditional?.keys ?? [];
    if (!accounts.length && !keys.length) return;
    const pick = (account) => fillLogin(field, account);
    if (!keys.length && accounts.length === 1 && firstOffer(scope, "login")) return pick(accounts[0]);
    show(field, [
      ...keys.map((key) => ({ label: `${key.username || key.title} \u00b7 Passkey`, pick: () => useWaitingPasskey(key) })),
      ...accounts.map((account) => ({ label: account.username || account.title, pick: () => pick(account) })),
    ]);
  }

  const STYLE = `
    :host { all: initial; }
    .menu { position: fixed; z-index: 2147483647; box-sizing: border-box; padding: 3px; border-radius: 7px;
      background: #ffffff; color: #1f2328; border: 1px solid #d8dbe0; box-shadow: 0 8px 24px rgba(0,0,0,.18);
      font: 13px/1.35 -apple-system, system-ui, sans-serif; }
    .row { height: 26px; line-height: 26px; padding: 0 8px; border-radius: 5px; cursor: default;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .row.at { background: #3b82f6; color: #ffffff; }
    @media (prefers-color-scheme: dark) {
      .menu { background: #2b2f36; color: #dcdfe4; border-color: #3d424b; box-shadow: 0 8px 24px rgba(0,0,0,.45); }
      .row.at { background: #2f6fde; }
    }`;

  function show(field, rows) {
    hide();
    const host = document.createElement("vault-autofill");
    host.dataset.rows = String(rows.length);
    const root = host.attachShadow({ mode: "closed" });
    const box = document.createElement("div");
    box.className = "menu";
    const style = document.createElement("style");
    style.textContent = STYLE;
    root.append(style, box);
    const rect = field.getBoundingClientRect();
    // As wide as the field, one short line per account.
    Object.assign(box.style, { top: `${rect.bottom + MENU_GAP}px`, left: `${rect.left}px`, width: `${rect.width}px` });
    const items = rows.map((row, i) => {
      const item = document.createElement("div");
      item.className = "row";
      item.textContent = row.label;
      // Pressing keeps the field focused, so the menu isn't closed before the click lands.
      item.addEventListener("mousedown", (e) => e.preventDefault());
      item.addEventListener("click", () => row.pick());
      item.addEventListener("mouseenter", () => select(i));
      box.append(item);
      return item;
    });
    document.documentElement.append(host);
    menu = { host, field, rows, items, at: -1 };
    field.addEventListener("keydown", onKey, true);
    field.addEventListener("blur", hide, { once: true });
  }

  function select(i) {
    if (!menu) return;
    menu.at = i;
    menu.items.forEach((item, j) => item.classList.toggle("at", j === i));
  }

  function onKey(e) {
    if (!menu || !e.isTrusted) return;
    const count = menu.rows.length;
    if (e.key === "ArrowDown") select((menu.at + 1) % count);
    else if (e.key === "ArrowUp") select((menu.at - 1 + count) % count);
    else if (e.key === "Enter" && menu.at >= 0) menu.rows[menu.at].pick();
    else if (e.key === "Escape") hide();
    else return;
    e.preventDefault();
    e.stopPropagation();
  }

  function hide() {
    if (!menu) return;
    menu.field.removeEventListener("keydown", onKey, true);
    menu.host.remove();
    menu = null;
  }

  // Offering to save a login typed by hand: noticed as its form goes (submit, a submit button, Enter
  // in a password field), offered on the page that comes next, or on this one if it stays.
  const OFFER_AFTER = 1_500;
  const OFFER_SHOWN = 12_000;
  let lastFilled = null;
  let offer = null;

  function typedLogin(scope) {
    const filled = [...scope.querySelectorAll("input[type=password]")].filter((el) => el.value);
    if (!filled.length) return null;
    // A change-password form's new password comes last.
    const password = filled[filled.length - 1].value;
    const user = [...scope.querySelectorAll("input")].find((el) => el.value && el.type !== "password" && el.type !== "hidden"
      && (kind(el) === "username" || el.type === "email"));
    return { username: user?.value ?? "", password };
  }

  async function noticeLogin(scope) {
    const login = typedLogin(scope);
    if (!login || (lastFilled && lastFilled.username === login.username && lastFilled.password === login.password)) return;
    const { pending } = await ask({ type: "typed", ...login });
    if (pending) setTimeout(checkOffer, OFFER_AFTER);
  }

  async function checkOffer() {
    if (offer || window !== window.top) return;
    const pending = await ask({ type: "pending" });
    // Clicking a submit button notices the login twice (its click, then the form's submit), so two
    // checks can be in flight at once: only the first to come back may show the offer.
    if (pending && "username" in pending && !offer) showOffer(pending);
  }

  // The offer: what was typed, in fields that can be corrected before saving.
  function showOffer(pending) {
    const host = document.createElement("vault-autofill-save");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .toast { position: fixed; z-index: 2147483647; top: 12px; right: 12px; width: 300px; box-sizing: border-box;
        padding: 12px 12px 10px 14px; border-radius: 10px; background: #ffffff; color: #1f2328; border: 1px solid #d8dbe0;
        box-shadow: 0 10px 28px rgba(0,0,0,.18); font: 13px/1.4 -apple-system, system-ui, sans-serif; transition: opacity .25s; }
      .title { font-weight: 600; padding-right: 22px; }
      .site { opacity: .65; font-size: 12px; margin-bottom: 8px; }
      .field { display: flex; align-items: center; gap: 6px; margin-top: 6px; }
      .field label { width: 64px; flex: none; opacity: .7; font-size: 12px; }
      input { flex: 1; min-width: 0; font: inherit; color: inherit; background: transparent; border: 1px solid #d8dbe0;
        border-radius: 6px; padding: 3px 6px; outline: none; }
      input:focus { border-color: #3b82f6; }
      .show { font-size: 12px; padding: 2px 6px; }
      .actions { display: flex; justify-content: flex-end; gap: 6px; margin-top: 10px; }
      button { font: inherit; border-radius: 6px; padding: 4px 12px; cursor: default; border: 1px solid #d8dbe0; background: transparent; color: inherit; }
      .save { background: #3b82f6; border-color: #3b82f6; color: #fff; }
      .close { position: absolute; top: 6px; right: 6px; width: 22px; height: 22px; padding: 0; border: none; font-size: 16px; line-height: 20px; opacity: .55; }
      .close:hover { opacity: 1; }
      .note { opacity: .7; }
      @media (prefers-color-scheme: dark) {
        .toast { background: #2b2f36; color: #dcdfe4; border-color: #3d424b; box-shadow: 0 10px 28px rgba(0,0,0,.45); }
        input, button { border-color: #474d57; } input:focus { border-color: #2f6fde; } .save { background: #2f6fde; border-color: #2f6fde; }
      }`;
    const make = (tag, props) => Object.assign(document.createElement(tag), props);
    const box = make("div", { className: "toast" });
    const close = make("button", { className: "close", textContent: "\u00d7", title: "Close" });
    const user = make("input", { className: "user", value: pending.username ?? "", placeholder: "No username", spellcheck: false });
    const pass = make("input", { className: "pass", type: "password", value: pending.password ?? "" });
    const show = make("button", { className: "show", textContent: "Show" });
    const later = make("button", { className: "later", textContent: "Not now" });
    const save = make("button", { className: "save", textContent: pending.update ? "Update" : "Save" });
    const field = (name, ...children) => {
      const row = make("div", { className: "field" });
      row.append(make("label", { textContent: name }), ...children);
      return row;
    };
    const actions = make("div", { className: "actions" });
    actions.append(later, save);
    box.append(close, make("div", { className: "title", textContent: pending.update ? "Update the saved password?" : "Save this password?" }),
      make("div", { className: "site", textContent: location.hostname }), field("Username", user), field("Password", pass, show), actions);
    root.append(style, box);
    // One offer at a time: a repeated notice replaces the one on screen rather than stacking a
    // second copy over it (whose buttons would then have nothing left to close).
    if (offer) {
      clearTimeout(offer.timer);
      offer.host.remove();
    }
    document.documentElement.append(host);
    offer = { host, timer: null };
    const away = (dismiss = true) => {
      const current = offer?.host === host;
      if (current) {
        clearTimeout(offer.timer);
        offer = null;
      }
      // This host goes even if a newer offer took over, so an old toast is never stuck on screen.
      box.style.opacity = "0";
      setTimeout(() => host.remove(), 250);
      if (dismiss && current) ask({ type: "dismiss" });
    };
    // It fades by itself, but not while the pointer is on it or a field is being edited.
    const soon = () => {
      if (offer?.host !== host) return;
      clearTimeout(offer.timer);
      if (!box.matches(":hover") && !root.activeElement) offer.timer = setTimeout(() => away(), OFFER_SHOWN);
    };
    const hold = () => { if (offer?.host === host) clearTimeout(offer.timer); };
    box.addEventListener("mouseenter", hold);
    box.addEventListener("mouseleave", soon);
    box.addEventListener("focusin", hold);
    box.addEventListener("focusout", () => setTimeout(soon, 0));
    close.addEventListener("click", (e) => e.isTrusted && away());
    later.addEventListener("click", (e) => e.isTrusted && away());
    show.addEventListener("click", (e) => {
      if (!e.isTrusted) return;
      pass.type = pass.type === "password" ? "text" : "password";
      show.textContent = pass.type === "password" ? "Show" : "Hide";
    });
    const store = async () => {
      if (offer?.host === host) clearTimeout(offer.timer);
      save.disabled = later.disabled = true;
      const got = await ask({ type: "save", username: user.value.trim(), password: pass.value });
      const note = got?.saved ? (got.created ? "Saved to a new vault" : "Saved to your vault") : "Couldn\u2019t save it";
      actions.replaceChildren(make("div", { className: "note", textContent: note }));
      setTimeout(() => away(false), 1_800);
    };
    save.addEventListener("click", (e) => e.isTrusted && store());
    for (const input of [user, pass]) input.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.isTrusted) store(); });
    // Where the controls are, for tests that press them as a person would.
    const at = (el) => { const r = el.getBoundingClientRect(); return `${Math.round(r.x + r.width / 2)},${Math.round(r.y + r.height / 2)}`; };
    Object.assign(host.dataset, { save: at(save), later: at(later), close: at(close), user: at(user), pass: at(pass) });
    soon();
  }

  document.addEventListener("submit", (e) => noticeLogin(e.target), true);
  document.addEventListener("click", (e) => {
    const button = e.target instanceof Element ? e.target.closest("button, input[type=submit]") : null;
    if (button && !button.closest("vault-autofill-save")) noticeLogin(button.form ?? button.closest("form") ?? document);
  }, true);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target instanceof HTMLInputElement && e.target.type === "password") noticeLogin(e.target.form ?? document);
  }, true);
  checkOffer();

  // A site's passkey requests, from the page's own world (webauthn.js). The vault answers when it
  // has a passkey for the site, or when asked to save a new one; otherwise the page asks Chromium.
  const passkeyIds = new Set();
  // A sign-in waiting for a passkey to be picked in the field menu (conditional mediation).
  let conditional = null;
  let sheet = null;

  const answerPage = (id, answer) =>
    document.dispatchEvent(new CustomEvent("vault-passkey-answer", { detail: JSON.stringify({ id, ...answer }) }));
  const refused = (message = "The passkey wasn't used.") => ({ error: "NotAllowedError", message });
  const ALREADY_SAVED = { error: "InvalidStateError", message: "The vault already has a passkey for this account." };

  document.addEventListener("vault-passkey", async (event) => {
    let request;
    try { request = JSON.parse(event.detail); } catch { return; }
    // The page sends again until it hears back; each request is answered once.
    if (typeof request?.id !== "string" || passkeyIds.has(request.id)) return;
    passkeyIds.add(request.id);
    answerPage(request.id, { ack: true });
    if (window !== window.top || typeof request.rpId !== "string" || typeof request.challenge !== "string") {
      return answerPage(request.id, { fallback: true });
    }
    request.allow = Array.isArray(request.allow) ? request.allow.filter((id) => typeof id === "string") : [];
    request.exclude = Array.isArray(request.exclude) ? request.exclude.filter((id) => typeof id === "string") : [];
    // A new request ends one waiting in the menu or a sheet, as in Chrome.
    if (conditional) {
      answerPage(conditional.id, { error: "AbortError", message: "Another passkey request started." });
      conditional = null;
    }
    closeSheet();
    if (request.kind === "create") answerPage(request.id, await createPasskey(request));
    else if (request.kind === "get") getPasskey(request);
    else answerPage(request.id, { fallback: true });
  });

  document.addEventListener("vault-passkey-cancel", (event) => {
    let id;
    try { ({ id } = JSON.parse(event.detail)); } catch { return; }
    if (conditional?.id === id) conditional = null;
    if (sheet?.id === id) closeSheet();
  });

  async function signIn(request, key) {
    const got = await ask({ type: "passkey-sign", rpId: request.rpId, challenge: request.challenge, credentialId: key.credentialId });
    return got?.signature ? got : refused();
  }

  async function getPasskey(request) {
    const listed = await ask({ type: "passkeys", rpId: request.rpId });
    const keys = (listed.passkeys ?? []).filter((key) => !request.allow.length || request.allow.includes(key.credentialId));
    if (!keys.length) return answerPage(request.id, { fallback: true });
    if (request.mediation === "conditional") {
      conditional = { ...request, keys };
      // A login field focused already shows them now.
      if (document.activeElement instanceof HTMLInputElement) onFocus({ target: document.activeElement });
      return;
    }
    // One passkey goes straight to Touch ID; several ask which.
    let key = keys[0];
    if (keys.length > 1) {
      const choice = await askSheet({
        id: request.id,
        title: "Sign in with a passkey",
        rows: keys.map((each) => ({ label: each.username || each.title, value: each })),
        actions: [{ label: "Other device", value: "other" }],
      });
      if (choice === "other") return answerPage(request.id, { fallback: true });
      if (typeof choice !== "object") return answerPage(request.id, refused());
      key = choice;
    }
    answerPage(request.id, await signIn(request, key));
  }

  async function useWaitingPasskey(key) {
    hide();
    const request = conditional;
    if (!request) return;
    conditional = null;
    const answer = await signIn(request, key);
    // Touch ID cancelled: the site is still waiting, and the passkey stays in the menu.
    if (answer.error) conditional = request;
    else answerPage(request.id, answer);
  }

  async function createPasskey(request) {
    const listed = await ask({ type: "passkeys", rpId: request.rpId });
    if (listed.error) return { fallback: true };
    if ((listed.passkeys ?? []).some((key) => request.exclude.includes(key.credentialId))) {
      await askSheet({
        id: request.id,
        title: "Already in your vault",
        text: `Your vault has a passkey for this account.`,
        actions: [{ label: "OK", value: "ok", primary: true }],
      });
      return ALREADY_SAVED;
    }
    const choice = await askSheet({
      id: request.id,
      title: "Save a passkey in your vault?",
      text: request.userName || request.userDisplayName,
      actions: [{ label: "Other device", value: "other" }, { label: "Save", value: "save", primary: true }],
      keep: true,
    });
    if (choice === "other") return { fallback: true };
    if (choice !== "save") return refused();
    const got = await ask({
      type: "passkey-create", rpId: request.rpId, challenge: request.challenge,
      userName: request.userName, userHandle: request.userHandle, excludeCredentials: request.exclude,
    });
    sheetNote(got?.attestationObject ? (got.created ? "Saved to a new vault" : "Saved to your vault") : "Couldn\u2019t save the passkey");
    if (got?.attestationObject) return got;
    return /excluded:/.test(got?.error ?? "") ? ALREADY_SAVED : refused();
  }

  const SHEET_STYLE = `
    :host { all: initial; }
    .toast { position: fixed; z-index: 2147483647; top: 12px; right: 12px; width: 300px; box-sizing: border-box;
      padding: 12px 12px 10px 14px; border-radius: 10px; background: #ffffff; color: #1f2328; border: 1px solid #d8dbe0;
      box-shadow: 0 10px 28px rgba(0,0,0,.18); font: 13px/1.4 -apple-system, system-ui, sans-serif; }
    .title { font-weight: 600; padding-right: 22px; }
    .site { opacity: .65; font-size: 12px; margin-bottom: 8px; }
    .text { margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    button { font: inherit; color: inherit; cursor: default; }
    .account { display: block; width: 100%; height: 28px; margin-top: 4px; padding: 0 8px; text-align: left; border-radius: 6px;
      border: 1px solid #d8dbe0; background: transparent; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .account:hover { background: #3b82f6; border-color: #3b82f6; color: #fff; }
    .actions { display: flex; justify-content: flex-end; gap: 6px; margin-top: 10px; }
    .actions button { border-radius: 6px; padding: 4px 12px; border: 1px solid #d8dbe0; background: transparent; }
    .actions .primary { background: #3b82f6; border-color: #3b82f6; color: #fff; }
    .close { position: absolute; top: 6px; right: 6px; width: 22px; height: 22px; padding: 0; border: none; background: transparent;
      font-size: 16px; line-height: 20px; opacity: .55; }
    .close:hover { opacity: 1; }
    .note { opacity: .7; }
    @media (prefers-color-scheme: dark) {
      .toast { background: #2b2f36; color: #dcdfe4; border-color: #3d424b; box-shadow: 0 10px 28px rgba(0,0,0,.45); }
      .account, .actions button { border-color: #474d57; }
      .account:hover, .actions .primary { background: #2f6fde; border-color: #2f6fde; }
    }`;

  // A small sheet at the top right for a passkey choice. It answers with the row or action picked,
  // or "cancel"; only a real click counts. With `keep`, it stays up after the pick for a note.
  function askSheet({ id, title, text = "", rows = [], actions = [], keep = false }) {
    closeSheet();
    const make = (tag, props) => Object.assign(document.createElement(tag), props);
    const host = document.createElement("vault-autofill-passkey");
    const root = host.attachShadow({ mode: "closed" });
    const box = make("div", { className: "toast" });
    const close = make("button", { className: "close", textContent: "\u00d7", title: "Close" });
    box.append(close, make("div", { className: "title", textContent: title }), make("div", { className: "site", textContent: location.hostname }));
    if (text) box.append(make("div", { className: "text", textContent: text }));
    const list = rows.map((row) => make("button", { className: "account", textContent: row.label }));
    box.append(...list);
    const bar = make("div", { className: "actions" });
    const buttons = actions.map((action) => make("button", { className: action.primary ? "primary" : "", textContent: action.label }));
    bar.append(...buttons);
    if (buttons.length) box.append(bar);
    root.append(make("style", { textContent: SHEET_STYLE }), box);
    document.documentElement.append(host);
    return new Promise((resolve) => {
      let settled = false;
      const settle = (value) => { if (!settled) { settled = true; resolve(value); } };
      sheet = { id, host, bar, settle, make };
      const pick = (value) => (e) => {
        if (!e.isTrusted || sheet?.host !== host) return;
        settle(value);
        if (keep && value !== "other") bar.replaceChildren(make("div", { className: "note", textContent: "Waiting for Touch ID\u2026" }));
        else closeSheet();
      };
      close.addEventListener("click", (e) => { if (e.isTrusted && sheet?.host === host) closeSheet(); });
      list.forEach((el, i) => el.addEventListener("click", pick(rows[i].value)));
      buttons.forEach((el, i) => el.addEventListener("click", pick(actions[i].value)));
      // Where the controls are, for tests that press them as a person would.
      const at = (el) => { const r = el.getBoundingClientRect(); return `${Math.round(r.x + r.width / 2)},${Math.round(r.y + r.height / 2)}`; };
      host.dataset.close = at(close);
      list.forEach((el, i) => { host.dataset[`row${i}`] = at(el); });
      buttons.forEach((el, i) => { host.dataset[actions[i].value] = at(el); });
    });
  }

  function closeSheet() {
    if (!sheet) return;
    const { host, settle } = sheet;
    sheet = null;
    host.remove();
    settle("cancel");
  }

  function sheetNote(text) {
    if (!sheet) return;
    const { host, bar, make } = sheet;
    bar.replaceChildren(make("div", { className: "note", textContent: text }));
    setTimeout(() => { if (sheet?.host === host) closeSheet(); }, 1_600);
  }

  document.addEventListener("focusin", onFocus, true);
  // A field focused before this arrived (autofocus) gets its turn now.
  if (document.activeElement instanceof HTMLInputElement) onFocus({ target: document.activeElement });
  window.addEventListener("scroll", hide, true);
  window.addEventListener("resize", hide);
})();
