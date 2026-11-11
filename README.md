# vault

A local KeePass vault as a stateless Rust CLI plus a skill.

```
bin/vault               entry point: builds the Rust binary on first use, then execs it
Cargo.toml              Rust CLI crate
rust/main.rs            the whole CLI: reads, writes, TOTP, Keychain, `run`
rust/autofill_host.rs   native messaging host for the browser extension
browser/                Vault Autofill for Helium: extension, install and uninstall scripts
src/mcp.ts              optional MCP stdio adapter (kept, not wired into OpenCode)
src/tools.ts            MCP tool surface
src/vault.ts            the previous TypeScript .kdbx core
skills/vault/SKILL.md   when and how the agent should use the CLI
```

The CLI is one short-lived process per command: it opens the `.kdbx` (master
password from the macOS Keychain), does one thing, and exits. There is no
session, no daemon and no long-running server. Browser fill is optional: the
Vault Autofill extension in `browser/` runs the CLI through a native messaging
host, while an agent without the extension receives the value and injects it
itself, or uses `vault run` to hand it to a program without it entering the
conversation.

## Build and run

```sh
cargo build --release          # target/release/vault
cargo test                     # TOTP vectors and entry mapping
./bin/vault status             # builds on first run, then execs the binary
```

## Commands

```sh
vault path [--set /absolute/database.kdbx]
vault status | list
vault get <title> [--field password|username|recovery|notes|url|totp-seed]
vault totp <title> | recovery-codes <title>
vault put <title> [--username u] [--password p|--password-stdin] [--url u]
                  [--notes n] [--totp-seed s] [--recovery-code c]...
vault delete <title>
vault create --password-stdin
vault change-password [--current c] [--next n|--next-stdin]
vault destroy --confirm "<the vault path>"
vault run <title> -- <command> [args...]
vault passkey list | register --rp <RPID> | use --rp <RPID> | import ...
vault skills status|install|uninstall
```

Every command prints JSON to stdout; diagnostics go to stderr; a non-zero exit
means it failed.

## Passkeys

`vault passkey` captures and replays WebAuthn passkeys through a Chromium
browser driven over the DevTools Protocol (default `http://127.0.0.1:9333`,
override with `--cdp` or `VAULT_CDP`). Run a command in the background
(`vault passkey use --rp <rpId> --target <url substring> &`), wait for its
`{"ready":true,...}` stdout line, then click the site's passkey or sign-in
button in the same browser. `use` keeps its websocket open until the assertion,
exits 0 with `{"used":true,...}` and saves the new sign count; `register` works
the same and saves a new entry. Both wait up to `--timeout` seconds (default
120).

The virtual authenticator lives only while the command's CDP connection is
open, and Chrome resets virtual authenticators on a page whenever any DevTools
client detaches from it: drive the page from one persistent connection
(Playwright `connectOverCDP` is fine), and do not open and close short-lived
CDP clients on that page during the ceremony.

```sh
vault passkey list                                    # stored passkeys, never key material
vault passkey register --rp webauthn.io [--title t]   # capture a passkey the site registers
vault passkey use --rp webauthn.io [--title t]        # let a sign-in complete with a stored passkey
vault passkey import --rp rp --credential-id id --user-handle h \
    --username u --title t --private-key-stdin        # PKCS#8 PEM private key on stdin
vault passkey list --rp example.com                   # one site's passkeys
vault passkey create < request.json                   # make and store a passkey, no CDP
vault passkey sign < request.json                     # sign a sign-in, no CDP
```

`create` and `sign` are for a browser that asks the vault itself (Vault
Autofill does, after Touch ID): no CDP, one JSON request on stdin, one JSON
answer on stdout. `create` takes `rpId`, `userName`, `userHandle` (base64url)
and optionally `excludeCredentials` and `title`; it makes an ES256 key with
"none" attestation, stores it marked `VAULT_PASSKEY_BACKED_UP`, and returns the
credential id, attestation object, authenticator data and public key. `sign`
takes `rpId`, `clientDataHash` (base64url SHA-256) and `credentialId` or
`allowCredentials`, and returns the authenticator data, DER signature and user
handle. Only ES256 keys sign; a counter that never started stays at zero, so a
sign-in doesn't write the database.

`--target <url substring>` picks the page (or `--target-id`); with exactly one
page open it can be omitted, and errors list page urls only. Entries store
KeePassXC's `KPEX_PASSKEY_*` custom fields plus a `VAULT_PASSKEY_SIGN_COUNT`
sign counter, with the private key and user handle protected; `vault list`
flags them with `hasPasskey`. Registering a passkey changes a real account's
security settings, so get the owner's explicit OK for each account first.
Private keys are never printed; the key is handed to the browser only for the
ceremony. Verified on webauthn.io with CloakBrowser.

## Browser autofill (Helium)

`browser/` holds Vault Autofill and `rust/autofill_host.rs` is its native
messaging host. It fills logins, verification codes, addresses, cards and
passkeys from the same vault, asking Touch ID before a secret leaves it.

```sh
./browser/install.sh     # build both binaries, install the extension files and host manifest
```

In Helium, open `helium://extensions`, enable Developer mode the first time,
and Load unpacked from `~/.local/share/helium-autofill/extension`. After that,
run `browser/install.sh` and reload "Vault Autofill" whenever the extension
changes. The native host manifest is
`~/Library/Application Support/net.imput.helium/NativeMessagingHosts/dev.vault.autofill.json`.

The extension id comes from the `key` in `browser/extension/manifest.json`; the
installer derives it and writes it into `allowed_origins`. Reading the Messages
database for verification codes needs Full Disk Access for the host binary.
`./browser/uninstall.sh` removes the host; add `--purge` to remove the
installed extension files too.

The installed `host.sh` points at this checkout's `target/release/vault` and
`vault-autofill-host`. `VAULT_CLI` overrides the CLI path, and `VAULT_CLI_HOME`
runs it with another HOME for a test vault.

## State

- The vault file: `~/Library/Application Support/vault/vault.kdbx`, or whatever
  `~/.config/opencode/vault.json` / `VAULT_FILE` names.
- The master password: macOS Keychain, service `OpenCode Vault`, account = the
  vault path. `VAULT_PASSWORD` overrides it.

### Database location and iCloud Drive

`vault path` reports JSON with `path`, `source` (`config`, `env`, or `default`)
and `configFile`, without opening the database or accessing Keychain. It reports
a `warning` if malformed/unreadable config caused fallback. A nonblank configured
path takes precedence over `VAULT_FILE`, then the default applies.

To point at a database in iCloud Drive on this Mac:

```sh
./bin/vault path --set "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Vault/vault.kdbx"
```

The setter requires an absolute file path, preserves other JSON fields, writes
configuration atomically with mode `0600`, and refuses malformed/nonobject
configuration, symlinks and nonregular config files. It does not create or move
the database, create its parent folders, or change the master password/Keychain.
It leaves existing config-directory permissions unchanged. Manually written
JSON paths do not expand `~` or `$HOME`.

Configure each device separately. The exact local database path is the Keychain
account identifier, so a new location needs its own secure unlock setup. Sync
only the encrypted `.kdbx`, not credentials. Download the latest copy before use,
write from one device at a time, and wait for iCloud sync before switching;
the CLI does not merge concurrent database edits.

## Skill install

```sh
./bin/vault skills install      # symlink skills/vault into each detected agent
./bin/vault skills status       # per-agent link state, read-only
./bin/vault skills uninstall    # remove the links this tool made
```

It covers every agent present on the machine (Claude Code, Codex, Prime Agent,
OpenClaw, OpenCode, Antigravity, Hermes) and never replaces a link or file it
did not make.

## The MCP adapter

`src/mcp.ts` still speaks MCP over stdio and carries the older tool set,
including the browser-fill `login` tool that the Rust CLI dropped. It is no
longer started by OpenCode, which uses the CLI through the skill instead. Keep
it for a client that has no shell, or delete `src/`, `bin/vault-mcp` and
`driver.ts` once nothing needs it.
