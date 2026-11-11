# Coding agent instructions

## Repository
- `vault` is a local KeePass vault implemented as a stateless Rust CLI plus an agent skill.
- Each CLI command runs in one short-lived process; `path` and `skills` do not open the `.kdbx`.
- The CLI has no session, daemon, or long-running server.

## Layout
- `Cargo.toml`: Rust crate `vault-cli`; binaries `vault` and `vault-autofill-host`.
- `rust/main.rs`: CLI commands, database access, TOTP, Keychain, and command execution.
- `rust/autofill_host.rs`: native messaging host for the Vault Autofill extension (macOS).
- `browser/extension/`: the Vault Autofill extension for Helium.
- `browser/install.sh`, `browser/uninstall.sh`: install or remove its host manifest.
- `rust/cdp.rs` and `rust/passkey.rs`: browser CDP and passkey support.
- `bin/vault`: builds the release binary when absent or stale, then executes it.
- `skills/vault/SKILL.md`: agent instructions for using the CLI.
- `src/mcp.ts` and `src/tools.ts`: retained optional MCP stdio adapter and tools.
- `src/vault.ts`: previous TypeScript `.kdbx` implementation.

## Verification
- Run `cargo test` from the repository root.
- Build both binaries with `cargo build --release --bin vault --bin vault-autofill-host`.
- Install the browser helper with `./browser/install.sh`; it writes the host manifest for Helium.

## Repository safety
- Work on a feature branch based on `main`.
- Use imperative commit subjects of at most 72 characters.
- Do not include AI attribution in commits.
- Never commit to or merge `main`.
- Never run `git stash`.
- Never put secrets in code or logs.
- Do not treat an installed CLI as authenticated or authorized access.

## Gotchas
- The master password comes from nonempty `VAULT_PASSWORD`, then macOS Keychain.
- Config and database writes use mode `0600`; database saves set the parent directory to `0700`.
- Configured database paths take precedence over `VAULT_FILE`, then the default path.
- Manually written JSON paths do not expand `~` or `$HOME`.
- The exact database path is the Keychain account identifier.
- Setting a database path does not move the database or configure its unlock credentials.
- Sync only the encrypted `.kdbx`; write from one device at a time.
- The CLI does not merge concurrent database edits.
- Structured CLI reports use JSON on stdout; `vault skills` prints plain text; diagnostics go to stderr.
- The retained MCP adapter includes the older browser-fill `login` tool; the Rust CLI does not.
- The browser extension talks to the native host `dev.vault.autofill`; its id is derived from the `key` in `browser/extension/manifest.json`.
- `browser/install.sh` writes the host manifest for Helium only; another Chromium profile needs `VAULT_HELIUM_DIR` or its own copy.
- Passkey ceremonies require the command's CDP connection to remain open.
- Detaching any DevTools client can reset the page's virtual authenticators.
- Obtain explicit owner approval per account before registering a passkey.
