---
name: vault
description: Account passwords, TOTP codes and recovery codes in a local KeePass (.kdbx) vault. Use for credentials, one-time codes, and vault database location or sync setup. The `vault` CLI is stateless.
metadata:
  opencode/autoinvoke: true
---

# Vault

A KeePass-compatible `.kdbx` database read and written by the `vault` CLI. The
master password lives in the macOS Keychain under the service `OpenCode Vault`,
keyed by the vault path, so opening is silent and nothing is typed. There is no
MCP server: every command is one short-lived process, and the vault is opened
and closed on each call.

On this host, invoke `/Users/carlvincetan/code/agents/vault/bin/vault`;
`vault` below is shorthand, not a guarantee that it is on `PATH`. On other
devices, resolve their installed CLI path.

## Database location and iCloud Drive

Use these commands for location setup:

```sh
vault path                         # effective path, source and configFile; no credential access
vault path --set /absolute/vault.kdbx # update local config only; does not move the database
```

Prefer `path`, not `status`, when only inspecting location: `status` checks the
master password through Keychain. `path` never opens the database or accesses
credentials. The setter preserves unknown JSON fields, writes atomically with
mode `0600`, and refuses malformed/nonobject config, symlinks and nonregular
config files. It leaves existing config-directory permissions unchanged.

Resolution order:

1. A nonblank `path` in `~/.config/opencode/vault.json`.
2. The `VAULT_FILE` environment variable.
3. The default `~/Library/Application Support/vault/vault.kdbx`.

Use an absolute path in configuration: the CLI does not expand `~` or `$HOME`
inside JSON. Other commands silently fall back on invalid configuration;
`vault path` reports a warning. Check its reported path/source before use.

For this user's synced vaults, prefer `iCloud Drive/Vault/vault.kdbx` when
explicitly configured. Each Mac needs its own local configuration. After
approval to change the location, use:

```sh
vault path --set "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Vault/vault.kdbx"
```

- Sync the encrypted `.kdbx` file, not the master password or local config.
  Each device needs a secure unlock setup. The macOS Keychain entry uses service
  `OpenCode Vault` and the exact local database path as its account identifier;
  changing the path changes the lookup. Do not assume unlock setup syncs.
- Changing this skill or the config does not move an existing database. Ask
  before changing an existing vault's configured location, migrating it, or
  changing unlock setup. Never overwrite an existing destination or delete
  the source as cleanup without approval.
- For an existing synced database, do not use `create` or `change-password` merely
  to register it on another device: those commands create or re-encrypt a vault.
- Ensure the latest file is downloaded locally before use. Use one writing
  device at a time and wait for iCloud sync before switching. The CLI does not
  merge concurrent edits; stop on sync conflicts rather than choosing a copy
  or overwriting automatically.

## Rules

1. Secrets are now returned to you directly. Never repeat a value in a summary,
   a file, a commit, a log or a memory; use it and drop it.
2. Prefer passing a secret to a program without echoing it: `vault run` execs a
   command with the entry's fields in the environment.
3. Ask before `delete` and `destroy`. `destroy` also requires the vault path
   typed out as `--confirm`.
4. `put` changes only the fields passed, so adding a TOTP seed does not clear a
   password. Ask before storing a secret you did not generate.
5. Every command prints JSON to stdout. Diagnostics go to stderr and a non-zero
   exit means it failed.

## Reads

```sh
vault path                                    # location metadata, no Keychain access
vault status                                  # path, exists, passwordAvailable
vault list                                    # titles, which fields each holds, own plain fields; never a protected value
vault get <title>                             # password + username
vault get <title> --field username            # username
vault get <title> --field totp-seed           # the stored seed
vault get <title> --field recovery            # recovery codes
vault get <title> --field notes               # notes
vault get <title> --field url                 # stored URL
vault totp <title>                            # current code + secondsUntilExpiry
vault recovery-codes <title>                  # recovery codes as a list
vault fields <title>                          # the entry's own fields, protected ones included
```

An entry may hold no password because the site is OAuth- or passkey-only; read
`--field notes` for the provider and identity before concluding nothing is
stored.

## Writes

```sh
vault put <title> --username u --password p --url https://... --notes "..."
vault put <title> --totp-seed JBSWY3DPEHPK3PXP     # bare seed or otpauth:// URL
vault put <title> --recovery-code AAAA --recovery-code BBBB
vault put <title> --password-stdin                  # read the password from stdin
vault delete <title>
vault create --password-stdin                       # new empty vault, refuses overwrite
vault change-password --next-stdin                  # re-encrypt + update Keychain
vault destroy --confirm "<the vault path>"
```

Pass `--password-stdin`/`--next-stdin` when a value should not appear in the
process list or shell history.

## Addresses and cards

An entry can hold fields of its own: `--field NAME=VALUE` (shown by `list`) and
`--secret-field NAME=VALUE` (stored protected, listed by name only, read back with
`vault fields`). An empty value removes a field. Herdr's browser panes fill
checkout forms from entries that use these names:

```sh
vault put "Home address" --field name="A Person" --field organization="..." \
  --field street="1 Main St" --field street2="Apt 2" --field city=Springfield \
  --field state=IL --field postcode=62701 --field country="United States" \
  --field phone="+1 555 0100" --field email=a@example.com
vault put "Visa" --field cardholder="A Person" --field expiry=08/29 \
  --secret-field number=4111111111111111 --secret-field cvc=123
```

An entry with `street` or `postcode` is an address; one with a secret `number` is
a card. Card numbers and security codes are secrets: ask before storing ones you
did not generate, and never repeat them.

Some sites have no password to store because they are OAuth- or passkey-only.
Keep an entry anyway and record how to sign in with `--notes`, for example
`--notes "Sign in with Google — carl@gmail.com"` or a note that the passkey
lives in iCloud Keychain.

## Passing a secret to another command

`vault run` opens the vault and execs a command with the entry's fields in the
environment, so a value never has to travel through you:

```sh
vault run GitHub -- ./deploy.sh
```

It exports whichever of these exist: `VAULT_TITLE`, `VAULT_USERNAME`,
`VAULT_PASSWORD`, `VAULT_URL`, `VAULT_NOTES`, `VAULT_TOTP`,
`VAULT_TOTP_SEED`, `VAULT_RECOVERY_CODES`. The child inherits stdio and its exit
code becomes `vault`'s.

## Passkeys (agent sign-in)

A stored passkey can complete a site's sign-in with no human step, through a
Chromium browser driven over CDP (default `http://127.0.0.1:9333`,
`--cdp`/`VAULT_CDP`):

```sh
vault passkey use --rp google.com --target accounts.google.com &   # rpId is the registrable domain, not the page host
# wait for its {"ready":true,...} line, then click the site's "Use passkey"/sign-in button
```

Run it in the background, wait for the `{"ready":true,...}` stdout line, then
click the site's passkey or sign-in button in the same browser. It exits 0
after the assertion printing `{"used":true,...}` and saves the new sign count;
registering works the same with `register` (`--rp`, then click) and saves the
new passkey as a new entry. `--target <url substring>` (or `--target-id`) picks
the page when more than one is open, and `--timeout` defaults to 120s.

The virtual authenticator lives only while the command's CDP connection is
open, and Chrome resets virtual authenticators on a page whenever any DevTools
client detaches from it. Drive the page from one persistent connection
(Playwright `connectOverCDP` is fine); do not open and close short-lived CDP
clients on that page during the ceremony.

`vault passkey list` shows stored passkeys without key material; entries hold
the `KPEX_PASSKEY_*` KeePassXC fields plus `VAULT_PASSKEY_SIGN_COUNT`. Private
keys are never printed; the key is handed to the browser only for the ceremony.
`vault passkey import` stores a passkey manually from a PKCS#8 PEM on stdin.
`vault passkey create` and `vault passkey sign` (JSON on stdin, no CDP) are what
Herdr's browser autofill uses after Touch ID; agents don't need them, and they
follow the same rule below.
Registering a passkey on a real account changes that account's security
settings; get the owner's explicit OK for each account before registering.
Verified on webauthn.io with CloakBrowser.

## Maintenance

```sh
vault skills status|install|uninstall    # link this skill into each detected agent
```

`vault skills install` symlinks this pack into every agent found on the machine
and never replaces a link or file it did not make.
