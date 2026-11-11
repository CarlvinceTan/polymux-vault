# Vault regressions

Moved from cstack on 2026-11-12.

## vault

### R-vault-2: moved checkout left every agent link dangling
- **symptom / scenario:** `vault skills install` printed pack path
  `/Users/carlvincetan/code/vault/skills/vault` (a directory that no longer
  exists) and left `~/.claude/skills/vault`, `~/.agents/skills/vault` and
  `~/.gemini/skills/vault` broken. Two causes: `env!("CARGO_MANIFEST_DIR")` was
  compiled when the repo lived at `~/code/vault`, and the installer refused to
  replace a link whose target no longer matched the pack.
- **guard:** `repo_root()` resolves at runtime (`VAULT_REPO_ROOT` from
  `bin/vault`, else `current_exe`); the installer relinks a prior pack link
  (`<...>/skills/vault`) instead of leaving it, while still refusing foreign
  files and links.
- **verify:** `cargo test` (6 pass) and `vault skills install` reports `relinked`
  for Claude/Codex/Antigravity; every link resolves to `~/code/proj/polymux-vault`.
- **status:** verified (2026-10-06)

### R-vault-1: never print vault contents
- **symptom / scenario:** `vault status` prints metadata but still queries the
  master password in Keychain; credential-free maintenance needs `vault path`.
- **guard:** `/update` runs `path`/help/`skills status`, builds, and `cargo test`
  only. Never `status`, `list`, `get`, `totp`, or `recovery-codes`. Location
  maintenance must not migrate a database or modify unlock setup.
- **verify:** `cargo test --offline` includes isolated-HOME path CLI tests;
  the vault manifest check invokes `path`, not `status`.
- **status:** verified (2026-10-07, all 17 tests pass in debug and release;
  credential-free manifest check and isolated-HOME launcher smoke test passed)

### R-vault-3: location setup needed instructions, not a new CLI command
- **symptom / scenario:** Database-location work started toward a new CLI command
  despite an existing JSON path override; the user requested skill-only setup.
  Plain `vault` was also absent from this session's PATH.
- **guard:** Honor skill-only scope when requested; a CLI command is optional,
  not a prerequisite for changing paths. The subsequently authorized `path`
  command only inspects/updates local location config, preserves unknown keys,
  and never accesses credentials or migrates a database. The skill documents
  config-before-environment precedence, absolute paths and iCloud sync limits.
- **verify:** `cargo test --offline` covers resolution, config safety and isolated
  CLI inspect/set behavior; `bin/vault path --help` and `bin/vault skills status`
  verify the launcher and active skill links.
- **status:** verified (2026-10-07, 17 tests plus release-launcher inspect/set,
  help/version and four active skill links passed; real database/config unchanged,
  database migration and cross-device sync not run)

---

