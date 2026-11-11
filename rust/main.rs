use anyhow::{Context, Result, bail};
use argon2::Version;
use clap::{Args, Parser, Subcommand, ValueEnum};
use data_encoding::BASE32_NOPAD;
use keepass::{
    Database, DatabaseKey,
    config::{DatabaseVersion, KdfConfig},
    db::{Entry, EntryId, EntryRef, GroupRef, fields},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use totp_rs::{Builder, Totp};

mod authenticator;
mod cdp;
mod passkey;

const KEYCHAIN_SERVICE: &str = "OpenCode Vault";

#[derive(Parser)]
#[command(name = "vault", about = "Stateless KeePass vault CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: VaultCommand,
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Inspect or set the database location without opening the vault or Keychain.
    Path(PathArgs),
    Status,
    List,
    Get(GetArgs),
    Totp {
        title: String,
    },
    RecoveryCodes {
        title: String,
    },
    Put(PutArgs),
    /// Every field of an entry's own, protected ones included (an address, a card).
    Fields {
        title: String,
    },
    Delete {
        title: String,
    },
    Create(PasswordArgs),
    ChangePassword(ChangePasswordArgs),
    Destroy {
        #[arg(long)]
        confirm: String,
    },
    /// Run a command with this entry's fields in the environment.
    Run(RunArgs),
    /// Store and use WebAuthn passkeys through a browser CDP endpoint.
    Passkey(passkey::PasskeyArgs),
    Skills {
        #[arg(default_value = "status")]
        action: SkillAction,
    },
}

#[derive(Args)]
struct PathArgs {
    /// Save an absolute database path; does not move the database or unlock setup.
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    set: Option<PathBuf>,
}

#[derive(Args)]
struct RunArgs {
    /// Entry whose fields become environment variables.
    entry: String,
    /// Command to run, after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Clone, ValueEnum)]
enum SecretField {
    Password,
    Username,
    Recovery,
    Notes,
    Url,
    TotpSeed,
}

#[derive(Args)]
struct GetArgs {
    title: String,
    #[arg(long, value_enum, default_value = "password")]
    field: SecretField,
}

#[derive(Args)]
struct PasswordArgs {
    #[arg(long, conflicts_with = "password_stdin")]
    password: Option<String>,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Args)]
struct ChangePasswordArgs {
    #[arg(long)]
    current: Option<String>,
    #[arg(long, conflicts_with = "next_stdin")]
    next: Option<String>,
    #[arg(long)]
    next_stdin: bool,
}

#[derive(Args)]
struct PutArgs {
    title: String,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    notes: Option<String>,
    #[arg(long, conflicts_with = "password_stdin")]
    password: Option<String>,
    #[arg(long)]
    password_stdin: bool,
    #[arg(long)]
    totp_seed: Option<String>,
    #[arg(long = "recovery-code")]
    recovery_codes: Vec<String>,
    /// A field of the entry's own, NAME=VALUE (an address's street, a card's expiry). An empty
    /// value removes it.
    #[arg(long = "field", value_name = "NAME=VALUE")]
    fields: Vec<String>,
    /// As --field, but stored protected like a password (a card's number or security code).
    #[arg(long = "secret-field", value_name = "NAME=VALUE")]
    secret_fields: Vec<String>,
}

#[derive(Clone, ValueEnum)]
enum SkillAction {
    Status,
    Install,
    Update,
    Uninstall,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntrySummary {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    group: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    has_password: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    has_totp: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    has_recovery_codes: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    has_passkey: bool,
    /// The entry's own unprotected fields, with their values.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    fields: BTreeMap<String, String>,
    /// The names of its own protected fields; their values only come from `fields`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    secret_fields: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("vault: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        VaultCommand::Skills { action } => return skills(action),
        VaultCommand::Path(args) => {
            let location = configured_location();
            let mut report = serde_json::to_value(&location)?;
            if let Some(path) = args.set {
                set_configured_path(&location.config_file, &path)?;
                report = serde_json::to_value(configured_location())?;
                report["previousPath"] = json!(location.path);
                report["updated"] = json!(true);
                report["databaseMoved"] = json!(false);
                report["unlockSetupChanged"] = json!(false);
            }
            output(report);
            return Ok(());
        }
        VaultCommand::Passkey(args) => {
            let path = configured_path();
            let password = resolve_password(&path)
                .with_context(|| format!("no master password stored for {}", path.display()))?;
            return passkey::run(args, &path, &password);
        }
        _ => {}
    }
    let path = configured_path();
    match cli.command {
        VaultCommand::Status => output(json!({
            "path": path,
            "exists": path.is_file(),
            "passwordAvailable": resolve_password(&path).is_some(),
            "stateless": true
        })),
        VaultCommand::Create(args) => {
            if path.exists() {
                bail!("{} already exists; refusing to overwrite", path.display());
            }
            let password = password_arg(args.password, args.password_stdin)?;
            let mut db = Database::new();
            db.root_mut().name = "Vault".into();
            db.config.kdf_config = KdfConfig::Argon2 {
                iterations: 3,
                memory: 64 * 1024 * 1024,
                parallelism: 2,
                version: Version::Version13,
            };
            save_database(&db, &path, &password)?;
            store_password(&path, &password)?;
            output(json!({"path": path, "entries": 0}));
        }
        VaultCommand::Destroy { confirm } => {
            if confirm != path.to_string_lossy() {
                bail!(
                    "--confirm must repeat the vault path exactly ({})",
                    path.display()
                );
            }
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
            output(json!({"path": path, "destroyed": true}));
        }
        other => {
            let password = resolve_password(&path)
                .with_context(|| format!("no master password stored for {}", path.display()))?;
            let mut db = open_database(&path, &password)?;
            match other {
                VaultCommand::List => {
                    let mut entries = summaries(&db);
                    entries.sort_by_key(|entry| entry.title.to_lowercase());
                    output(json!({"entries": entries}));
                }
                VaultCommand::Get(args) => output(get_value(&db, &args.title, args.field)?),
                VaultCommand::Totp { title } => output(totp_value(&db, &title)?),
                VaultCommand::RecoveryCodes { title } => {
                    let entry = locate(&db, &title)?;
                    output(json!({"title": title_of(&entry), "codes": recovery_codes(&entry)?}));
                }
                VaultCommand::Fields { title } => {
                    let entry = locate(&db, &title)?;
                    let own: BTreeMap<String, String> = entry
                        .fields
                        .iter()
                        .filter(|(name, _)| is_own_field(name))
                        .map(|(name, value)| (name.clone(), value.get().clone()))
                        .collect();
                    output(json!({"title": title_of(&entry), "fields": own}));
                }
                VaultCommand::Put(args) => {
                    put(&mut db, args)?;
                    save_database(&db, &path, &password)?;
                }
                VaultCommand::Delete { title } => {
                    let id = locate(&db, &title)?.id();
                    db.entry_mut(id).context("entry disappeared")?.remove();
                    save_database(&db, &path, &password)?;
                    output(json!({"title": title, "removed": true}));
                }
                VaultCommand::Run(args) => {
                    let entry = locate(&db, &args.entry)?;
                    let status = entry_command(&entry, &args.command)?;
                    std::process::exit(status);
                }
                VaultCommand::ChangePassword(args) => {
                    let current = args.current.unwrap_or(password);
                    // Re-open with the supplied current value so a wrong override cannot rewrite anything.
                    db = open_database(&path, &current)?;
                    let next = password_arg(args.next, args.next_stdin)?;
                    save_database(&db, &path, &next)?;
                    store_password(&path, &next)?;
                    output(json!({"path": path, "reencrypted": true}));
                }
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PathLocation {
    path: PathBuf,
    source: &'static str,
    config_file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<&'static str>,
}

fn configured_location() -> PathLocation {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    resolve_location(&home, env::var_os("VAULT_FILE").map(PathBuf::from))
}

fn configured_path() -> PathBuf {
    configured_location().path
}

fn resolve_location(home: &Path, environment_path: Option<PathBuf>) -> PathLocation {
    let config_file = home.join(".config/opencode/vault.json");
    let mut warning = None;
    match fs::read(&config_file) {
        Ok(raw) => match serde_json::from_slice::<Value>(&raw) {
            Ok(value) if value.is_object() => {
                if let Some(path) = value
                    .get("path")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                {
                    return PathLocation {
                        path: PathBuf::from(path.trim()),
                        source: "config",
                        config_file,
                        warning: None,
                    };
                }
            }
            _ => warning = Some("Invalid vault configuration; using the fallback location."),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => warning = Some("Cannot read vault configuration; using the fallback location."),
    }
    let (path, source) = match environment_path {
        Some(path) => (path, "env"),
        None => (
            home.join("Library/Application Support/vault/vault.kdbx"),
            "default",
        ),
    };
    PathLocation {
        path,
        source,
        config_file,
        warning,
    }
}

/// Refuse symlinks and nonregular files rather than replacing another owner's config.
fn editable_config_contents(config_file: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(config_file) {
        Ok(metadata) if metadata.is_file() => Ok(Some(
            fs::read(config_file).context("read vault configuration")?,
        )),
        Ok(_) => bail!("vault configuration is not a regular file; refusing to replace it"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("inspect vault configuration"),
    }
}

fn set_configured_path(config_file: &Path, path: &Path) -> Result<()> {
    let text = path.to_str().context("database path must be valid UTF-8")?;
    if !path.is_absolute()
        || path.file_name().is_none()
        || text != text.trim()
        || text.contains('\0')
    {
        bail!(
            "database path must be an absolute file path without leading/trailing whitespace or NUL bytes"
        );
    }
    if !config_file.is_absolute() {
        bail!("HOME must be an absolute path to set the database location");
    }
    let original = editable_config_contents(config_file)?;
    let mut config = match &original {
        Some(raw) => serde_json::from_slice::<Value>(raw)
            .context("vault configuration is invalid JSON; refusing to overwrite it")?,
        None => json!({}),
    };
    config
        .as_object_mut()
        .context("vault configuration must be a JSON object; refusing to overwrite it")?
        .insert("path".into(), json!(text));

    let parent = config_file
        .parent()
        .context("configuration path has no parent")?;
    fs::create_dir_all(parent).context("create configuration directory")?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(&mut temporary, &config)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    if editable_config_contents(config_file)? != original {
        bail!("vault configuration changed during the update; refusing to overwrite it");
    }
    if original.is_some() {
        temporary
            .persist(config_file)
            .context("save vault configuration")?;
    } else {
        temporary
            .persist_noclobber(config_file)
            .context("create vault configuration")?;
    }
    Ok(())
}

fn security(args: &[&str]) -> Result<String> {
    let result = Command::new("/usr/bin/security")
        .args(args)
        .output()
        .context("run macOS security")?;
    if !result.status.success() {
        bail!("macOS Keychain operation failed");
    }
    Ok(String::from_utf8(result.stdout)?
        .trim_end_matches(['\r', '\n'])
        .to_owned())
}

fn resolve_password(path: &Path) -> Option<String> {
    if let Ok(value) = env::var("VAULT_PASSWORD") {
        if !value.is_empty() {
            return Some(value);
        }
    }
    security(&[
        "find-generic-password",
        "-s",
        KEYCHAIN_SERVICE,
        "-a",
        &path.to_string_lossy(),
        "-w",
    ])
    .ok()
    .filter(|s| !s.is_empty())
}

fn store_password(path: &Path, password: &str) -> Result<()> {
    security(&[
        "add-generic-password",
        "-U",
        "-s",
        KEYCHAIN_SERVICE,
        "-a",
        &path.to_string_lossy(),
        "-w",
        password,
    ])
    .map(|_| ())
}

fn password_arg(value: Option<String>, from_stdin: bool) -> Result<String> {
    let password = if from_stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        input.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        value.context("provide --password/--next or the matching --*-stdin flag")?
    };
    if password.is_empty() {
        bail!("password cannot be empty");
    }
    Ok(password)
}

pub(crate) fn open_database(path: &Path, password: &str) -> Result<Database> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut db = Database::open(&mut file, DatabaseKey::new().with_password(password))
        .context("open KDBX database")?;
    // keepass only writes KDBX 4.1; 4.1 is a compatible superset of 4.0, so
    // upgrade 4.0 databases on open or every later save fails.
    if matches!(db.config.version, DatabaseVersion::KDB4(0)) {
        db.config.version = DatabaseVersion::KDB4(1);
    }
    Ok(db)
}

pub(crate) fn save_database(db: &Database, path: &Path, password: &str) -> Result<()> {
    let parent = path.parent().context("vault path has no parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    db.save(
        temporary.as_file_mut(),
        DatabaseKey::new().with_password(password),
    )
    .context("serialize KDBX database")?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

fn locate<'a>(db: &'a Database, title: &str) -> Result<EntryRef<'a>> {
    let wanted = title.trim();
    db.iter_all_entries()
        .find(|entry| {
            entry
                .get_title()
                .is_some_and(|name| name.eq_ignore_ascii_case(wanted))
        })
        .with_context(|| format!("no entry named \"{title}\""))
}

fn title_of(entry: &EntryRef<'_>) -> String {
    entry.get_title().unwrap_or_default().to_owned()
}

/// The group names from the root down to `group`, so a nested entry reports
/// "Vault/Work" the way the TypeScript core did.
fn group_names(group: GroupRef<'_>) -> Vec<String> {
    let mut names = group.parent().map(group_names).unwrap_or_default();
    names.push(group.name.clone());
    names
}

fn summaries(db: &Database) -> Vec<EntrySummary> {
    db.iter_all_entries()
        .map(|entry| {
            let names = group_names(entry.parent());
            EntrySummary {
                title: title_of(&entry),
                username: nonempty(entry.get_username()),
                url: nonempty(entry.get_url()),
                notes: nonempty(entry.get(fields::NOTES)),
                group: names.join("/"),
                has_password: entry.get_password().is_some_and(|v| !v.is_empty()),
                has_totp: entry.get("otp").is_some_and(|v| !v.is_empty())
                    || entry.get("otpauth").is_some_and(|v| !v.is_empty()),
                has_recovery_codes: entry.get("recovery.codes").is_some_and(|v| !v.is_empty()),
                has_passkey: passkey::is_passkey_entry(&entry),
                fields: plain_fields(&entry),
                secret_fields: secret_field_names(&entry),
            }
        })
        .collect()
}

/// Fields the vault manages itself; everything else on an entry is the person's own.
fn is_own_field(name: &str) -> bool {
    !matches!(
        name,
        fields::TITLE | fields::USERNAME | fields::PASSWORD | fields::URL | fields::NOTES | "otp" | "otpauth" | "recovery.codes"
    ) && !name.starts_with("KPEX_")
        && !name.starts_with("VAULT_")
}

fn plain_fields(entry: &Entry) -> BTreeMap<String, String> {
    entry
        .fields
        .iter()
        .filter(|(name, value)| is_own_field(name) && !value.is_protected())
        .map(|(name, value)| (name.clone(), value.get().clone()))
        .collect()
}

fn secret_field_names(entry: &Entry) -> Vec<String> {
    let mut names: Vec<String> = entry
        .fields
        .iter()
        .filter(|(name, value)| is_own_field(name) && value.is_protected())
        .map(|(name, _)| name.clone())
        .collect();
    names.sort();
    names
}

/// "NAME=VALUE" from --field, checked before anything changes. The value never goes into an error.
fn own_field(pair: &str) -> Result<(&str, &str)> {
    let (name, value) = pair.split_once('=').context("a field is written NAME=VALUE")?;
    let name = name.trim();
    if name.is_empty() || !is_own_field(name) {
        bail!("{name:?} isn't a name an entry's own field can have");
    }
    Ok((name, value))
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.is_empty()).map(str::to_owned)
}

fn recovery_codes(entry: &EntryRef<'_>) -> Result<Vec<String>> {
    let raw = entry
        .get("recovery.codes")
        .filter(|s| !s.trim().is_empty())
        .context("entry has no recovery codes stored")?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect())
}

fn get_value(db: &Database, title: &str, field: SecretField) -> Result<Value> {
    let entry = locate(db, title)?;
    let title = title_of(&entry);
    Ok(match field {
        SecretField::Password => {
            json!({"title": title, "username": entry.get_username(), "password": entry.get_password().filter(|s| !s.is_empty()).context("entry has no password stored")?})
        }
        SecretField::Username => {
            json!({"title": title, "username": entry.get_username().context("entry has no username stored")?})
        }
        SecretField::Recovery => json!({"title": title, "codes": recovery_codes(&entry)?}),
        SecretField::Notes => {
            json!({"title": title, "notes": entry.get(fields::NOTES).context("entry has no notes stored")?})
        }
        SecretField::Url => {
            json!({"title": title, "url": entry.get_url().context("entry has no URL stored")?})
        }
        SecretField::TotpSeed => {
            json!({"title": title, "totpSeed": entry.get("otpauth").or_else(|| entry.get("otp")).context("entry has no TOTP seed stored")?})
        }
    })
}

fn totp_value(db: &Database, title: &str) -> Result<Value> {
    let entry = locate(db, title)?;
    let raw = entry
        .get("otpauth")
        .or_else(|| entry.get("otp"))
        .context("entry has no TOTP seed stored")?;
    let totp = build_totp(raw)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(
        json!({"title": title_of(&entry), "code": totp.generate(now).to_string(), "secondsUntilExpiry": totp.ttl()}),
    )
}

/// A stored seed is either a full `otpauth://` URL or a bare Base32 secret that
/// gets the conventional SHA-1 / 6-digit / 30-second defaults.
fn build_totp(raw: &str) -> Result<Totp> {
    if raw.to_ascii_lowercase().starts_with("otpauth://") {
        // Unchecked keeps the previous leniency: short seeds that exist in the
        // wild are accepted, and the URL's own algorithm/digits/period win.
        return Totp::from_url_unchecked(raw).context("parse otpauth URL");
    }
    let normalized: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .flat_map(char::to_uppercase)
        .collect();
    let secret = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .context("decode base32 TOTP seed")?;
    Ok(Builder::new().with_secret(secret).build_noncompliant())
}

/// Runs a child with the entry's fields exported as `VAULT_*` variables, so a
/// credential can reach a program without being printed. The child inherits
/// stdio and its exit code becomes ours.
fn entry_command(entry: &EntryRef<'_>, command: &[String]) -> Result<i32> {
    let (program, arguments) = command.split_first().context("no command given after --")?;
    let mut child = Command::new(program);
    child.args(arguments);
    for (key, value) in entry_env(entry)? {
        child.env(key, value);
    }
    let status = child.status().with_context(|| format!("run {program}"))?;
    Ok(status.code().unwrap_or(1))
}

fn entry_env(entry: &EntryRef<'_>) -> Result<Vec<(&'static str, String)>> {
    let mut values = Vec::new();
    let mut add = |key: &'static str, value: Option<&str>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            values.push((key, value.to_owned()));
        }
    };
    add("VAULT_TITLE", entry.get_title());
    add("VAULT_USERNAME", entry.get_username());
    add("VAULT_PASSWORD", entry.get_password());
    add("VAULT_URL", entry.get_url());
    add("VAULT_NOTES", entry.get(fields::NOTES));
    add(
        "VAULT_TOTP_SEED",
        entry.get("otpauth").or_else(|| entry.get("otp")),
    );
    if let Some(raw) = entry.get("otpauth").or_else(|| entry.get("otp")) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        values.push(("VAULT_TOTP", build_totp(raw)?.generate(now).to_string()));
    }
    if let Ok(codes) = recovery_codes(entry) {
        values.push(("VAULT_RECOVERY_CODES", codes.join("\n")));
    }
    Ok(values)
}

fn put(db: &mut Database, args: PutArgs) -> Result<()> {
    let title = args.title.trim().to_owned();
    if title.is_empty() {
        bail!("an entry needs a title");
    }
    let own: Vec<(&str, &str, bool)> = args.fields.iter().map(|pair| (pair, false))
        .chain(args.secret_fields.iter().map(|pair| (pair, true)))
        .map(|(pair, protect)| own_field(pair).map(|(name, value)| (name, value, protect)))
        .collect::<Result<_>>()?;
    let password = if args.password_stdin {
        Some(password_arg(None, true)?)
    } else {
        args.password
    };
    let id: Option<EntryId> = db
        .iter_all_entries()
        .find(|entry| {
            entry
                .get_title()
                .is_some_and(|v| v.eq_ignore_ascii_case(&title))
        })
        .map(|entry| entry.id());
    // The `None` arm cannot borrow from `db.root_mut()` while the `Some` arm
    // borrows `db`, so a missing entry is created first and both paths then go
    // through `db.entry_mut`.
    let id = match id {
        Some(id) => id,
        None => {
            let mut root = db.root_mut();
            root.add_entry().id()
        }
    };
    let mut entry = db.entry_mut(id).context("entry disappeared")?;
    entry.set_unprotected(fields::TITLE, &title);
    if let Some(value) = args.username.filter(|v| !v.trim().is_empty()) {
        entry.set_unprotected(fields::USERNAME, value.trim());
    }
    if let Some(value) = args.url.filter(|v| !v.trim().is_empty()) {
        entry.set_unprotected(fields::URL, value.trim());
    }
    if let Some(value) = args.notes.filter(|v| !v.trim().is_empty()) {
        entry.set_unprotected(fields::NOTES, value.trim());
    }
    if let Some(value) = password {
        entry.set_protected(fields::PASSWORD, value);
    }
    if let Some(seed) = args.totp_seed.filter(|v| !v.trim().is_empty()) {
        if seed.to_ascii_lowercase().starts_with("otpauth://") {
            entry.set_protected("otpauth", seed.trim());
            entry.fields.remove("otp");
        } else {
            entry.set_protected("otp", seed.trim().to_uppercase());
            entry.fields.remove("otpauth");
        }
    }
    if !args.recovery_codes.is_empty() {
        entry.set_protected("recovery.codes", args.recovery_codes.join("\n"));
    }
    for (name, value, protect) in own {
        match (value.is_empty(), protect) {
            (true, _) => {
                entry.fields.remove(name);
            }
            (false, true) => entry.set_protected(name, value),
            (false, false) => entry.set_unprotected(name, value),
        }
    }
    let summary = EntrySummary {
        title: title.clone(),
        username: nonempty(entry.get_username()),
        url: nonempty(entry.get_url()),
        notes: nonempty(entry.get(fields::NOTES)),
        group: entry.parent_mut().name.clone(),
        has_password: entry.get_password().is_some_and(|v| !v.is_empty()),
        has_totp: entry.get("otp").is_some_and(|v| !v.is_empty())
            || entry.get("otpauth").is_some_and(|v| !v.is_empty()),
        has_recovery_codes: entry.get("recovery.codes").is_some_and(|v| !v.is_empty()),
        has_passkey: passkey::is_passkey_entry(&entry),
        fields: plain_fields(&entry),
        secret_fields: secret_field_names(&entry),
    };
    output(serde_json::to_value(summary)?);
    Ok(())
}

pub(crate) fn output(value: Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("JSON serialization")
    );
}

/// Resolve the repo root at runtime. `CARGO_MANIFEST_DIR` is baked in at
/// compile time, so it goes stale when the checkout is moved; prefer the env
/// var set by bin/vault, then the running executable's own location.
fn repo_root() -> PathBuf {
    if let Some(root) = env::var_os("VAULT_REPO_ROOT") {
        return PathBuf::from(root);
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(root) = exe.parent().and_then(Path::parent).and_then(Path::parent) {
            if root.join("Cargo.toml").exists() && root.join("skills/vault").is_dir() {
                return root.to_path_buf();
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// True when `link` is a symlink this tool made in a previous run, judged by
/// the pack's own `<...>/skills/vault` shape. A moved checkout leaves these
/// dangling; they are ours to repair, unlike a foreign link or real file.
fn is_prior_pack_link(link: &Path) -> bool {
    fs::read_link(link).ok().is_some_and(|target| {
        target.file_name().and_then(|n| n.to_str()) == Some("vault")
            && target
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                == Some("skills")
    })
}

fn skills(action: SkillAction) -> Result<()> {
    let root = repo_root();
    let pack = root.join("skills/vault");
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")?;
    let agents = [
        ("Claude Code", home.join(".claude/skills")),
        ("Codex", home.join(".agents/skills")),
        ("Prime Agent", home.join(".prime/agent/skills")),
        ("OpenClaw", home.join(".openclaw/skills")),
        ("OpenCode", home.join(".config/opencode/skills")),
        ("Antigravity", home.join(".gemini/skills")),
        ("Hermes", home.join(".hermes/skills")),
    ];
    println!("Local skill pack: {}", pack.display());
    let uninstall = matches!(action, SkillAction::Uninstall);
    let mutate = !matches!(action, SkillAction::Status);
    let mut failed = false;
    for (agent, dir) in agents {
        let link = dir.join("vault");
        if !dir.parent().is_some_and(Path::exists) {
            println!("  {agent} — agent dir not present: {}", dir.display());
            continue;
        }
        let state = fs::symlink_metadata(&link).ok();
        let correct = state.as_ref().is_some_and(|m| m.file_type().is_symlink())
            && fs::read_link(&link)
                .ok()
                .and_then(|p| fs::canonicalize(link.parent().unwrap().join(p)).ok())
                == fs::canonicalize(&pack).ok();
        if !mutate {
            let detail = if correct {
                format!("{} → {}", link.display(), pack.display())
            } else if state.is_some() {
                link.display().to_string()
            } else {
                link.display().to_string()
            };
            println!(
                "  {agent} — {}: {detail}",
                if correct {
                    "linked"
                } else if state.is_some() {
                    "occupied/foreign"
                } else {
                    "not linked"
                }
            );
            continue;
        }
        if uninstall {
            if correct || is_prior_pack_link(&link) {
                fs::remove_file(&link)?;
                println!("  {agent} — unlinked: {}", link.display());
            } else if state.is_none() {
                println!("  {agent} — nothing to remove: {}", link.display());
            } else {
                eprintln!("  {agent} — left alone: {}", link.display());
                failed = true;
            }
        } else if correct {
            println!("  {agent} — already linked: {}", link.display());
        } else if state.is_some() && is_prior_pack_link(&link) {
            fs::remove_file(&link)?;
            std::os::unix::fs::symlink(&pack, &link)?;
            println!("  {agent} — relinked: {}", link.display());
        } else if state.is_some() {
            eprintln!("  {agent} — left alone: {}", link.display());
            failed = true;
        } else {
            fs::create_dir_all(&dir)?;
            std::os::unix::fs::symlink(&pack, &link)?;
            println!("  {agent} — linked: {}", link.display());
        }
    }
    if failed {
        bail!("one or more skill links were left alone");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_location_preserves_config_env_default_precedence() {
        let home = tempfile::tempdir().unwrap();
        let config_file = home.path().join(".config/opencode/vault.json");
        let environment_path = home.path().join("environment.kdbx");
        let default = resolve_location(home.path(), None);
        assert_eq!(default.source, "default");
        assert_eq!(
            default.path,
            home.path()
                .join("Library/Application Support/vault/vault.kdbx")
        );
        assert!(!config_file.exists());
        let environment = resolve_location(home.path(), Some(environment_path.clone()));
        assert_eq!(environment.source, "env");
        assert_eq!(environment.path, environment_path);
        fs::create_dir_all(config_file.parent().unwrap()).unwrap();
        fs::write(&config_file, br#"{"path":"  /configured/vault.kdbx  "}"#).unwrap();
        let configured = resolve_location(home.path(), Some(environment_path));
        assert_eq!(configured.source, "config");
        assert_eq!(configured.path, Path::new("/configured/vault.kdbx"));
        assert_eq!(configured.config_file, config_file);
        assert!(configured.warning.is_none());
    }

    #[test]
    fn invalid_configuration_reports_fallback_without_rewriting() {
        let home = tempfile::tempdir().unwrap();
        let config_file = home.path().join(".config/opencode/vault.json");
        fs::create_dir_all(config_file.parent().unwrap()).unwrap();
        for raw in ["{broken", "[]", "null"] {
            fs::write(&config_file, raw).unwrap();
            let location = resolve_location(home.path(), Some(PathBuf::from("/environment.kdbx")));
            assert_eq!(location.source, "env");
            assert!(location.warning.is_some());
            assert_eq!(fs::read_to_string(&config_file).unwrap(), raw);
        }
    }

    #[test]
    fn missing_or_blank_config_path_retains_environment_fallback() {
        let home = tempfile::tempdir().unwrap();
        let config_file = home.path().join(".config/opencode/vault.json");
        fs::create_dir_all(config_file.parent().unwrap()).unwrap();
        for raw in [r#"{}"#, r#"{"path":"  "}"#, r#"{"path":42}"#] {
            fs::write(&config_file, raw).unwrap();
            assert_eq!(
                resolve_location(home.path(), Some(PathBuf::from("/env.kdbx"))).source,
                "env"
            );
        }
    }

    #[test]
    fn setting_location_creates_only_private_config_not_database() {
        let home = tempfile::tempdir().unwrap();
        let config_file = home.path().join(".config/opencode/vault.json");
        let database_path = home.path().join("iCloud Drive/Vault/vault.kdbx");
        set_configured_path(&config_file, &database_path).unwrap();
        let location = resolve_location(home.path(), None);
        assert_eq!(location.source, "config");
        assert_eq!(location.path, database_path);
        assert_eq!(
            fs::metadata(&config_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!database_path.parent().unwrap().exists());
    }

    #[test]
    fn setting_location_preserves_unknown_fields_and_parent_permissions() {
        let home = tempfile::tempdir().unwrap();
        let config_file = home.path().join("vault.json");
        let original = json!({"path":"/old.kdbx", "extension":{"enabled":true}, "label":"work"});
        fs::write(&config_file, serde_json::to_vec(&original).unwrap()).unwrap();
        let permissions = fs::metadata(home.path()).unwrap().permissions().mode();
        set_configured_path(&config_file, Path::new("/new.kdbx")).unwrap();
        let config: Value = serde_json::from_slice(&fs::read(&config_file).unwrap()).unwrap();
        assert_eq!(config["path"], "/new.kdbx");
        assert_eq!(config["extension"], original["extension"]);
        assert_eq!(config["label"], original["label"]);
        assert_eq!(
            fs::metadata(home.path()).unwrap().permissions().mode(),
            permissions
        );
    }

    #[test]
    fn setting_location_rejects_invalid_paths_without_writes() {
        let home = tempfile::tempdir().unwrap();
        let config_file = home.path().join("new/vault.json");
        for path in [
            "",
            "relative.kdbx",
            "~/vault.kdbx",
            "$HOME/vault.kdbx",
            "/",
            " /vault.kdbx",
            "/vault.kdbx ",
            "/vault\0.kdbx",
        ] {
            assert!(
                set_configured_path(&config_file, Path::new(path)).is_err(),
                "{path:?}"
            );
        }
        assert!(!config_file.parent().unwrap().exists());
        assert!(
            set_configured_path(Path::new("relative/config.json"), Path::new("/vault.kdbx"))
                .is_err()
        );
    }

    #[test]
    fn setting_location_refuses_malformed_or_nonobject_config() {
        let home = tempfile::tempdir().unwrap();
        let config_file = home.path().join("vault.json");
        for raw in ["{broken", "[]", "null", "42"] {
            fs::write(&config_file, raw).unwrap();
            assert!(set_configured_path(&config_file, Path::new("/vault.kdbx")).is_err());
            assert_eq!(fs::read_to_string(&config_file).unwrap(), raw);
        }
    }

    #[test]
    fn setting_location_refuses_symlinks_and_directories() {
        let home = tempfile::tempdir().unwrap();
        let target = home.path().join("target.json");
        fs::write(&target, "{}").unwrap();
        for (name, destination) in [
            ("live", target.clone()),
            ("dangling", home.path().join("missing")),
        ] {
            let link = home.path().join(name);
            std::os::unix::fs::symlink(&destination, &link).unwrap();
            assert!(set_configured_path(&link, Path::new("/vault.kdbx")).is_err());
            assert_eq!(fs::read_link(&link).unwrap(), destination);
        }
        assert_eq!(fs::read_to_string(&target).unwrap(), "{}");
        assert!(set_configured_path(home.path(), Path::new("/vault.kdbx")).is_err());
        assert!(home.path().is_dir());
    }

    #[test]
    fn prior_pack_links_are_recognized_but_foreign_ones_are_not() {
        let dir = std::env::temp_dir().join(format!("vault-prior-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let prior = dir.join("vault");
        std::os::unix::fs::symlink("/moved/away/skills/vault", &prior).unwrap();
        assert!(is_prior_pack_link(&prior));
        let foreign = dir.join("foreign");
        std::os::unix::fs::symlink("/etc", &foreign).unwrap();
        assert!(!is_prior_pack_link(&foreign));
        let _ = fs::remove_dir_all(&dir);
    }

    // The same vector the keepass crate asserts for a stored otpauth URL.
    #[test]
    fn otpauth_url_matches_known_vector() {
        let totp =
            build_totp("otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6")
                .expect("parse url");
        assert_eq!(totp.generate(1234).to_string(), "806863");
    }

    // RFC 6238 SHA-1 secret "12345678901234567890", truncated to the six digits
    // the CLI uses by default.
    #[test]
    fn bare_seed_matches_rfc6238_vector() {
        let totp = build_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("parse seed");
        assert_eq!(totp.generate(59).to_string(), "287082");
    }

    #[test]
    fn bare_seed_ignores_spaces_and_padding() {
        let totp = build_totp("gezd gnbv gy3t qojq gezd gnbv gy3t qojq====").expect("parse seed");
        assert_eq!(totp.generate(59).to_string(), "287082");
    }

    #[test]
    fn missing_entry_is_an_error() {
        let db = Database::new();
        assert!(locate(&db, "nope").is_err());
    }

    #[test]
    fn summaries_report_group_and_flags_but_no_secrets() {
        let mut db = Database::new();
        db.root_mut().name = "Vault".into();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Example");
            entry.set_protected(fields::PASSWORD, "hunter2");
            entry.set_protected("otp", "JBSWY3DPEHPK3PXP");
        }
        let summaries = summaries(&db);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].title, "Example");
        assert_eq!(summaries[0].group, "Vault");
        assert!(summaries[0].has_password);
        assert!(summaries[0].has_totp);
        assert!(!summaries[0].has_recovery_codes);
        let json = serde_json::to_string(&summaries[0]).expect("serialize");
        assert!(!json.contains("hunter2"));
    }
}
