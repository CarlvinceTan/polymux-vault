//! `vault passkey`: capture, reuse, make, sign with and manually import
//! WebAuthn passkeys.
//!
//! Stored keys use KeePassXC's `KPEX_PASSKEY_*` custom entry fields so the
//! database stays interoperable, plus `VAULT_PASSKEY_SIGN_COUNT` for the sign
//! counter and `VAULT_PASSKEY_BACKED_UP` for passkeys the vault made itself.
//! Private key material is stored protected and never printed.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use keepass::{
    Database,
    db::{Entry, fields},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use crate::{
    authenticator,
    cdp::{self, ConnectOptions},
    open_database, output, save_database,
};

pub const CREDENTIAL_ID_FIELD: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub const PRIVATE_KEY_FIELD: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const RELYING_PARTY_FIELD: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub const USERNAME_FIELD: &str = "KPEX_PASSKEY_USERNAME";
pub const USER_HANDLE_FIELD: &str = "KPEX_PASSKEY_USER_HANDLE";
pub const SIGN_COUNT_FIELD: &str = "VAULT_PASSKEY_SIGN_COUNT";
/// "1" on passkeys `create` made: they travel with the database, so their
/// authenticator data says backed up, as it did when the site registered them.
pub const BACKED_UP_FIELD: &str = "VAULT_PASSKEY_BACKED_UP";

const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Args)]
pub struct PasskeyArgs {
    #[command(subcommand)]
    pub command: PasskeyCommand,
    /// Chrome DevTools Protocol HTTP endpoint.
    #[arg(
        long,
        global = true,
        env = "VAULT_CDP",
        value_name = "URL",
        default_value = "http://127.0.0.1:9333"
    )]
    pub cdp: String,
    /// Page whose url contains this substring (first match).
    #[arg(long, global = true, value_name = "SUBSTRING", conflicts_with = "target_id")]
    pub target: Option<String>,
    /// Page target id from `GET <cdp>/json/list`.
    #[arg(long = "target-id", global = true, value_name = "ID")]
    pub target_id: Option<String>,
    /// Seconds to wait for the passkey ceremony.
    #[arg(long, global = true, value_name = "SECS", default_value_t = 120)]
    pub timeout: u64,
}

#[derive(Subcommand)]
pub enum PasskeyCommand {
    /// List stored passkeys (titles and ids, never key material).
    List(ListArgs),
    /// Capture a passkey the site registers in the browser into the vault.
    Register(RegisterArgs),
    /// Serve stored passkeys to the browser so a sign-in completes.
    Use(UseArgs),
    /// Import a passkey manually from a PKCS#8 PEM on stdin.
    Import(ImportArgs),
    /// Make a new passkey for a site and store it; a JSON request on stdin
    /// (rpId, userName, userHandle, excludeCredentials, title). No CDP.
    Create,
    /// Sign a site's sign-in with a stored passkey; a JSON request on stdin
    /// (rpId, clientDataHash, credentialId or allowCredentials). No CDP.
    Sign,
}

#[derive(Args)]
pub struct ListArgs {
    /// Only passkeys for this relying party id.
    #[arg(long, value_name = "RPID")]
    pub rp: Option<String>,
}

#[derive(Args)]
pub struct RegisterArgs {
    /// Relying party id, for example webauthn.io.
    #[arg(long, value_name = "RPID")]
    pub rp: String,
    /// Entry title; defaults to "<rpId> passkey (<username>)".
    #[arg(long)]
    pub title: Option<String>,
}

#[derive(Args)]
pub struct UseArgs {
    /// Relying party id, for example webauthn.io.
    #[arg(long, value_name = "RPID")]
    pub rp: String,
    /// Restrict to the passkey stored under this entry title.
    #[arg(long)]
    pub title: Option<String>,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Relying party id, for example webauthn.io.
    #[arg(long, value_name = "RPID")]
    pub rp: String,
    /// Credential id, base64url without padding.
    #[arg(long = "credential-id", value_name = "B64URL", allow_hyphen_values = true)]
    pub credential_id: String,
    /// User handle, base64url without padding.
    #[arg(long = "user-handle", value_name = "B64URL", allow_hyphen_values = true)]
    pub user_handle: String,
    /// Passkey username.
    #[arg(long, value_name = "USERNAME")]
    pub username: String,
    /// Entry title.
    #[arg(long)]
    pub title: String,
    /// Read the PKCS#8 PEM private key from stdin.
    #[arg(long = "private-key-stdin")]
    pub private_key_stdin: bool,
}

pub fn run(args: PasskeyArgs, path: &Path, password: &str) -> Result<()> {
    let options = ConnectOptions {
        url: args.cdp,
        target: args.target,
        target_id: args.target_id,
    };
    let timeout = Duration::from_secs(args.timeout);
    match args.command {
        PasskeyCommand::List(list) => {
            let db = open_database(path, password)?;
            let rp = optional(&list.rp);
            let passkeys: Vec<PasskeySummary> = stored_summaries(&db)
                .into_iter()
                .filter(|passkey| rp.as_deref().is_none_or(|rp| passkey.rp_id.eq_ignore_ascii_case(rp)))
                .collect();
            output(json!({"passkeys": passkeys}));
            Ok(())
        }
        PasskeyCommand::Create => create(read_request()?, path, password),
        PasskeyCommand::Sign => sign(read_request()?, path, password),
        PasskeyCommand::Import(import) => import_passkey(import, path, password),
        PasskeyCommand::Register(args) => register(args, &options, timeout, path, password),
        PasskeyCommand::Use(use_args) => use_passkey(use_args, &options, timeout, path, password),
    }
}

/// Standard base64 (with padding, as CDP sends it) to base64url without
/// padding (as stored in the vault).
pub fn b64_to_b64url(value: &str) -> Result<String> {
    let bytes = BASE64.decode(value.as_bytes()).context("decode base64")?;
    Ok(BASE64URL_NOPAD.encode(&bytes))
}

/// base64url without padding (as stored in the vault) to standard base64 (with
/// padding, as CDP expects).
pub fn b64url_to_b64(value: &str) -> Result<String> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .context("decode base64url")?;
    Ok(BASE64.encode(&bytes))
}

/// Decode a PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----") into DER bytes.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    const HEADER: &str = "-----BEGIN PRIVATE KEY-----";
    const FOOTER: &str = "-----END PRIVATE KEY-----";
    let trimmed = pem.trim();
    if !trimmed.starts_with(HEADER) || !trimmed.contains(FOOTER) {
        bail!("expected a PKCS#8 private key PEM ({HEADER})");
    }
    let mut body = String::new();
    let mut inside = false;
    for line in trimmed.lines() {
        let line = line.trim();
        if line == HEADER {
            inside = true;
        } else if line == FOOTER {
            inside = false;
        } else if inside {
            body.push_str(line);
        }
    }
    if body.is_empty() {
        bail!("the PEM private key has no base64 body");
    }
    BASE64.decode(body.as_bytes()).context("decode PEM base64")
}

/// Encode DER bytes as a PKCS#8 PEM with the base64 body wrapped at 64 columns.
pub fn der_to_pem(der: &[u8]) -> String {
    let encoded = BASE64.encode(der);
    let mut pem = String::with_capacity(encoded.len() + 64);
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// base64url input, canonicalized without padding; trailing `=` is tolerated.
fn canonical_b64url(value: &str) -> Result<String> {
    let bytes = BASE64URL_NOPAD
        .decode(value.trim().trim_end_matches('=').as_bytes())
        .context("decode base64url")?;
    Ok(BASE64URL_NOPAD.encode(&bytes))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeySummary {
    pub title: String,
    pub rp_id: String,
    pub username: String,
    pub credential_id: String,
    pub sign_count: u64,
}

pub(crate) fn is_passkey_entry(entry: &Entry) -> bool {
    entry
        .get(PRIVATE_KEY_FIELD)
        .is_some_and(|value| !value.is_empty())
}

fn sign_count(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

fn stored_summaries(db: &Database) -> Vec<PasskeySummary> {
    let mut passkeys: Vec<PasskeySummary> = db
        .iter_all_entries()
        .filter(|entry| is_passkey_entry(entry))
        .map(|entry| PasskeySummary {
            title: entry.get_title().unwrap_or_default().to_owned(),
            rp_id: entry.get(RELYING_PARTY_FIELD).unwrap_or_default().to_owned(),
            username: entry.get(USERNAME_FIELD).unwrap_or_default().to_owned(),
            credential_id: entry.get(CREDENTIAL_ID_FIELD).unwrap_or_default().to_owned(),
            sign_count: sign_count(entry.get(SIGN_COUNT_FIELD)),
        })
        .collect();
    passkeys.sort_by_key(|passkey| passkey.title.to_lowercase());
    passkeys
}

/// The passkey fields as stored in one entry.
struct StoredPasskey {
    title: String,
    rp_id: String,
    username: String,
    backed_up: bool,
    credential_id: String,
    user_handle: String,
    private_key: String,
    sign_count: u64,
}

fn stored_passkeys(db: &Database, rp_id: &str, title: Option<&str>) -> Vec<StoredPasskey> {
    db.iter_all_entries()
        .filter(|entry| is_passkey_entry(entry))
        .filter(|entry| {
            entry
                .get(RELYING_PARTY_FIELD)
                .is_some_and(|stored| stored.eq_ignore_ascii_case(rp_id))
        })
        .filter(|entry| {
            title.is_none_or(|wanted| {
                entry
                    .get_title()
                    .is_some_and(|stored| stored.eq_ignore_ascii_case(wanted))
            })
        })
        .map(|entry| StoredPasskey {
            title: entry.get_title().unwrap_or_default().to_owned(),
            rp_id: entry.get(RELYING_PARTY_FIELD).unwrap_or_default().to_owned(),
            username: entry.get(USERNAME_FIELD).unwrap_or_default().to_owned(),
            backed_up: entry.get(BACKED_UP_FIELD) == Some("1"),
            credential_id: entry.get(CREDENTIAL_ID_FIELD).unwrap_or_default().to_owned(),
            user_handle: entry.get(USER_HANDLE_FIELD).unwrap_or_default().to_owned(),
            private_key: entry.get(PRIVATE_KEY_FIELD).unwrap_or_default().to_owned(),
            sign_count: sign_count(entry.get(SIGN_COUNT_FIELD)),
        })
        .collect()
}

/// The passkey fields as CDP wants them on the wire.
struct LoadedPasskey {
    title: String,
    rp_id: String,
    credential_id: String,
    credential_id_b64: String,
    private_key_b64: String,
    user_handle_b64: String,
    sign_count: u64,
}

fn load_passkey(stored: StoredPasskey) -> Result<LoadedPasskey> {
    let entry = |detail: String| format!("passkey entry \"{}\": {detail}", stored.title);
    let credential_id_b64 = b64url_to_b64(&stored.credential_id)
        .with_context(|| entry("invalid credential id".to_owned()))?;
    let private_key_b64 = BASE64.encode(
        &pem_to_der(&stored.private_key)
            .with_context(|| entry("invalid private key PEM".to_owned()))?,
    );
    let user_handle_b64 = b64url_to_b64(&stored.user_handle)
        .with_context(|| entry("invalid user handle".to_owned()))?;
    Ok(LoadedPasskey {
        title: stored.title,
        rp_id: stored.rp_id,
        credential_id: stored.credential_id,
        credential_id_b64,
        private_key_b64,
        user_handle_b64,
        sign_count: stored.sign_count,
    })
}

/// Which loaded passkeys the browser has bumped past their loaded sign count,
/// as `(index into loaded, new count)`. Credentials that were not loaded and
/// counts that did not move are ignored.
fn sign_increments(loaded: &[LoadedPasskey], credentials: &[Value]) -> Vec<(usize, u64)> {
    loaded
        .iter()
        .enumerate()
        .filter_map(|(index, passkey)| {
            let current = credentials.iter().find(|credential| {
                credential.get("credentialId").and_then(Value::as_str)
                    == Some(passkey.credential_id_b64.as_str())
            })?;
            let count = current.get("signCount").and_then(Value::as_u64)?;
            (count > passkey.sign_count).then_some((index, count))
        })
        .collect()
}

/// A passkey about to be stored in a new entry.
struct NewPasskey {
    title: String,
    rp_id: String,
    username: String,
    credential_id: String,
    private_key_pem: String,
    user_handle: String,
    sign_count: u64,
    backed_up: bool,
}

fn insert_entry(db: &mut Database, passkey: &NewPasskey) -> Result<()> {
    let id = db.root_mut().add_entry().id();
    let mut entry = db.entry_mut(id).context("entry disappeared")?;
    entry.set_unprotected(fields::TITLE, &passkey.title);
    entry.set_unprotected(fields::USERNAME, &passkey.username);
    entry.set_unprotected(fields::URL, format!("https://{}", passkey.rp_id));
    entry.set_unprotected(CREDENTIAL_ID_FIELD, &passkey.credential_id);
    entry.set_protected(PRIVATE_KEY_FIELD, &passkey.private_key_pem);
    entry.set_unprotected(RELYING_PARTY_FIELD, &passkey.rp_id);
    entry.set_unprotected(USERNAME_FIELD, &passkey.username);
    entry.set_protected(USER_HANDLE_FIELD, &passkey.user_handle);
    entry.set_unprotected(SIGN_COUNT_FIELD, passkey.sign_count.to_string());
    if passkey.backed_up {
        entry.set_unprotected(BACKED_UP_FIELD, "1");
    }
    Ok(())
}

fn title_taken(db: &Database, title: &str) -> bool {
    db.iter_all_entries()
        .any(|entry| entry.get_title().is_some_and(|stored| stored.eq_ignore_ascii_case(title)))
}

/// Trim an optional CLI string, treating an empty value as absent.
fn optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn required_title(value: &str) -> Result<String> {
    let title = value.trim();
    if title.is_empty() {
        bail!("--title cannot be empty");
    }
    Ok(title.to_owned())
}

fn default_title(rp_id: &str, username: &str, user_handle: &str) -> String {
    let identity = if !username.is_empty() {
        username.to_owned()
    } else if !user_handle.is_empty() {
        user_handle.chars().take(8).collect()
    } else {
        String::new()
    };
    if identity.is_empty() {
        format!("{rp_id} passkey")
    } else {
        format!("{rp_id} passkey ({identity})")
    }
}

fn authenticator_options() -> Value {
    json!({
        "protocol": "ctap2",
        "ctap2Version": "ctap2_1",
        "transport": "internal",
        "hasResidentKey": true,
        "hasUserVerification": true,
        "isUserVerified": true,
        "automaticPresenceSimulation": true
    })
}

fn add_virtual_authenticator(browser: &mut cdp::Cdp) -> Result<String> {
    let result = browser.call(
        "WebAuthn.addVirtualAuthenticator",
        json!({"options": authenticator_options()}),
    )?;
    Ok(result
        .get("authenticatorId")
        .and_then(Value::as_str)
        .context("CDP did not return an authenticatorId")?
        .to_owned())
}

fn import_passkey(args: ImportArgs, path: &Path, password: &str) -> Result<()> {
    if !args.private_key_stdin {
        bail!("import needs --private-key-stdin (a PKCS#8 PEM on stdin)");
    }
    let rp_id = args.rp.trim().to_ascii_lowercase();
    if rp_id.is_empty() {
        bail!("--rp cannot be empty");
    }
    let title = required_title(&args.title)?;
    let credential_id = canonical_b64url(&args.credential_id)
        .context("--credential-id must be base64url (no padding)")?;
    if credential_id.is_empty() {
        bail!("--credential-id cannot be empty");
    }
    let user_handle = canonical_b64url(&args.user_handle)
        .context("--user-handle must be base64url (no padding)")?;
    let mut pem = String::new();
    io::stdin().read_to_string(&mut pem)?;
    let der = pem_to_der(&pem).context("--private-key-stdin must be a PKCS#8 PEM private key")?;
    let passkey = NewPasskey {
        title,
        rp_id,
        username: args.username.trim().to_owned(),
        credential_id,
        private_key_pem: der_to_pem(&der),
        user_handle,
        sign_count: 0,
        backed_up: false,
    };
    let mut db = open_database(path, password)?;
    if title_taken(&db, &passkey.title) {
        bail!("an entry named \"{}\" already exists", passkey.title);
    }
    if let Some(existing) = db
        .iter_all_entries()
        .find(|entry| entry.get(CREDENTIAL_ID_FIELD) == Some(passkey.credential_id.as_str()))
    {
        bail!(
            "a passkey with credential id {} is already stored in entry \"{}\"",
            passkey.credential_id,
            existing.get_title().unwrap_or_default()
        );
    }
    insert_entry(&mut db, &passkey)?;
    save_database(&db, path, password)?;
    println!("{}", saved_line(&passkey));
    Ok(())
}

fn register(
    args: RegisterArgs,
    options: &ConnectOptions,
    timeout: Duration,
    path: &Path,
    password: &str,
) -> Result<()> {
    let rp_id = args.rp.trim().to_ascii_lowercase();
    if rp_id.is_empty() {
        bail!("--rp cannot be empty");
    }
    // Fail before touching the browser: a passkey registered while the vault
    // is unreadable, or under a title that is already taken, could not be
    // saved, and re-running the ceremony may mint a different credential.
    {
        let db = open_database(path, password)?;
        if let Some(title) = optional(&args.title) {
            if title_taken(&db, &title) {
                bail!("an entry named \"{title}\" already exists");
            }
        }
    }
    let deadline = Instant::now() + timeout;
    let mut browser = options.connect()?;
    browser.call("WebAuthn.enable", json!({"enableUI": false}))?;
    let authenticator_id = add_virtual_authenticator(&mut browser)?;
    println!(
        "{}",
        json!({"ready": true, "authenticatorId": authenticator_id})
    );
    io::stdout().flush()?;

    let credential = loop {
        let result = browser.call(
            "WebAuthn.getCredentials",
            json!({"authenticatorId": authenticator_id}),
        )?;
        let found = result
            .get("credentials")
            .and_then(Value::as_array)
            .and_then(|credentials| {
                credentials.iter().find(|credential| {
                    credential
                        .get("rpId")
                        .and_then(Value::as_str)
                        .is_some_and(|stored| stored.eq_ignore_ascii_case(&rp_id))
                })
            });
        if let Some(credential) = found {
            break credential.clone();
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {}s waiting for the site to register a passkey for {rp_id}",
                timeout.as_secs()
            );
        }
        sleep(POLL_INTERVAL);
    };

    let credential_id = credential
        .get("credentialId")
        .and_then(Value::as_str)
        .context("CDP credential has no credentialId")?;
    let private_key = credential
        .get("privateKey")
        .and_then(Value::as_str)
        .context("CDP credential has no privateKey")?;
    let user_handle = credential
        .get("userHandle")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let username = credential
        .get("userName")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let sign_count = credential
        .get("signCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let der = BASE64
        .decode(private_key.as_bytes())
        .context("CDP privateKey is not base64")?;
    if der.is_empty() {
        bail!("CDP returned an empty private key");
    }
    let passkey = NewPasskey {
        title: optional(&args.title)
            .unwrap_or_else(|| default_title(&rp_id, username, user_handle)),
        rp_id: rp_id.clone(),
        username: username.to_owned(),
        credential_id: b64_to_b64url(credential_id).context("CDP credentialId is not base64")?,
        private_key_pem: der_to_pem(&der),
        user_handle: b64_to_b64url(user_handle).context("CDP userHandle is not base64")?,
        sign_count,
        backed_up: false,
    };

    // Re-open after the ceremony: the file may have changed while waiting, and
    // a credential the site already registered must not be dropped silently
    // when the save fails.
    let persisted = (|| -> Result<()> {
        let mut db = open_database(path, password)?;
        if title_taken(&db, &passkey.title) {
            bail!("an entry named \"{}\" already exists", passkey.title);
        }
        insert_entry(&mut db, &passkey)?;
        save_database(&db, path, password)
    })();
    if let Err(error) = persisted {
        eprintln!(
            "vault: hint: the site now holds a passkey that is not saved in the vault (credential id {})",
            passkey.credential_id
        );
        return Err(error);
    }
    println!("{}", saved_line(&passkey));
    // Best effort: the authenticator also goes away when this process exits.
    if let Err(error) = browser.call(
        "WebAuthn.removeVirtualAuthenticator",
        json!({"authenticatorId": authenticator_id}),
    ) {
        eprintln!("vault: warning: could not remove the virtual authenticator: {error:#}");
    }
    Ok(())
}

fn saved_line(passkey: &NewPasskey) -> Value {
    json!({
        "saved": true,
        "title": passkey.title,
        "rpId": passkey.rp_id,
        "username": passkey.username,
        "credentialId": passkey.credential_id
    })
}

fn use_passkey(
    args: UseArgs,
    options: &ConnectOptions,
    timeout: Duration,
    path: &Path,
    password: &str,
) -> Result<()> {
    let rp_id = args.rp.trim().to_ascii_lowercase();
    if rp_id.is_empty() {
        bail!("--rp cannot be empty");
    }
    let title = optional(&args.title);
    let db = open_database(path, password)?;
    let stored = stored_passkeys(&db, &rp_id, title.as_deref());
    if stored.is_empty() {
        let qualifier = title
            .as_deref()
            .map(|title| format!(" titled \"{title}\""))
            .unwrap_or_default();
        bail!("no stored passkey for {rp_id}{qualifier}");
    }
    let loaded: Vec<LoadedPasskey> = stored
        .into_iter()
        .map(load_passkey)
        .collect::<Result<_>>()?;
    drop(db);

    let deadline = Instant::now() + timeout;
    let mut browser = options.connect()?;
    browser.call("WebAuthn.enable", json!({"enableUI": false}))?;
    let authenticator_id = add_virtual_authenticator(&mut browser)?;
    for passkey in &loaded {
        let payload = json!({
            "authenticatorId": authenticator_id,
            "credential": {
                "credentialId": passkey.credential_id_b64,
                "isResidentCredential": true,
                "rpId": passkey.rp_id,
                "privateKey": passkey.private_key_b64,
                "userHandle": passkey.user_handle_b64,
                "signCount": passkey.sign_count
            }
        });
        if let Err(error) = browser.call_checked("WebAuthn.addCredential", payload) {
            // The payload carries the private key, so report only the entry
            // and the CDP error's code/message fields; never the params or
            // any other error data.
            bail!(
                "CDP WebAuthn.addCredential failed for passkey entry \"{}\": {error}",
                passkey.title
            );
        }
    }
    println!(
        "{}",
        json!({"ready": true, "credentials": loaded.len()})
    );
    io::stdout().flush()?;

    // A sign-in happened when an assertion bumped a sign counter past what was
    // loaded. The virtual authenticator stays alive until this process exits.
    let used = loop {
        let result = browser.call(
            "WebAuthn.getCredentials",
            json!({"authenticatorId": authenticator_id}),
        )?;
        let credentials = result
            .get("credentials")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let increments = sign_increments(&loaded, &credentials);
        if !increments.is_empty() {
            break increments;
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {}s waiting for a sign-in for {rp_id}",
                timeout.as_secs()
            );
        }
        sleep(POLL_INTERVAL);
    };

    // The database may have changed while waiting; write a fresh copy.
    let mut db = open_database(path, password)?;
    for (index, count) in &used {
        let passkey = &loaded[*index];
        let id = db
            .iter_all_entries()
            .find(|entry| entry.get(CREDENTIAL_ID_FIELD) == Some(passkey.credential_id.as_str()))
            .map(|entry| entry.id())
            .with_context(|| {
                format!(
                    "passkey entry \"{}\" disappeared while waiting",
                    passkey.title
                )
            })?;
        db.entry_mut(id)
            .context("entry disappeared")?
            .set_unprotected(SIGN_COUNT_FIELD, count.to_string());
    }
    save_database(&db, path, password)?;
    let (index, count) = used.first().copied().context("no credential was used")?;
    let passkey = &loaded[index];
    println!(
        "{}",
        json!({
            "used": true,
            "title": passkey.title,
            "rpId": rp_id,
            "credentialId": passkey.credential_id,
            "signCount": count
        })
    );
    Ok(())
}

/// A request from a browser, as JSON on stdin.
fn read_request<T: for<'de> Deserialize<'de>>() -> Result<T> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    serde_json::from_str(&input).context("the request on stdin is not the expected JSON")
}

fn rp_id_of(value: &str) -> Result<String> {
    let rp_id = value.trim().to_ascii_lowercase();
    if rp_id.is_empty() {
        bail!("rpId cannot be empty");
    }
    Ok(rp_id)
}

fn decode_b64url(value: &str, what: &str) -> Result<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(value.trim().trim_end_matches('=').as_bytes())
        .with_context(|| format!("{what} must be base64url"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRequest {
    rp_id: String,
    user_name: String,
    /// The site's id for the account, base64url.
    user_handle: String,
    #[serde(default)]
    exclude_credentials: Vec<String>,
    #[serde(default)]
    title: Option<String>,
}

/// The first of "title", "title 2", "title 3"... that no entry uses.
fn free_title(db: &Database, title: &str) -> String {
    (1..)
        .map(|n| if n == 1 { title.to_owned() } else { format!("{title} {n}") })
        .find(|candidate| !title_taken(db, candidate))
        .expect("some title is free")
}

fn create(request: CreateRequest, path: &Path, password: &str) -> Result<()> {
    let rp_id = rp_id_of(&request.rp_id)?;
    let user_handle = decode_b64url(&request.user_handle, "userHandle")?;
    if user_handle.is_empty() || user_handle.len() > 64 {
        bail!("userHandle must be 1 to 64 bytes");
    }
    let excluded: Vec<String> = request
        .exclude_credentials
        .iter()
        .filter_map(|id| canonical_b64url(id).ok())
        .collect();
    let mut db = open_database(path, password)?;
    if let Some(existing) = stored_passkeys(&db, &rp_id, None)
        .into_iter()
        .find(|stored| excluded.contains(&stored.credential_id))
    {
        bail!("excluded: the vault already has a passkey for {rp_id} in \"{}\"", existing.title);
    }
    let username = request.user_name.trim().to_owned();
    let user_handle = BASE64URL_NOPAD.encode(&user_handle);
    let title = optional(&request.title).unwrap_or_else(|| default_title(&rp_id, &username, &user_handle));
    let made = authenticator::make(&rp_id, true)?;
    let passkey = NewPasskey {
        title: free_title(&db, &title),
        rp_id,
        username,
        credential_id: BASE64URL_NOPAD.encode(&made.credential_id),
        private_key_pem: made.private_key_pem.clone(),
        user_handle,
        sign_count: 0,
        backed_up: true,
    };
    insert_entry(&mut db, &passkey)?;
    save_database(&db, path, password)?;
    output(json!({
        "title": passkey.title,
        "rpId": passkey.rp_id,
        "credentialId": passkey.credential_id,
        "attestationObject": BASE64URL_NOPAD.encode(&made.attestation_object),
        "authenticatorData": BASE64URL_NOPAD.encode(&made.authenticator_data),
        "publicKey": BASE64URL_NOPAD.encode(&made.public_key_der),
        "publicKeyAlgorithm": authenticator::ES256,
    }));
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest {
    rp_id: String,
    /// SHA-256 of the client data JSON, base64url.
    client_data_hash: String,
    /// The passkey chosen, when the site allows several.
    #[serde(default)]
    credential_id: Option<String>,
    /// The site's list of acceptable passkeys; empty means any for the site.
    #[serde(default)]
    allow_credentials: Vec<String>,
}

fn sign(request: SignRequest, path: &Path, password: &str) -> Result<()> {
    let rp_id = rp_id_of(&request.rp_id)?;
    let client_data_hash = decode_b64url(&request.client_data_hash, "clientDataHash")?;
    if client_data_hash.len() != 32 {
        bail!("clientDataHash must be a SHA-256 hash (32 bytes)");
    }
    let chosen = request.credential_id.as_deref().map(canonical_b64url).transpose()?;
    let allowed: Vec<String> = request
        .allow_credentials
        .iter()
        .filter_map(|id| canonical_b64url(id).ok())
        .collect();
    let db = open_database(path, password)?;
    let mut matches: Vec<StoredPasskey> = stored_passkeys(&db, &rp_id, None)
        .into_iter()
        .filter(|stored| chosen.as_ref().is_none_or(|id| &stored.credential_id == id))
        .filter(|stored| allowed.is_empty() || allowed.contains(&stored.credential_id))
        .collect();
    if matches.is_empty() {
        bail!("no passkey for {rp_id} in the vault");
    }
    if matches.len() > 1 {
        bail!("{} passkeys for {rp_id} match; choose one with credentialId", matches.len());
    }
    let stored = matches.remove(0);
    // A counter that has started (a passkey captured from the browser) keeps
    // going up; one that never did stays at zero, so a sign-in never writes.
    let sign_count = if stored.sign_count > 0 { stored.sign_count + 1 } else { 0 };
    let assertion = authenticator::assert(
        &stored.private_key,
        &rp_id,
        &client_data_hash,
        u32::try_from(sign_count).unwrap_or(u32::MAX),
        stored.backed_up,
    )
    .with_context(|| format!("passkey entry \"{}\"", stored.title))?;
    if sign_count > 0 {
        let mut db = db;
        let id = db
            .iter_all_entries()
            .find(|entry| entry.get(CREDENTIAL_ID_FIELD) == Some(stored.credential_id.as_str()))
            .map(|entry| entry.id())
            .context("the passkey entry disappeared")?;
        db.entry_mut(id)
            .context("entry disappeared")?
            .set_unprotected(SIGN_COUNT_FIELD, sign_count.to_string());
        save_database(&db, path, password)?;
    }
    output(json!({
        "title": stored.title,
        "rpId": rp_id,
        "userName": stored.username,
        "credentialId": stored.credential_id,
        "userHandle": stored.user_handle,
        "authenticatorData": BASE64URL_NOPAD.encode(&assertion.authenticator_data),
        "signature": BASE64URL_NOPAD.encode(&assertion.signature),
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_and_url_base64_convert_both_ways() {
        assert_eq!(b64_to_b64url("+/8A").unwrap(), "-_8A");
        assert_eq!(b64_to_b64url("/+4=").unwrap(), "_-4");
        assert_eq!(b64_to_b64url("aGVsbG8=").unwrap(), "aGVsbG8");
        assert_eq!(b64url_to_b64("-_8A").unwrap(), "+/8A");
        assert_eq!(b64url_to_b64("_-4").unwrap(), "/+4=");
        assert_eq!(b64url_to_b64("aGVsbG8").unwrap(), "aGVsbG8=");
    }

    #[test]
    fn base64_helpers_reject_invalid_input() {
        assert!(b64_to_b64url("not base64!").is_err());
        assert!(b64_to_b64url("aGVsbG8").is_err()); // standard base64 needs padding
        assert!(b64url_to_b64("*bad*").is_err());
        assert!(b64url_to_b64("aGVsbG8=").is_err()); // base64url here is unpadded
    }

    #[test]
    fn pem_and_der_round_trip_with_lines_wrapped_at_64_columns() {
        let der: Vec<u8> = (0u8..130).collect();
        let pem = der_to_pem(&der);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
        let lines: Vec<&str> = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines.iter().map(|line| line.len()).collect::<Vec<_>>(),
            vec![64, 64, 48]
        );
        assert_eq!(pem_to_der(&pem).unwrap(), der);
        assert_eq!(
            pem_to_der("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----").unwrap(),
            b"abc"
        );
        assert!(der_to_pem(b"abc").contains("\nYWJj\n"));
    }

    #[test]
    fn pem_decoding_requires_a_pkcs8_body() {
        assert!(pem_to_der("").is_err());
        assert!(
            pem_to_der("-----BEGIN EC PRIVATE KEY-----\nYWJj\n-----END EC PRIVATE KEY-----")
                .is_err()
        );
        assert!(pem_to_der("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----").is_err());
    }

    #[test]
    fn passkey_entries_filter_by_rp_and_title_and_default_the_sign_count() {
        let mut db = Database::new();
        db.root_mut().name = "Vault".into();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "webauthn.io passkey (alice)");
            entry.set_unprotected(RELYING_PARTY_FIELD, "webauthn.io");
            entry.set_unprotected(USERNAME_FIELD, "alice");
            entry.set_unprotected(CREDENTIAL_ID_FIELD, "-_8A");
            entry.set_protected(PRIVATE_KEY_FIELD, "pem");
            entry.set_unprotected(USER_HANDLE_FIELD, "aGVsbG8");
            entry.set_unprotected(SIGN_COUNT_FIELD, "7");
        }
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "no key here");
            entry.set_unprotected(RELYING_PARTY_FIELD, "webauthn.io");
        }
        let summaries = stored_summaries(&db);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].title, "webauthn.io passkey (alice)");
        assert_eq!(summaries[0].rp_id, "webauthn.io");
        assert_eq!(summaries[0].username, "alice");
        assert_eq!(summaries[0].credential_id, "-_8A");
        assert_eq!(summaries[0].sign_count, 7);

        assert_eq!(stored_passkeys(&db, "WEBAUTHN.IO", None).len(), 1);
        assert_eq!(
            stored_passkeys(&db, "webauthn.io", Some("WEBAUTHN.IO PASSKEY (ALICE)")).len(),
            1
        );
        assert!(stored_passkeys(&db, "webauthn.io", Some("nope")).is_empty());
        assert!(stored_passkeys(&db, "example.test", None).is_empty());
    }

    #[test]
    fn default_titles_use_the_username_then_the_user_handle_prefix() {
        assert_eq!(
            default_title("webauthn.io", "alice", "aGVsbG8"),
            "webauthn.io passkey (alice)"
        );
        assert_eq!(
            default_title("webauthn.io", "", "aGVsbG8"),
            "webauthn.io passkey (aGVsbG8)"
        );
        assert_eq!(default_title("webauthn.io", "", ""), "webauthn.io passkey");
    }

    fn loaded_passkey(credential_id_b64: &str, sign_count: u64) -> LoadedPasskey {
        LoadedPasskey {
            title: format!("{credential_id_b64} entry"),
            rp_id: "webauthn.io".to_owned(),
            credential_id: format!("stored-{credential_id_b64}"),
            credential_id_b64: credential_id_b64.to_owned(),
            private_key_b64: String::new(),
            user_handle_b64: String::new(),
            sign_count,
        }
    }

    #[test]
    fn sign_increments_reports_counts_that_moved_past_the_loaded_value() {
        let loaded = vec![loaded_passkey("cred-a", 2), loaded_passkey("cred-b", 0)];
        // The browser may list credentials in any order, so match by id.
        let credentials = vec![
            json!({"credentialId": "cred-b", "signCount": 5}),
            json!({"credentialId": "cred-a", "signCount": 2}),
        ];
        assert_eq!(sign_increments(&loaded, &credentials), vec![(1, 5)]);
    }

    #[test]
    fn sign_increments_ignores_unchanged_counts() {
        let loaded = vec![loaded_passkey("cred-a", 4)];
        let credentials = vec![json!({"credentialId": "cred-a", "signCount": 4})];
        assert!(sign_increments(&loaded, &credentials).is_empty());
    }

    #[test]
    fn sign_increments_ignores_unknown_credentials() {
        let loaded = vec![loaded_passkey("cred-a", 0)];
        let credentials = vec![json!({"credentialId": "not-loaded", "signCount": 9})];
        assert!(sign_increments(&loaded, &credentials).is_empty());
    }
}
