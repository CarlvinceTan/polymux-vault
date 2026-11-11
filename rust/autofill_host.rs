//! Vault Autofill's native messaging host. Chromium starts it for each request from the
//! autofill extension: it finds the open site's accounts in the user's vault (the `vault` CLI over
//! a .kdbx), and hands over a password or code only after Touch ID, and only for that site.

#[cfg(target_os = "macos")]
mod host {
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;

    use block::ConcreteBlock;
    use objc::runtime::{BOOL, Object, YES};
    use objc::{class, msg_send, sel, sel_impl};
    use serde_json::{Value, json};

    #[link(name = "LocalAuthentication", kind = "framework")]
    unsafe extern "C" {}

    // Touch ID, or the Mac's password when it isn't available.
    const OWNER_AUTHENTICATION: i64 = 2;
    const CONFIRM_TIME: Duration = Duration::from_secs(120);
    // Second-level labels that are public suffixes, so "example.co.uk" is one site.
    const TWO_PART_SUFFIXES: [&str; 11] = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "edu.au", "com.sg", "co.nz",
        "co.jp", "com.br",
    ];

    struct Account {
        title: String,
        username: String,
        totp: bool,
    }

    // VAULT_AUTOFILL_DEBUG names a file for timings while testing; never a secret.
    fn note(what: &str) {
        let Some(path) = std::env::var_os("VAULT_AUTOFILL_DEBUG") else {
            return;
        };
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(file, "{at} {} {what}", std::process::id());
        }
    }

    pub fn main() {
        note("started");
        let Some(request) = read_message() else {
            return;
        };
        note(&format!(
            "asked {}",
            request["type"].as_str().unwrap_or("?")
        ));
        let reply = answer(&request).unwrap_or_else(|error| json!({ "error": error }));
        write_message(&reply);
        note("answered");
    }

    // Chrome's framing: a 4-byte length in native byte order, then that much JSON.
    fn read_message() -> Option<Value> {
        let mut length = [0u8; 4];
        std::io::stdin().read_exact(&mut length).ok()?;
        let mut body = vec![0u8; u32::from_ne_bytes(length) as usize];
        std::io::stdin().read_exact(&mut body).ok()?;
        serde_json::from_slice(&body).ok()
    }

    fn write_message(message: &Value) {
        let body = message.to_string().into_bytes();
        let mut out = std::io::stdout();
        let _ = out.write_all(&(body.len() as u32).to_ne_bytes());
        let _ = out.write_all(&body);
        let _ = out.flush();
    }

    fn answer(request: &Value) -> Result<Value, String> {
        // The extension reports that its worker is up; nothing here needs to wait for that.
        if matches!(request["type"].as_str(), Some("ready")) {
            return Ok(json!({}));
        }
        // The extension sets this from the frame that asked, not from anything the page says.
        let url = request["url"].as_str().ok_or("no page")?;
        let site = site_of(&host_of(url).ok_or("not a web page")?);
        let accounts = || -> Result<Vec<Account>, String> {
            Ok(vault(&["list"])?["entries"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|entry| entry_matches_site(entry, &site))
                // A passkey on its own has no password to fill; it's offered as a passkey.
                .filter(|entry| {
                    !(entry["hasPasskey"].as_bool() == Some(true)
                        && entry["hasPassword"].as_bool() != Some(true))
                })
                .map(|entry| Account {
                    title: entry["title"].as_str().unwrap_or_default().to_owned(),
                    username: entry["username"].as_str().unwrap_or_default().to_owned(),
                    totp: entry["hasTotp"].as_bool().unwrap_or(false),
                })
                .collect())
        };
        let chosen = |accounts: Vec<Account>| -> Result<Account, String> {
            let title = request["title"].as_str().ok_or("no account chosen")?;
            accounts
                .into_iter()
                .find(|account| account.title == title)
                .ok_or_else(|| "that account isn't for this site".into())
        };
        match request["type"].as_str() {
            Some("accounts") => Ok(json!({
                "accounts": accounts()?.iter()
                    .map(|account| json!({ "title": account.title, "username": account.username, "totp": account.totp }))
                    .collect::<Vec<_>>(),
            })),
            Some("fill") => {
                let account = chosen(accounts()?)?;
                confirm(&format!("fill your password for {site}"))?;
                let entry = vault(&["get", &account.title, "--field", "password"])?;
                Ok(json!({ "username": entry["username"], "password": entry["password"] }))
            }
            Some("code") => {
                let account = chosen(
                    accounts()?
                        .into_iter()
                        .filter(|account| account.totp)
                        .collect(),
                )?;
                confirm(&format!("fill a verification code for {site}"))?;
                Ok(json!({ "code": vault(&["totp", &account.title])?["code"] }))
            }
            // Addresses fill without Touch ID, as Safari's contact details do; a card asks first.
            Some("addresses") => Ok(json!({
                "addresses": own_entries(|entry| ["street", "postcode"].iter().any(|name| entry["fields"].get(name).is_some()))?
                    .iter().map(|entry| json!({ "title": entry["title"], "fields": entry["fields"] })).collect::<Vec<_>>(),
            })),
            Some("cards") => Ok(json!({
                "cards": own_entries(is_card)?.iter().map(|entry| json!({ "title": entry["title"] })).collect::<Vec<_>>(),
            })),
            Some("card") => {
                let title = request["title"].as_str().ok_or("no card chosen")?;
                if !own_entries(is_card)?
                    .iter()
                    .any(|entry| entry["title"] == title)
                {
                    return Err("no such card".into());
                }
                confirm(&format!("fill your card {title}"))?;
                Ok(json!({ "fields": vault(&["fields", title])?["fields"] }))
            }
            // A login just typed: whether the vault has it already. Nothing secret goes back.
            Some("known") => {
                // No vault yet: everything is new, and saving makes one.
                if vault(&["status"])?["exists"].as_bool() == Some(false) {
                    return Ok(json!({}));
                }
                let (username, password) = (
                    request["username"].as_str().unwrap_or_default(),
                    request["password"].as_str().unwrap_or_default(),
                );
                let Some(account) = accounts()?
                    .into_iter()
                    .find(|account| account.username == username)
                else {
                    return Ok(json!({}));
                };
                let saved = vault(&["get", &account.title, "--field", "password"])?;
                Ok(if saved["password"].as_str() == Some(password) {
                    json!({ "same": true })
                } else {
                    json!({ "update": true })
                })
            }
            // Saving what was typed, after a click on the page's offer: the account with this username
            // gets the new password, or a new entry is made under the site's name.
            Some("save") => {
                let (username, password) = (
                    request["username"].as_str().unwrap_or_default(),
                    request["password"].as_str().unwrap_or_default(),
                );
                if password.is_empty() {
                    return Err("nothing to save".into());
                }
                let created = ensure_vault()?;
                let title = match accounts()?
                    .into_iter()
                    .find(|account| account.username == username)
                {
                    Some(account) => account.title,
                    None => {
                        let taken: Vec<String> = vault(&["list"])?["entries"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|entry| {
                                entry["title"].as_str().map(str::to_ascii_lowercase)
                            })
                            .collect();
                        let named = if username.is_empty() {
                            site.clone()
                        } else {
                            format!("{site} ({username})")
                        };
                        if taken.contains(&site.to_ascii_lowercase()) {
                            named
                        } else {
                            site.clone()
                        }
                    }
                };
                let origin = url.split('/').take(3).collect::<Vec<_>>().join("/");
                let mut args = vec![
                    "put",
                    title.as_str(),
                    "--url",
                    origin.as_str(),
                    "--password-stdin",
                ];
                if !username.is_empty() {
                    args.extend(["--username", username]);
                }
                let mut child = vault_command(&args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("can't run vault: {e}"))?;
                child
                    .stdin
                    .take()
                    .ok_or("no stdin")?
                    .write_all(password.as_bytes())
                    .map_err(|e| format!("can't hand vault the password: {e}"))?;
                let output = child
                    .wait_with_output()
                    .map_err(|e| format!("vault failed: {e}"))?;
                if !output.status.success() {
                    return Err(String::from_utf8_lossy(&output.stderr)
                        .lines()
                        .next()
                        .unwrap_or("vault failed")
                        .to_owned());
                }
                Ok(json!({ "saved": title, "created": created }))
            }
            // A site's passkey request, answered by the vault itself.
            Some("passkeys") => passkeys(request, url),
            Some("passkey-create") => passkey_create(request, url),
            Some("passkey-sign") => passkey_sign(request, url),
            // A code from Messages needs no Touch ID: it's only filled into the field that asked.
            Some("messages") => Ok(message_code(&site).map_or(
                json!({}),
                |(code, for_site)| json!({ "code": code, "forSite": for_site }),
            )),
            _ => Err("unknown request".into()),
        }
    }

    // The relying party a page names has to be its own host or a domain it sits under (never a public
    // suffix), on https, as WebAuthn requires. Plain http is only for this machine.
    fn relying_party(request: &Value, url: &str) -> Result<String, String> {
        let host = host_of(url).ok_or("not a web page")?;
        let local = host == "localhost" || host.ends_with(".localhost");
        if !url.starts_with("https://") && !(url.starts_with("http://") && local) {
            return Err("passkeys need a secure page".into());
        }
        let rp = request["rpId"]
            .as_str()
            .filter(|rp| !rp.is_empty())
            .map_or_else(|| host.clone(), str::to_ascii_lowercase);
        if !(host == rp || host.ends_with(&format!(".{rp}"))) || site_of(&rp) != site_of(&host) {
            return Err("that passkey isn't for this site".into());
        }
        Ok(rp)
    }

    fn site_passkeys(rp: &str) -> Result<Vec<Value>, String> {
        Ok(vault(&["passkey", "list", "--rp", rp])?["passkeys"]
            .as_array()
            .cloned()
            .unwrap_or_default())
    }

    // A site's passkeys in the vault: names and ids only, so no Touch ID.
    fn passkeys(request: &Value, url: &str) -> Result<Value, String> {
        let rp = relying_party(request, url)?;
        Ok(json!({
            "passkeys": site_passkeys(&rp)?.iter()
                .map(|key| json!({ "title": key["title"], "username": key["username"], "credentialId": key["credentialId"] }))
                .collect::<Vec<_>>(),
        }))
    }

    // A new passkey, after a click on the page's sheet and Touch ID.
    fn passkey_create(request: &Value, url: &str) -> Result<Value, String> {
        let rp = relying_party(request, url)?;
        let user = request["userName"].as_str().unwrap_or_default();
        confirm(&if user.is_empty() {
            format!("save a passkey for {rp}")
        } else {
            format!("save a passkey for {user} on {rp}")
        })?;
        let created = ensure_vault()?;
        let input = json!({
            "rpId": rp, "userName": user, "userHandle": request["userHandle"],
            "excludeCredentials": request["excludeCredentials"].as_array().cloned().unwrap_or_default(),
        });
        let mut made = vault_with_input(&["passkey", "create"], &input.to_string())?;
        made["created"] = json!(created);
        Ok(made)
    }

    // The first thing saved with no vault yet makes one where the vault keeps it by default, its
    // master password random and kept in the Keychain (any KeePass app opens it with that
    // password, from Keychain Access, "OpenCode Vault"). Returns whether it made one.
    fn ensure_vault() -> Result<bool, String> {
        let status = vault(&["status"])?;
        if status["exists"].as_bool() == Some(true) {
            return if status["passwordAvailable"].as_bool() == Some(true) {
                Ok(false)
            } else {
                Err("the vault's master password isn't in the Keychain".into())
            };
        }
        let mut bytes = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut random| std::io::Read::read_exact(&mut random, &mut bytes))
            .map_err(|e| format!("no randomness for a master password: {e}"))?;
        let password: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        vault_with_input(&["create", "--password-stdin"], &password)?;
        note("made a vault");
        Ok(true)
    }

    // A sign-in with the passkey picked, after Touch ID.
    fn passkey_sign(request: &Value, url: &str) -> Result<Value, String> {
        let rp = relying_party(request, url)?;
        let id = request["credentialId"]
            .as_str()
            .ok_or("no passkey chosen")?;
        let keys = site_passkeys(&rp)?;
        let key = keys
            .iter()
            .find(|key| key["credentialId"].as_str() == Some(id))
            .ok_or("that passkey isn't for this site")?;
        let user = key["username"].as_str().unwrap_or_default();
        confirm(&if user.is_empty() {
            format!("sign in to {rp} with a passkey")
        } else {
            format!("sign in to {rp} as {user}")
        })?;
        let input =
            json!({ "rpId": rp, "clientDataHash": request["clientDataHash"], "credentialId": id });
        vault_with_input(&["passkey", "sign"], &input.to_string())
    }

    // Entries with fields of their own (`vault put --field`), for addresses and cards.
    fn own_entries(keep: impl Fn(&Value) -> bool) -> Result<Vec<Value>, String> {
        Ok(vault(&["list"])?["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| keep(entry))
            .cloned()
            .collect())
    }

    fn is_card(entry: &Value) -> bool {
        entry["secretFields"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "number"))
    }

    // How far back a code from Messages still counts.
    const MESSAGE_CODE_AGE: u64 = 3 * 60;
    // Messages counts time in nanoseconds from 2001.
    const APPLE_EPOCH: u64 = 978_307_200;
    const CODE_WORDS: [&str; 8] = [
        "code",
        "verification",
        "verify",
        "otp",
        "passcode",
        "one-time",
        "2fa",
        "pin",
    ];

    // The newest verification code in Messages from the last few minutes, and whether it's this
    // site's: a domain-bound "@site #code" line, or the message naming the site. Reading the Messages
    // database needs Full Disk Access for the host; without it there's simply no code.
    fn message_code(site: &str) -> Option<(String, bool)> {
        let db = std::env::var("VAULT_MESSAGES_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("HOME").unwrap_or_default())
                    .join("Library/Messages/chat.db")
            });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let since = (now
            .saturating_sub(MESSAGE_CODE_AGE)
            .saturating_sub(APPLE_EPOCH)) as u128
            * 1_000_000_000;
        let query = format!(
            "SELECT text, hex(attributedBody) AS body FROM message WHERE is_from_me = 0 AND date > {since} ORDER BY date DESC LIMIT 10"
        );
        let output = Command::new("/usr/bin/sqlite3")
            .args(["-readonly", "-json"])
            .arg(&db)
            .arg(query)
            .output()
            .ok()?;
        let rows: Vec<Value> = serde_json::from_slice(&output.stdout).ok()?;
        let name = site.split('.').next().unwrap_or(site).to_ascii_lowercase();
        rows.iter().find_map(|row| {
            let text = row["text"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| row["body"].as_str().and_then(attributed_text))?;
            Some(match bound_code(&text) {
                Some((domain, code)) => (code, site_of(&domain) == site),
                None => (code_in(&text)?, text.to_ascii_lowercase().contains(&name)),
            })
        })
    }

    // Newer Messages keeps the text only in an archived NSAttributedString: the string follows
    // "NSString", a marker byte "+", and its length.
    fn attributed_text(hex: &str) -> Option<String> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
            .collect();
        let at = bytes.windows(8).position(|w| w == b"NSString")? + 8;
        let plus = bytes[at..].iter().position(|b| *b == b'+')? + at + 1;
        let (length, start) = match *bytes.get(plus)? {
            0x81 => (
                u16::from_le_bytes([*bytes.get(plus + 1)?, *bytes.get(plus + 2)?]) as usize,
                plus + 3,
            ),
            n => (n as usize, plus + 1),
        };
        String::from_utf8(bytes.get(start..start + length)?.to_vec()).ok()
    }

    // The standard's domain-bound line: "@example.com #123456".
    fn bound_code(text: &str) -> Option<(String, String)> {
        let line = text.lines().last()?.trim();
        let (domain, code) = line.strip_prefix('@')?.split_once(" #")?;
        let code = code.split_whitespace().next()?;
        (!domain.is_empty() && code.chars().all(|c| c.is_ascii_alphanumeric()))
            .then(|| (domain.to_ascii_lowercase(), code.to_owned()))
    }

    // A 4 to 8 digit run in a message that reads like a code ("G-123456" counts as 123456).
    fn code_in(text: &str) -> Option<String> {
        let lower = text.to_ascii_lowercase();
        if !CODE_WORDS.iter().any(|word| lower.contains(word)) {
            return None;
        }
        lower
            .split(|c: char| !c.is_ascii_digit())
            .find(|run| (4..=8).contains(&run.len()))
            .map(str::to_owned)
    }

    fn host_of(url: &str) -> Option<String> {
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let authority = rest.split(['/', '?', '#']).next()?;
        let host = authority
            .rsplit('@')
            .next()?
            .split(':')
            .next()?
            .to_ascii_lowercase();
        (!host.is_empty()).then_some(host)
    }

    // The registrable part of a host, roughly as browsers group logins: "accounts.example.com" and
    // "www.example.com" are both "example.com". Addresses and single names stay whole.
    fn site_of(host: &str) -> String {
        let labels: Vec<&str> = host.split('.').collect();
        if labels.len() <= 2 || host.parse::<std::net::IpAddr>().is_ok() {
            return host.to_owned();
        }
        let last_two = labels[labels.len() - 2..].join(".");
        let keep = if TWO_PART_SUFFIXES.contains(&last_two.as_str()) {
            3
        } else {
            2
        };
        labels[labels.len() - keep..].join(".")
    }

    // An entry's login sites: its URL, then the `urls` field (one URL per line or comma), so a
    // Microsoft-hosted NUS login can match the NUS entry without loosening matching for others.
    fn entry_matches_site(entry: &Value, site: &str) -> bool {
        let url = entry["url"].as_str();
        let more = entry["fields"]["urls"].as_str();
        url.into_iter()
            .chain(more)
            .flat_map(|urls| urls.split(['\n', '\r', ',', ';', ' ']))
            .filter_map(|url| host_of(url.trim()))
            .any(|host| site_of(&host) == site)
    }

    // The vault CLI: VAULT_CLI names one, else the copy built beside this helper, else `vault` on
    // the PATH. VAULT_CLI_HOME runs it with another HOME, which keeps a test vault apart from the
    // real one (whose path is in ~/.config/opencode/vault.json).
    fn vault_command(args: &[&str]) -> Command {
        let program = std::env::var("VAULT_CLI")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let built_in = std::env::current_exe()
                    .ok()
                    .map(|exe| exe.with_file_name("vault"));
                built_in
                    .filter(|path| path.exists())
                    .unwrap_or_else(|| PathBuf::from("vault"))
            });
        let mut command = Command::new(program);
        command.args(args);
        if let Ok(test_home) = std::env::var("VAULT_CLI_HOME") {
            command.env("HOME", test_home);
        }
        command
    }

    // The vault with a request on stdin (never on the command line, where `ps` shows it).
    fn vault_with_input(args: &[&str], input: &str) -> Result<Value, String> {
        let mut child = vault_command(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("can't run vault: {e}"))?;
        child
            .stdin
            .take()
            .ok_or("no stdin")?
            .write_all(input.as_bytes())
            .map_err(|e| format!("can't ask vault: {e}"))?;
        let output = child
            .wait_with_output()
            .map_err(|e| format!("vault failed: {e}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("vault failed")
                .to_owned());
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| "vault answered in a way this doesn't read".into())
    }

    fn vault(args: &[&str]) -> Result<Value, String> {
        let output = vault_command(args)
            .output()
            .map_err(|e| format!("can't run vault: {e}"))?;
        if !output.status.success() {
            let why = String::from_utf8_lossy(&output.stderr);
            return Err(why.lines().next().unwrap_or("vault failed").to_owned());
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| "vault answered in a way this doesn't read".into())
    }

    // Touch ID before anything secret leaves the vault, as Safari asks before it fills. macOS shows
    // the reason with this host's name: "<host> is trying to <reason>."
    fn confirm(reason: &str) -> Result<(), String> {
        if std::env::var_os("VAULT_AUTOFILL_TEST_CONFIRM").is_some() {
            return Ok(());
        }
        let (sent, answered) = mpsc::channel();
        unsafe {
            let context: *mut Object = msg_send![class!(LAContext), new];
            let text = std::ffi::CString::new(reason).unwrap_or_default();
            let reason: *mut Object =
                msg_send![class!(NSString), stringWithUTF8String: text.as_ptr()];
            let reply = ConcreteBlock::new(move |ok: BOOL, _error: *mut Object| {
                let _ = sent.send(ok == YES);
            })
            .copy();
            let _: () = msg_send![context, evaluatePolicy: OWNER_AUTHENTICATION localizedReason: reason reply: &*reply];
        }
        match answered.recv_timeout(CONFIRM_TIME) {
            Ok(true) => Ok(()),
            _ => Err("not confirmed".into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn entry(url: &str, urls: Option<&str>) -> Value {
            let mut entry = json!({ "url": url });
            if let Some(urls) = urls {
                entry["fields"] = json!({ "urls": urls });
            }
            entry
        }

        #[test]
        fn an_entry_matches_its_url_and_its_extra_login_urls() {
            let nus = entry(
                "https://vafs.u.nus.edu/",
                Some("https://login.microsoftonline.com/\nhttps://nus.edu.sg"),
            );
            assert!(entry_matches_site(&nus, "microsoftonline.com"));
            assert!(entry_matches_site(&nus, "nus.edu"));
            assert!(!entry_matches_site(&nus, "example.com"));
            assert!(entry_matches_site(
                &entry("https://example.com", None),
                "example.com"
            ));
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    host::main();
}

#[cfg(not(target_os = "macos"))]
fn main() {}
