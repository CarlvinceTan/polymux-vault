use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

/// Throwaway P-256 PKCS#8 key generated for this test; it protects nothing.
const TEST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFOqxoKZldVHgBwRX
6bHZbVfYD9x3KsP9CzJZ1x1lg++hRANCAARYWFDyvGHrhfnCDg5f4cd8VnlFbaWJ
vXYV+TruThDANeanbui9alxILMlVOW/wyK0dVZikRz4+coC715d3YPoa
-----END PRIVATE KEY-----
";

const PASSWORD: &str = "passkey-test-password";

/// `vault create` stores the master password in the macOS Keychain, and a temp
/// HOME has no login keychain; give it one. Neither this keychain nor anything
/// else here can reach the real vault: HOME and VAULT_FILE both point into the
/// temp directory.
fn prepare_keychain(home: &Path) {
    let keychain = home.join("Library/Keychains/login.keychain-db");
    fs::create_dir_all(keychain.parent().unwrap()).unwrap();
    let keychain = keychain.to_str().unwrap();
    for args in [
        &["create-keychain", "-p", PASSWORD, keychain][..],
        &["default-keychain", "-s", keychain][..],
    ] {
        let status = Command::new("/usr/bin/security")
            .env("HOME", home)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "security {args:?}");
    }
}

fn vault(home: &Path, database: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vault"));
    command
        .env_clear()
        .env("HOME", home)
        .env("VAULT_FILE", database)
        .env("VAULT_PASSWORD", PASSWORD)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        let mut handle = child.stdin.take().unwrap();
        handle.write_all(input.as_bytes()).unwrap();
        drop(handle);
    }
    child.wait_with_output().unwrap()
}

fn ok(output: &Output) {
    assert!(
        output.status.success(),
        "exit {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The fixture PEM body's first 20 base64 characters. If they appear in a
/// command's output, private key material leaked.
fn pem_body_prefix() -> String {
    let body: String = TEST_KEY_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let prefix: String = body.chars().take(20).collect();
    assert_eq!(prefix.len(), 20, "the fixture PEM has no 20-character body");
    prefix
}

/// Every command, including `import`, must keep the fixture key out of both
/// stdout and stderr.
fn assert_no_key_material(output: &Output, command: &str) {
    let prefix = pem_body_prefix();
    for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(prefix.as_str()),
            "{command}: {stream} contains the fixture's private key material"
        );
    }
}

#[test]
fn imported_passkeys_are_listed_without_private_key_material() {
    const TITLE: &str = "webauthn.io passkey (alice)";
    const CREDENTIAL_ID: &str = "-_8A";
    const USER_HANDLE: &str = "aGVsbG8";

    let home = tempfile::tempdir().unwrap();
    let database = home.path().join("vault.kdbx");
    prepare_keychain(home.path());

    let output = vault(home.path(), &database, &["create", "--password", PASSWORD], None);
    ok(&output);
    assert_no_key_material(&output, "create");
    assert!(database.is_file());

    let output = vault(home.path(), &database, &["passkey", "list"], None);
    ok(&output);
    assert_no_key_material(&output, "passkey list before import");
    let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed["passkeys"].as_array().unwrap().len(), 0);

    let output = vault(
        home.path(),
        &database,
        &[
            "passkey",
            "import",
            "--rp",
            "webauthn.io",
            "--credential-id",
            CREDENTIAL_ID,
            "--user-handle",
            USER_HANDLE,
            "--username",
            "alice",
            "--title",
            TITLE,
            "--private-key-stdin",
        ],
        Some(TEST_KEY_PEM),
    );
    ok(&output);
    assert_no_key_material(&output, "passkey import");
    let saved: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(saved["saved"], true);
    assert_eq!(saved["title"], TITLE);
    assert_eq!(saved["rpId"], "webauthn.io");
    assert_eq!(saved["username"], "alice");
    assert_eq!(saved["credentialId"], CREDENTIAL_ID);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE"));

    let output = vault(home.path(), &database, &["passkey", "list"], None);
    ok(&output);
    assert_no_key_material(&output, "passkey list after import");
    let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
    let passkeys = listed["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0]["title"], TITLE);
    assert_eq!(passkeys[0]["rpId"], "webauthn.io");
    assert_eq!(passkeys[0]["username"], "alice");
    assert_eq!(passkeys[0]["credentialId"], CREDENTIAL_ID);
    assert_eq!(passkeys[0]["signCount"], 0);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE"));

    let output = vault(home.path(), &database, &["list"], None);
    ok(&output);
    assert_no_key_material(&output, "list");
    let entries: Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = entries["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["title"], TITLE);
    assert_eq!(entries[0]["hasPasskey"], true);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE"));

    // A second import must not overwrite the stored passkey.
    let output = vault(
        home.path(),
        &database,
        &[
            "passkey",
            "import",
            "--rp",
            "webauthn.io",
            "--credential-id",
            CREDENTIAL_ID,
            "--user-handle",
            USER_HANDLE,
            "--username",
            "alice",
            "--title",
            TITLE,
            "--private-key-stdin",
        ],
        Some(TEST_KEY_PEM),
    );
    assert!(!output.status.success());
    assert_no_key_material(&output, "duplicate import");
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
}

#[test]
fn importing_a_duplicate_credential_id_fails() {
    const CREDENTIAL_ID: &str = "_-4";

    let home = tempfile::tempdir().unwrap();
    let database = home.path().join("vault.kdbx");
    prepare_keychain(home.path());

    let output = vault(home.path(), &database, &["create", "--password", PASSWORD], None);
    ok(&output);
    assert_no_key_material(&output, "create");

    let import = |title: &str| {
        vault(
            home.path(),
            &database,
            &[
                "passkey",
                "import",
                "--rp",
                "webauthn.io",
                "--credential-id",
                CREDENTIAL_ID,
                "--user-handle",
                "aGVsbG8",
                "--username",
                "alice",
                "--title",
                title,
                "--private-key-stdin",
            ],
            Some(TEST_KEY_PEM),
        )
    };

    let output = import("first entry");
    ok(&output);
    assert_no_key_material(&output, "first import");

    // A different title sidesteps the title check, so the duplicate credential
    // id alone must reject this import.
    let output = import("second entry");
    assert!(!output.status.success());
    assert_no_key_material(&output, "duplicate import");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already stored"), "stderr: {stderr}");
    assert!(stderr.contains("credential id"), "stderr: {stderr}");

    let output = vault(home.path(), &database, &["passkey", "list"], None);
    ok(&output);
    assert_no_key_material(&output, "passkey list");
    let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
    let passkeys = listed["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0]["title"], "first entry");
}

fn json_of(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn b64url(value: &Value) -> Vec<u8> {
    data_encoding::BASE64URL_NOPAD
        .decode(value.as_str().unwrap().as_bytes())
        .unwrap()
}

/// What a browser signs: the hash of its client data JSON.
fn client_data_hash(challenge: &str) -> String {
    use sha2::{Digest, Sha256};
    let client_data = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"https://example.com\",\"crossOrigin\":false}}"
    );
    data_encoding::BASE64URL_NOPAD.encode(&Sha256::digest(client_data.as_bytes()))
}

#[test]
fn made_passkeys_sign_what_their_public_key_verifies() {
    use p256::{
        ecdsa::{Signature, VerifyingKey, signature::Verifier},
        pkcs8::DecodePublicKey,
    };

    let home = tempfile::tempdir().unwrap();
    let database = home.path().join("vault.kdbx");
    prepare_keychain(home.path());
    ok(&vault(home.path(), &database, &["create", "--password", PASSWORD], None));

    let request = r#"{"rpId": "Example.com", "userName": "alice@example.com", "userHandle": "dXNlci0x"}"#;
    let output = vault(home.path(), &database, &["passkey", "create"], Some(request));
    ok(&output);
    let made = json_of(&output);
    assert_eq!(made["title"], "example.com passkey (alice@example.com)");
    assert_eq!(made["rpId"], "example.com");
    assert_eq!(made["publicKeyAlgorithm"], -7);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("PRIVATE KEY"), "create printed key material");

    // Listed for its site only, without key material.
    let output = vault(home.path(), &database, &["passkey", "list", "--rp", "example.com"], None);
    ok(&output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE KEY"));
    let listed = json_of(&output);
    assert_eq!(listed["passkeys"].as_array().unwrap().len(), 1);
    assert_eq!(listed["passkeys"][0]["username"], "alice@example.com");
    assert_eq!(listed["passkeys"][0]["credentialId"], made["credentialId"]);
    let output = vault(home.path(), &database, &["passkey", "list", "--rp", "other.com"], None);
    assert_eq!(json_of(&output)["passkeys"].as_array().unwrap().len(), 0);

    // A sign-in with no allow list finds it by site, and verifies.
    let hash = client_data_hash("Y2hhbGxlbmdl");
    let request = format!(r#"{{"rpId": "example.com", "clientDataHash": "{hash}"}}"#);
    let output = vault(home.path(), &database, &["passkey", "sign"], Some(&request));
    ok(&output);
    let signed = json_of(&output);
    assert_eq!(signed["credentialId"], made["credentialId"]);
    assert_eq!(signed["userHandle"], "dXNlci0x");
    assert_eq!(signed["userName"], "alice@example.com");
    let authenticator_data = b64url(&signed["authenticatorData"]);
    assert_eq!(authenticator_data.len(), 37);
    assert_eq!(authenticator_data[32], 0x1d, "user present, verified, backed up");
    assert_eq!(&authenticator_data[33..], &[0, 0, 0, 0], "the counter stays at zero");
    let public = VerifyingKey::from_public_key_der(&b64url(&made["publicKey"])).unwrap();
    let signature = Signature::from_der(&b64url(&signed["signature"])).unwrap();
    let mut message = authenticator_data.clone();
    message.extend_from_slice(&b64url(&serde_json::Value::String(hash)));
    public.verify(&message, &signature).unwrap();

    // The public key in the attestation is the same one.
    let attestation = b64url(&made["attestationObject"]);
    let authenticator_data = b64url(&made["authenticatorData"]);
    assert!(attestation.ends_with(&authenticator_data));
    assert_eq!(authenticator_data[32], 0x5d, "attested, user present, verified, backed up");

    // Another site's sign-in finds nothing.
    let request = format!(r#"{{"rpId": "other.com", "clientDataHash": "{}"}}"#, client_data_hash("eA"));
    let output = vault(home.path(), &database, &["passkey", "sign"], Some(&request));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no passkey for other.com"));
}

#[test]
fn excluded_and_several_passkeys_are_handled() {
    let home = tempfile::tempdir().unwrap();
    let database = home.path().join("vault.kdbx");
    prepare_keychain(home.path());
    ok(&vault(home.path(), &database, &["create", "--password", PASSWORD], None));

    let first = r#"{"rpId": "example.com", "userName": "alice", "userHandle": "YQ"}"#;
    let output = vault(home.path(), &database, &["passkey", "create"], Some(first));
    ok(&output);
    let alice = json_of(&output);

    // A site that lists the passkey it has already is told so, and nothing is stored.
    let again = format!(
        r#"{{"rpId": "example.com", "userName": "alice", "userHandle": "YQ", "excludeCredentials": ["{}"]}}"#,
        alice["credentialId"].as_str().unwrap()
    );
    let output = vault(home.path(), &database, &["passkey", "create"], Some(&again));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("excluded:"));

    // A second account gets its own entry; the same title gets a number.
    let second = r#"{"rpId": "example.com", "userName": "bob", "userHandle": "Yg"}"#;
    ok(&vault(home.path(), &database, &["passkey", "create"], Some(second)));
    let output = vault(home.path(), &database, &["passkey", "create"], Some(first));
    ok(&output);
    assert_eq!(json_of(&output)["title"], "example.com passkey (alice) 2");
    let output = vault(home.path(), &database, &["passkey", "list", "--rp", "example.com"], None);
    assert_eq!(json_of(&output)["passkeys"].as_array().unwrap().len(), 3);

    // With several, a sign-in has to say which.
    let hash = client_data_hash("Yw");
    let request = format!(r#"{{"rpId": "example.com", "clientDataHash": "{hash}"}}"#);
    let output = vault(home.path(), &database, &["passkey", "sign"], Some(&request));
    assert!(String::from_utf8_lossy(&output.stderr).contains("choose one"));
    let request = format!(
        r#"{{"rpId": "example.com", "clientDataHash": "{hash}", "credentialId": "{}"}}"#,
        alice["credentialId"].as_str().unwrap()
    );
    let output = vault(home.path(), &database, &["passkey", "sign"], Some(&request));
    ok(&output);
    assert_eq!(json_of(&output)["userName"], "alice");
    // Or narrow it with the site's allow list.
    let request = format!(
        r#"{{"rpId": "example.com", "clientDataHash": "{hash}", "allowCredentials": ["{}"]}}"#,
        alice["credentialId"].as_str().unwrap()
    );
    ok(&vault(home.path(), &database, &["passkey", "sign"], Some(&request)));
}

#[test]
fn an_imported_passkey_signs_without_the_backed_up_flag() {
    let home = tempfile::tempdir().unwrap();
    let database = home.path().join("vault.kdbx");
    prepare_keychain(home.path());
    ok(&vault(home.path(), &database, &["create", "--password", PASSWORD], None));
    ok(&vault(
        home.path(),
        &database,
        &[
            "passkey", "import", "--rp", "webauthn.io", "--credential-id", "-_8A", "--user-handle",
            "aGVsbG8", "--username", "alice", "--title", "captured", "--private-key-stdin",
        ],
        Some(TEST_KEY_PEM),
    ));
    // Imported at 0, it stays at 0 and isn't marked backed up.
    let request = format!(r#"{{"rpId": "webauthn.io", "clientDataHash": "{}"}}"#, client_data_hash("YQ"));
    let output = vault(home.path(), &database, &["passkey", "sign"], Some(&request));
    ok(&output);
    assert_no_key_material(&output, "passkey sign");
    let authenticator_data = b64url(&json_of(&output)["authenticatorData"]);
    assert_eq!(authenticator_data[32], 0x05, "user present and verified only");
    assert_eq!(&authenticator_data[33..], &[0, 0, 0, 0]);
}
