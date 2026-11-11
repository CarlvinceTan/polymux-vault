//! An entry's own fields: an address's street, a card's number. Protected ones are listed only by
//! name and come back only from `vault fields`.

use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const PASSWORD: &str = "fields-test-password";
const CARD_NUMBER: &str = "4111111111111111";

/// `vault create` stores the master password in the macOS Keychain, and a temp HOME has no login
/// keychain; give it one. HOME and VAULT_FILE both point into the temp directory, so nothing here
/// can reach the real vault.
fn prepare_keychain(home: &Path) {
    let keychain = home.join("Library/Keychains/login.keychain-db");
    fs::create_dir_all(keychain.parent().unwrap()).unwrap();
    let keychain = keychain.to_str().unwrap();
    for args in [&["create-keychain", "-p", PASSWORD, keychain][..], &["default-keychain", "-s", keychain][..]] {
        let status = Command::new("/usr/bin/security").env("HOME", home).args(args).status().unwrap();
        assert!(status.success(), "security {args:?}");
    }
}

fn vault(home: &Path, database: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vault"))
        .env_clear()
        .env("HOME", home)
        .env("VAULT_FILE", database)
        .env("VAULT_PASSWORD", PASSWORD)
        .args(args)
        .output()
        .unwrap()
}

fn json_of(output: Output) -> Value {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn entry<'a>(list: &'a Value, title: &str) -> &'a Value {
    list["entries"].as_array().unwrap().iter().find(|e| e["title"] == title).unwrap()
}

#[test]
fn own_fields_list_plainly_and_protected_ones_only_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    prepare_keychain(home);
    let database = home.join("fields.kdbx");
    json_of(vault(home, &database, &["create", "--password", PASSWORD]));
    json_of(vault(home, &database, &["put", "Home", "--field", "street=1 Main St", "--field", "city=Springfield"]));
    let card_number = format!("number={CARD_NUMBER}");
    json_of(vault(home, &database, &["put", "Visa", "--field", "cardholder=A Person", "--secret-field", &card_number, "--secret-field", "cvc=123"]));

    let listed = vault(home, &database, &["list"]);
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(CARD_NUMBER), "a protected value was listed");
    let list = json_of(listed);
    assert_eq!(entry(&list, "Home")["fields"], json!({"city": "Springfield", "street": "1 Main St"}));
    assert_eq!(entry(&list, "Visa")["fields"], json!({"cardholder": "A Person"}));
    assert_eq!(entry(&list, "Visa")["secretFields"], json!(["cvc", "number"]));

    let card = json_of(vault(home, &database, &["fields", "Visa"]));
    assert_eq!(card["fields"], json!({"cardholder": "A Person", "cvc": "123", "number": CARD_NUMBER}));

    json_of(vault(home, &database, &["put", "Home", "--field", "city="]));
    let address = json_of(vault(home, &database, &["fields", "Home"]));
    assert_eq!(address["fields"], json!({"street": "1 Main St"}));
}

#[test]
fn fields_the_vault_manages_cannot_be_set_as_own_fields() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    prepare_keychain(home);
    let database = home.join("fields.kdbx");
    json_of(vault(home, &database, &["create", "--password", PASSWORD]));
    for pair in ["Password=x", "otp=x", "KPEX_PASSKEY_USERNAME=x", "no-equals-sign"] {
        let refused = vault(home, &database, &["put", "Home", "--field", pair]);
        assert!(!refused.status.success(), "{pair} was accepted");
    }
}
