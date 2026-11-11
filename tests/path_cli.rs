use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn vault(home: &Path, args: &[&str], environment_path: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vault"));
    command.env_clear().env("HOME", home).args(args);
    if let Some(path) = environment_path {
        command.env("VAULT_FILE", path);
    }
    command.output().unwrap()
}

#[test]
fn path_inspects_without_opening_database_or_creating_config() {
    let home = tempfile::tempdir().unwrap();
    let database = home.path().join("invalid-database.kdbx");
    fs::write(&database, b"not a KDBX database").unwrap();
    let output = vault(home.path(), &["path"], Some(&database));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["path"], database.to_str().unwrap());
    assert_eq!(report["source"], "env");
    assert_eq!(
        report["configFile"],
        home.path()
            .join(".config/opencode/vault.json")
            .to_str()
            .unwrap()
    );
    assert!(report.get("passwordAvailable").is_none());
    assert!(!home.path().join(".config").exists());
    assert_eq!(fs::read(&database).unwrap(), b"not a KDBX database");
}

#[test]
fn path_set_overrides_environment_without_moving_or_creating_database() {
    let home = tempfile::tempdir().unwrap();
    let old = home.path().join("old.kdbx");
    fs::write(&old, b"fixture database left in place").unwrap();
    let destination = home.path().join("iCloud Drive/Vault/vault.kdbx");
    let output = vault(
        home.path(),
        &["path", "--set", destination.to_str().unwrap()],
        Some(&old),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["path"], destination.to_str().unwrap());
    assert_eq!(report["previousPath"], old.to_str().unwrap());
    assert_eq!(report["source"], "config");
    assert_eq!(report["updated"], true);
    assert_eq!(report["databaseMoved"], false);
    assert_eq!(report["unlockSetupChanged"], false);
    assert!(!destination.parent().unwrap().exists());
    assert_eq!(fs::read(&old).unwrap(), b"fixture database left in place");
    let output = vault(home.path(), &["path"], Some(&old));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["path"], destination.to_str().unwrap());
}

#[test]
fn malformed_config_warns_on_inspect_and_is_preserved_on_set() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join(".config/opencode/vault.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "{malformed").unwrap();
    let output = vault(home.path(), &["path"], None);
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source"], "default");
    assert!(report["warning"].is_string());
    let output = vault(home.path(), &["path", "--set", "/new.kdbx"], None);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_to_string(&config).unwrap(), "{malformed");
}
