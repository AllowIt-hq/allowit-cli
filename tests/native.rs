//! Process-level native SDK checks: no Node, source checkout, signer, or network.
use allowit_native::{client::LOADER, crypto::Key, policy::Policy, release};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Command, Output},
};
fn run(directory: &Path, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_allowit"));
    c.args(args);
    for (name, _) in std::env::vars() {
        if name.starts_with("ALLOWIT_") {
            c.env_remove(name);
        }
    }
    c.env("PATH", "")
        .env("ALLOWIT_POLICY_DIR", directory)
        .env("ALLOWIT_NODE", "/missing/node")
        .env("ALLOWIT_SDK_CLI", "/missing/cli.mjs")
        .output()
        .unwrap()
}
fn temp() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "allowit-cli-native-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
#[test]
fn generate_is_offline_native_and_preserves_policy_instance() {
    let directory = temp();
    let result = run(
        &directory,
        &[
            "policy",
            "generate",
            "Spend up to 5 test tokens per day",
            "--json",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let p: Policy = serde_json::from_slice(&result.stdout).unwrap();
    p.validate().unwrap();
    let before = std::fs::read(directory.join("policy.json")).unwrap();
    let retry = run(
        &directory,
        &[
            "policy",
            "generate",
            "Spend up to 6 test tokens per day",
            "--json",
        ],
    );
    assert_eq!(retry.status.code(), Some(3));
    assert_eq!(
        std::fs::read(directory.join("policy.json")).unwrap(),
        before
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(directory.join("policy.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}
#[test]
fn import_is_public_only_and_cannot_replace_occupied_policy() {
    let directory = temp();
    let p = Policy::generate("solana:testnet", "Spend up to 5 test tokens per day").unwrap();
    let policy = Key([2; 32]);
    let pd = Key::find_program_address(&[&policy.0], Key::parse(LOADER).unwrap())
        .unwrap()
        .0;
    let context = json!({"policyId":p.id,"owner":Key([3;32]),"network":p.network,"mint":Key([4;32]),"executor":Key([5;32]),"deployment":{"network":p.network,"sourceBundle":release().source_bundle,"policy":policy,"policyData":pd,"custody":Key([6;32])}});
    let bundle = json!({"version":1,"policy":p,"context":context});
    let source = directory.with_extension("executor.json");
    std::fs::write(&source, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let result = run(
        &directory,
        &["policy", "import", source.to_str().unwrap(), "--json"],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(output["imported"], true);
    let saved = std::fs::read(directory.join("context.json")).unwrap();
    let repeated = run(
        &directory,
        &["policy", "import", source.to_str().unwrap(), "--json"],
    );
    assert_eq!(repeated.status.code(), Some(3));
    assert_eq!(
        std::fs::read(directory.join("context.json")).unwrap(),
        saved
    );
    std::fs::remove_dir_all(directory).unwrap();
    std::fs::remove_file(source).unwrap();
}
