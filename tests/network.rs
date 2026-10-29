//! Process checks for public network binding and local-only key preparation.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "allowit-cli-network-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn invoke(args: &[&str], dir: &std::path::Path) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_allowit"));
    c.args(args);
    for (k, _) in std::env::vars() {
        if k.starts_with("ALLOWIT_") {
            c.env_remove(k);
        }
    }
    c.env("ALLOWIT_POLICY_DIR", dir)
        .env("ALLOWIT_URL", "http://127.0.0.1:1")
        .output()
        .unwrap()
}
#[test]
fn explicit_devnet_selects_native_generation_without_rpc() {
    let d = directory();
    let o = invoke(
        &[
            "policy",
            "generate",
            "Spend up to 5 test tokens per day",
            "--network",
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "--json",
        ],
        &d,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let p: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(p["network"], "solana:devnet");
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
fn local_wallet_output_contains_only_public_registration_metadata() {
    let d = directory();
    let key = d.join("agent.key");
    let o = invoke(
        &[
            "wallet",
            "generate",
            "--network",
            "eip155:42431",
            "--output",
            key.to_str().unwrap(),
        ],
        &d,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let p: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(p.as_object().unwrap().len(), 4);
    assert_eq!(p["network"], "eip155:42431");
    assert!(p.get("seed").is_none());
    let o = invoke(
        &[
            "wallet",
            "show",
            "--network",
            "eip155:42431",
            key.to_str().unwrap(),
        ],
        &d,
    );
    assert!(o.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&o.stdout).unwrap(), p);
    std::fs::remove_dir_all(d).unwrap();
}
#[test]
fn cross_rail_request_fails_before_any_backend_or_bundle_access() {
    let d = directory();
    let o = invoke(
        &[
            "exec",
            "policy-id",
            "--network",
            "eip155:42431",
            "--rail",
            "solana",
            "--op",
            "transferSOL",
            "--addr",
            "recipient",
            "--amount",
            "1",
        ],
        &d,
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("conflicts with Tempo"));
    assert!(!d.exists());
}

#[cfg(unix)]
#[test]
fn deploy_prints_bound_browser_intent_without_loading_owner_key_or_calling_rpc() {
    use allowit_native::{crypto::Key, release};
    use serde_json::json;
    let d = directory();
    let generated = invoke(
        &[
            "policy",
            "generate",
            "Spend up to 5 test tokens per day",
            "--network",
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "--json",
        ],
        &d,
    );
    assert!(generated.status.success());
    let manifest = d.join("deployment.json");
    std::fs::write(&manifest,serde_json::to_vec(&json!({"network":"solana:devnet","sourceBundle":release().source_bundle,"policy":Key([7;32]),"policyData":Key([8;32]),"custody":Key([9;32])})).unwrap()).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_allowit"));
    for (k, _) in std::env::vars() {
        if k.starts_with("ALLOWIT_") {
            c.env_remove(k);
        }
    }
    let o = c
        .args([
            "policy",
            "deploy",
            "1",
            "--network",
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "--json",
        ])
        .env("ALLOWIT_POLICY_DIR", &d)
        .env("ALLOWIT_URL", "https://app.allowit.xyz")
        .env("ALLOWIT_OWNER", Key([1; 32]).to_string())
        .env("ALLOWIT_MINT", Key([4; 32]).to_string())
        .env("ALLOWIT_EXECUTOR", Key([2; 32]).to_string())
        .env("ALLOWIT_AUTHORITY", Key([3; 32]).to_string())
        .env("ALLOWIT_DEPLOYMENT_FILE", &manifest)
        .env("ALLOWIT_REQUEST_ID", "browser-deploy-proof-1")
        .env("ALLOWIT_OWNER_KEYPAIR", "/must-never-be-opened")
        .env("ALLOWIT_RPC_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(10),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let value: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(value["executed"], false);
    assert_eq!(value["state"], "awaiting_owner_signature");
    assert_eq!(value["intentDigest"].as_str().unwrap().len(), 64);
    assert!(
        value["signingUrl"]
            .as_str()
            .unwrap()
            .contains("#allowit-deploy=")
    );
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn help_and_version_do_not_read_broken_ambient_wallet_configuration() {
    for command in ["help", "version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_allowit"))
            .arg(command)
            .env("ALLOWIT_NETWORK", "not-a-network")
            .env("ALLOWIT_TEMPO_BUNDLE", "/must-not-be-read")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn imported_default_tempo_bundle_routes_only_its_policy_and_rejects_ambiguity() {
    use serde_json::json;
    let d = directory();
    std::fs::create_dir_all(d.join(".allowit-tempo")).unwrap();
    let addr = |n: u8| format!("0x{}", format!("{n:02x}").repeat(20));
    let policy_id = "0f".repeat(32);
    let bundle = json!({"version":1,"profile":"tempo-native-v1","origin":"https://service.invalid","capability":format!("tempo-executor.{}","a".repeat(32)),"config":{"network":"tempo:testnet","chainId":42431,"rpcUrl":"https://rpc.invalid","factory":addr(11),"factoryCodeHash":format!("0x{}","0c".repeat(32)),"token":addr(13),"executor":addr(6),"authority":addr(7),"feeToken":addr(14)},"policy":{"id":policy_id,"profile":"tempo-native-v1","network":"tempo:testnet","chainId":42431,"owner":addr(5),"token":addr(13),"executor":addr(6),"authority":addr(7),"factory":addr(11),"vault":addr(16),"policyDigest":format!("0x{}","11".repeat(32)),"requirementsDigest":format!("0x{}","12".repeat(32)),"semanticRequired":true,"prompt":"Pay for approved research","dailyLimit":"5","actionLimit":"1","totalLimit":"20","expiresAt":"18446744073709551615","recipient":addr(0)}});
    std::fs::write(
        d.join(".allowit-tempo/executor.json"),
        serde_json::to_vec(&bundle).unwrap(),
    )
    .unwrap();
    let run = |id: &str| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_allowit"));
        for (k, _) in std::env::vars() {
            if k.starts_with("ALLOWIT_") {
                c.env_remove(k);
            }
        }
        c.args(["show", id, "--json"])
            .current_dir(&d)
            .output()
            .unwrap()
    };
    let output = run(&policy_id);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown["network"], "tempo:testnet");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("tempo-executor"));
    let unrelated = run("unrelated-policy");
    assert!(!unrelated.status.success());
    assert!(String::from_utf8_lossy(&unrelated.stderr).contains("harness token"));
    std::fs::create_dir_all(d.join(".allowit")).unwrap();
    std::fs::write(
        d.join(".allowit/context.json"),
        serde_json::to_vec(&json!({"policyId":policy_id,"network":"solana:devnet"})).unwrap(),
    )
    .unwrap();
    let ambiguous = run(&policy_id);
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("Multiple wallet bindings"));
    std::fs::remove_dir_all(d).unwrap();
}
