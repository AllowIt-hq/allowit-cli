//! Process checks for public network binding and local-only key preparation.
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn directory() -> PathBuf {
    std::env::temp_dir().canonicalize().unwrap().join(format!(
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

fn stellar_approval_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../repos/AllowIt-hq--allowit-sdk/client/tests/fixtures/stellar-approval.json"
    ))
    .unwrap()
}

fn public_stellar_bundle(fixture: &Value) -> Value {
    use allowit_stellar_wallet::{self as sdk, WalletConfig, WalletRoute};
    let policy = &fixture["policy"];
    let config = WalletConfig {
        network: "stellar:testnet".into(),
        policy_instance: [7; 32],
        wallet: fixture["intent"]["owner"].as_str().unwrap().into(),
        owner: fixture["intent"]["owner"].as_str().unwrap().into(),
        agent: sdk::account_for_seed(&[2; 32]),
        engine: sdk::account_for_seed(&[3; 32]),
        route: WalletRoute::Native,
        asset: policy["mint"].as_str().unwrap().into(),
        asset_symbol: "XLM".into(),
        asset_issuer: None,
        policy_source: policy["code"].as_str().unwrap().into(),
        source_hash: sdk::unhex(policy["sourceHash"].as_str().unwrap()).unwrap(),
        module_digest: [5; 32],
        max_fee_stroops: 100,
    };
    serde_json::json!({"version":1,"profile":sdk::PROFILE,"network":config.network,
        "policyId":policy["id"],"sourceHash":policy["sourceHash"],"irHash":policy["irHash"],
        "moduleDigest":sdk::hex(&config.module_digest),"wallet":config.wallet,
        "route":"native","config":config,
        "endpoints":{"execute":"/api/native/execute","status":"/api/native/execute/status"}})
}

fn isolated_command(dir: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_allowit"));
    for (name, _) in std::env::vars() {
        if name.starts_with("ALLOWIT_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(dir)
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "");
    command
}

#[test]
fn public_stellar_show_infers_network_without_signer_or_server_configuration() {
    let d = directory();
    std::fs::create_dir_all(&d).unwrap();
    let fixture = stellar_approval_fixture();
    let bundle = public_stellar_bundle(&fixture);
    let path = d.join("public-stellar.json");
    std::fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    for source in [false, true] {
        let mut command = isolated_command(&d);
        command
            .args(["show", "existing-native-policy", "--json"])
            .env("ALLOWIT_STELLAR_BUNDLE", &path)
            .env("ALLOWIT_STELLAR_SIGNER", "/must-never-be-opened")
            .env("ALLOWIT_URL", "not-a-server-origin");
        if source {
            command.arg("--source");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(shown["network"], "stellar:testnet");
        assert_eq!(shown["agent"], bundle["config"]["agent"]);
        assert_eq!(shown["wallet"], bundle["wallet"]);
        assert!(shown.get("signingSeed").is_none());
        assert!(shown.get("endpoints").is_none());
        if source {
            assert_eq!(shown["policy"], fixture["policy"]["code"]);
        } else {
            assert!(shown.get("policy").is_none());
        }
    }
    assert!(!d.join(".allowit").exists());
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn explicit_network_conflict_and_secret_public_bundle_fail_before_transport() {
    let d = directory();
    std::fs::create_dir_all(&d).unwrap();
    let fixture = stellar_approval_fixture();
    let mut bundle = public_stellar_bundle(&fixture);
    let path = d.join("public-stellar.json");
    std::fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let output = isolated_command(&d)
        .args([
            "show",
            "existing-native-policy",
            "--network",
            "solana:devnet",
            "--json",
        ])
        .env("ALLOWIT_STELLAR_BUNDLE", &path)
        .env("ALLOWIT_STELLAR_SIGNER", "/must-never-be-opened")
        .env("ALLOWIT_URL", "not-a-server-origin")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("conflicts with the public Stellar wallet binding")
    );
    assert!(output.stdout.is_empty());
    bundle["signingSeed"] = serde_json::json!("must-remain-local");
    std::fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let output = isolated_command(&d)
        .args(["show", "existing-native-policy", "--json"])
        .env("ALLOWIT_STELLAR_BUNDLE", &path)
        .env("ALLOWIT_URL", "not-a-server-origin")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not contain signing material"));
    assert!(output.stdout.is_empty());
    assert!(!d.join(".allowit").exists());
    std::fs::remove_dir_all(d).unwrap();
}

#[cfg(unix)]
#[test]
fn stellar_approval_commands_export_only_public_exact_intent_without_signing() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let fixture = stellar_approval_fixture();
    for generic in [false, true] {
        let d = directory();
        std::fs::create_dir_all(&d).unwrap();
        let file = d.join("policy.json");
        let mut policy = fixture["policy"].clone();
        policy["signingSeed"] = serde_json::json!("must-remain-local");
        std::fs::write(&file, serde_json::to_vec(&policy).unwrap()).unwrap();
        let owner = fixture["intent"]["owner"].as_str().unwrap();
        let request = fixture["intent"]["requestId"].as_str().unwrap();
        let mut command = isolated_command(&d);
        command
            .env("ALLOWIT_URL", "https://app.allowit.xyz")
            .env("ALLOWIT_OWNER_KEYPAIR", "/must-never-be-opened")
            .env("ALLOWIT_STELLAR_SIGNER", "/must-never-be-opened")
            .env("ALLOWIT_RPC_URL", "http://127.0.0.1:1");
        if generic {
            command
                .args(["policy", "deploy", "--network", "stellar:testnet", "--json"])
                .env("ALLOWIT_STELLAR_POLICY_FILE", &file)
                .env("ALLOWIT_OWNER", owner)
                .env("ALLOWIT_REQUEST_ID", request);
        } else {
            command.args([
                "--network",
                "stellar:testnet",
                "wallet",
                "approve",
                "--policy-file",
                file.to_str().unwrap(),
                "--owner",
                owner,
                "--request-id",
                request,
            ]);
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(shown["state"], "awaiting_owner_approval");
        assert_eq!(shown["executed"], false);
        assert_eq!(shown["movesFunds"], false);
        let url = shown["signingUrl"].as_str().unwrap();
        let encoded = url.split_once("#allowit-stellar-approval=").unwrap().1;
        let public: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        assert_eq!(public, fixture["intent"]);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("must-remain-local"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("must-never-be-opened"));
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn expired_stellar_setup_handoff_keeps_original_bytes_for_browser_recovery() {
    use allowit_stellar_wallet::{self as sdk, AccountState};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let d = directory();
    let journal = d.join(".allowit/stellar-owner-journal");
    std::fs::create_dir_all(&journal).unwrap();
    for path in [d.join(".allowit"), journal.clone()] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let state = AccountState {
        address: sdk::account_for_seed(&[1; 32]),
        sequence: 10,
        master_weight: 1,
        low_threshold: 0,
        medium_threshold: 0,
        high_threshold: 0,
        signers: vec![],
    };
    let agent = sdk::account_for_seed(&[2; 32]);
    let engine = sdk::account_for_seed(&[3; 32]);
    let id = "cli-expired-stellar-setup-001";
    let original =
        sdk::owner::prepare_native_setup(&state, &agent, &engine, id, "stellar:testnet", 100, 1)
            .unwrap();
    let path = journal.join(format!("request-{:x}.json", Sha256::digest(id.as_bytes())));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    serde_json::to_writer(file, &original).unwrap();
    let original_bytes = std::fs::read(&path).unwrap();
    let output = isolated_command(&d)
        .args([
            "wallet",
            "configure",
            "--network",
            "stellar:testnet",
            "--owner",
            &state.address,
            "--agent",
            &agent,
            "--engine",
            &engine,
            "--request-id",
            id,
        ])
        .env("ALLOWIT_URL", "https://app.allowit.xyz")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(10),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown["state"], "owner_intent_expired");
    assert_eq!(shown["recoveryOnly"], true);
    assert_eq!(shown["executed"], false);
    assert_eq!(shown["transactionHash"], original.transaction_hash);
    let encoded = shown["signingUrl"]
        .as_str()
        .unwrap()
        .split_once("#allowit-stellar-owner=")
        .unwrap()
        .1;
    let recovered: sdk::owner::NativeSetup =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
    assert_eq!(recovered, original);
    assert_eq!(std::fs::read(path).unwrap(), original_bytes);
    std::fs::remove_dir_all(d).unwrap();
}
