//! Process-level native SDK checks: no Node, source checkout, signer, or network.
use allowit_native::{client::LOADER, crypto::Key, policy::Policy, release};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Command, Output},
};
fn run(directory: &Path, args: &[&str]) -> Output {
    run_with(directory, args, &[])
}
fn run_with(directory: &Path, args: &[&str], extra: &[(&str, &str)]) -> Output {
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
        .envs(extra.iter().copied())
        .output()
        .unwrap()
}
#[test]
fn status_uses_public_context_without_loading_any_signing_key() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    let directory = temp();
    let reference: Value = serde_json::from_str(include_str!(
        "../vendor/allowit-native/tests/reference.json"
    ))
    .unwrap();
    let bundle = json!({"version":1,"policy":reference["policy"],"context":{"policyId":reference["policy"]["id"],"owner":reference["owner"],"network":reference["config"]["network"],"mint":reference["config"]["mint"],"executor":reference["config"]["executor"],"deployment":reference["config"]["deployment"]}});
    let source = directory.with_extension("executor.json");
    std::fs::write(&source, bundle.to_string()).unwrap();
    assert!(
        run(&directory, &["policy", "import", source.to_str().unwrap()])
            .status
            .success()
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            conn.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let size = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|n| n.parse::<usize>().ok())
            })
            .unwrap();
        let mut body = vec![0; size];
        conn.read_exact(&mut body).unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["method"], "getGenesisHash");
        let body = json!({"jsonrpc":"2.0","id":request["id"],"result":"wrong-genesis"}).to_string();
        write!(
            conn,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });
    let result = run_with(
        &directory,
        &["policy", "status", "--json"],
        &[
            ("ALLOWIT_OWNER_KEYPAIR", "/nonexistent-owner-key"),
            ("ALLOWIT_EXECUTOR_KEYPAIR", "/nonexistent-executor-key"),
            ("ALLOWIT_RPC_URL", &url),
        ],
    );
    assert_eq!(result.status.code(), Some(3));
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains("genesis"), "{error}");
    assert!(!error.contains("key file"));
    server.join().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    std::fs::remove_file(source).unwrap();
}
fn temp() -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "allowit-cli-native-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
#[test]
fn generate_is_offline_native_and_preserves_policy_instance() {
    let directory = temp();
    let result = run_with(
        &directory,
        &[
            "policy",
            "generate",
            "Spend up to 5 test tokens per day",
            "--json",
        ],
        &[
            ("ALLOWIT_MINT", "unused-invalid-mint"),
            ("ALLOWIT_EXECUTOR", "unused-invalid-executor"),
            ("ALLOWIT_RPC_URL", "unused-invalid-rpc"),
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
    let result = run_with(
        &directory,
        &["policy", "import", source.to_str().unwrap(), "--json"],
        &[
            ("ALLOWIT_MINT", "unused-invalid-mint"),
            ("ALLOWIT_EXECUTOR", "unused-invalid-executor"),
            ("ALLOWIT_RPC_URL", "unused-invalid-rpc"),
        ],
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
    let audited = temp();
    let token = format!("native-report.{}", "a".repeat(32));
    let mut bundle = bundle;
    bundle["audit"] = json!({"origin":"https://staging.example.invalid","token":token});
    std::fs::write(&source, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let imported = run(
        &audited,
        &["policy", "import", source.to_str().unwrap(), "--json"],
    );
    assert!(imported.status.success());
    assert!(!String::from_utf8_lossy(&imported.stdout).contains(&token));
    assert!(!String::from_utf8_lossy(&imported.stderr).contains(&token));
    let audit = audited.join("journal/audit.json");
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&audit).unwrap()).unwrap()["token"],
        token
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&audit).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(audited).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    std::fs::remove_file(source).unwrap();
}
