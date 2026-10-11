//! Compare the Rust executable to the preserved Go reference at the process and
//! wire boundaries. Go is a test dependency only.
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output},
    sync::{Mutex, OnceLock},
};
static REFERENCE: OnceLock<std::path::PathBuf> = OnceLock::new();
static SERIAL: Mutex<()> = Mutex::new(());
fn reference() -> &'static std::path::PathBuf {
    REFERENCE.get_or_init(|| {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let binary = root.join("target/allowit-go-reference");
        let go_root = if root.join("reference/go/go.mod").exists() {
            root.join("reference/go")
        } else {
            root
        };
        assert!(
            Command::new("go")
                .args(["build", "-trimpath", "-o"])
                .arg(&binary)
                .arg("./cmd/allowit")
                .current_dir(go_root)
                .status()
                .unwrap()
                .success()
        );
        binary
    })
}
fn invoke(bin: &std::path::Path, args: &[&str], env: &BTreeMap<&str, String>) -> Output {
    let mut c = Command::new(bin);
    c.args(args);
    for (key, _) in std::env::vars() {
        if key.starts_with("ALLOWIT_") {
            c.env_remove(key);
        }
    }
    c.envs(env);
    c.output().unwrap()
}
fn compare(args: &[&str], env: &BTreeMap<&str, String>) {
    let old = invoke(reference(), args, env);
    let new = invoke(
        std::path::Path::new(env!("CARGO_BIN_EXE_allowit")),
        args,
        env,
    );
    assert_eq!(
        old.status.code(),
        new.status.code(),
        "{args:?}: {}",
        String::from_utf8_lossy(&new.stderr)
    );
    assert_eq!(old.stdout, new.stdout, "stdout {args:?}");
    assert_eq!(old.stderr, new.stderr, "stderr {args:?}");
}
#[test]
fn validation_and_help_match_reference() {
    let _guard = SERIAL.lock().unwrap();
    let env = BTreeMap::new();
    // The native policy command set is versioned independently and covered in
    // native.rs; the remaining shared CLI validation stays byte-for-byte.
    for args in [
        vec![],
        vec!["help"],
        vec!["version"],
        vec!["mystery"],
        vec!["show"],
        vec!["show", "policy", "--unknown"],
        vec!["show", "policy", "--json=maybe"],
        vec!["exec", "policy", "--amount", "1", "--amount", "2"],
        vec!["status", "policy", "too-short"],
        vec!["policy", "fund", "0"],
        vec!["policy", "tune", "-1"],
        vec!["policy", "generate", ""],
        vec!["policy", "generate", "several", "words"],
    ] {
        compare(&args, &env);
    }
}
#[test]
fn request_bytes_ids_states_and_context_match_reference() {
    let _guard = SERIAL.lock().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let calls = std::sync::Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let server = std::thread::spawn(move || {
        for _ in 0..16 {
            let (mut conn, _) = listener.accept().unwrap();
            let mut data = Vec::new();
            let mut byte = [0u8; 1];
            while !data.ends_with(b"\r\n\r\n") {
                conn.read_exact(&mut byte).unwrap();
                data.push(byte[0]);
            }
            let head = String::from_utf8(data).unwrap();
            let len = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|v| v.parse::<usize>().ok())
                })
                .unwrap_or(0);
            let mut body = vec![0; len];
            conn.read_exact(&mut body).unwrap();
            let skill = head.starts_with("GET ");
            let response = if skill {
                r#"{"network":"local:dev","capabilities":{"rails":{"solana":["SOL","USDC"]},"fixedTestRatesUSDC":{"SOL":"100","USDC":"1"}}}"#
            } else {
                recorded.lock().unwrap().push(body);
                r#"{"outcome":"pass","status":"ready","kind":"judgment","requestId":"srv-12345678","executed":false,"localRecorded":false}"#
            };
            write!(conn,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",response.len(),response).unwrap();
        }
    });
    let env = BTreeMap::from([
        ("ALLOWIT_URL", origin),
        ("ALLOWIT_TOKEN", "owner.policy.abcdefghijklmnop".into()),
    ]);
    for extra in [
        vec![
            "--amount",
            "1.2300",
            "--context",
            r#"{"z":18446744073709551615,"a":1.2300,"b":1e5}"#,
        ],
        vec![
            "--amount",
            "0.000000001",
            "--rail",
            "solana",
            "--op",
            "transferSOL",
            "--addr",
            "11111111111111111111111111111111",
        ],
        vec![
            "--amount",
            "1",
            "--request-id",
            "explicit-1234",
            "--merchant",
            "<merchant>",
        ],
        vec![
            "--amount",
            "0.000000001",
            "--rail",
            "solana",
            "--op",
            "transferSOL",
            "--addr",
            "11111111111111111111111111111111",
            "--before",
            r#"[{"TYPE":"bogus","type":"contract_call","contract":"11111111111111111111111111111111","METHOD":"noop","args":{},"maxCostUSDC":"0","maxCostUSDC":null}]"#,
        ],
    ] {
        let mut args = vec!["eval", "policy", "--action", "research", "--json"];
        args.extend(extra);
        compare(&args, &env);
    }
    server.join().unwrap();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 8);
    for pair in calls.as_chunks::<2>().0 {
        assert_eq!(pair[0], pair[1], "wire request differs");
    }
}
