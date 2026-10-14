//! Process checks for the native Stellar command, key boundaries and private state.
#[cfg(unix)]
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};
#[cfg(unix)]
const VERSION: &str = allowit_cli::VERSION;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/config.rs"]
mod config;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/error.rs"]
mod error;
#[cfg(unix)]
#[path = "../src/stellar.rs"]
mod stellar;
#[cfg(unix)]
#[path = "../src/stellar_http.rs"]
mod stellar_http;
#[cfg(unix)]
#[path = "../src/stellar_rpc.rs"]
mod stellar_rpc;
#[cfg(unix)]
#[path = "../src/stellar_store.rs"]
mod stellar_store;

fn temporary() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "allowit-stellar-process-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn run(directory: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_allowit"));
    for (name, _) in std::env::vars() {
        if name.starts_with("ALLOWIT_") {
            command.env_remove(name);
        }
    }
    command
        .args(args)
        .env("PATH", "")
        .env("ALLOWIT_STELLAR_STATE_DIR", directory)
        .env(
            "ALLOWIT_STELLAR_EXECUTOR_KEY_FILE",
            "/must-not-be-read-executor",
        )
        .env(
            "ALLOWIT_STELLAR_AUTHORITY_KEY_FILE",
            "/must-not-be-read-authority",
        )
        .output()
        .unwrap()
}
#[test]
fn command_runs_without_node_and_names_explicit_operator_boundary() {
    let state = temporary();
    let output = run(&state, &["stellar", "help"]);
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("prepare URL --id"));
    assert!(help.contains("authorize REQUEST_ID"));
    assert!(help.contains("reads only the executor key"));
    assert!(!state.exists());
}
#[test]
fn repeated_or_missing_option_values_stop_before_state_or_key_access() {
    let state = temporary();
    for args in [
        vec!["stellar", "call", "--id"],
        vec!["stellar", "prepare", "--json", "--json"],
        vec!["stellar", "unknown"],
    ] {
        let output = run(&state, &args);
        assert_eq!(output.status.code(), Some(2));
        assert!(!state.exists());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains("signing key"));
    }
}

#[cfg(not(unix))]
#[test]
fn unsupported_platform_refuses_before_input_keys_and_state() {
    let state = temporary();
    let output = run(
        &state,
        &["stellar", "import", "/must-not-be-read-config.json"],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("local POSIX filesystem")
    );
    assert!(!state.exists());
}

#[cfg(unix)]
fn contract(seed: u8) -> String {
    let mut bytes = vec![16];
    bytes.extend([seed; 32]);
    let mut crc = 0u16;
    for byte in &bytes {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                crc.wrapping_shl(1) ^ 0x1021
            } else {
                crc.wrapping_shl(1)
            };
        }
    }
    bytes.extend(crc.to_le_bytes());
    data_encoding::BASE32_NOPAD.encode(&bytes)
}
#[cfg(unix)]
fn config() -> Value {
    json!({"network":"stellar:testnet","rpcUrl":"https://soroban-testnet.stellar.org","vault":contract(7),"owner":allowit_stellar::account_for_seed(&[1;32]),"executor":allowit_stellar::account_for_seed(&[2;32]),"authority":allowit_stellar::account_for_seed(&[4;32]),"asset":allowit_stellar::USDC_TESTNET,"policy":contract(5),"vaultWasmHash":"11".repeat(32),"policyWasmHash":"22".repeat(32),"policySourceHash":"33".repeat(32)})
}
#[cfg(unix)]
fn import(directory: &Path) -> PathBuf {
    let source = directory.with_extension("config.json");
    std::fs::write(&source, config().to_string()).unwrap();
    let output = run(
        directory,
        &["stellar", "import", source.to_str().unwrap(), "--json"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["executed"],
        false
    );
    source
}
#[cfg(unix)]
#[test]
fn import_is_private_durable_and_refuses_a_different_configuration() {
    use std::os::unix::fs::PermissionsExt;
    let state = temporary();
    let source = import(&state);
    assert_eq!(
        std::fs::metadata(state.join("configuration"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let records: Vec<_> = std::fs::read_dir(state.join("configuration"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|v| v == "json"))
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(
        std::fs::metadata(&records[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut changed = config();
    changed["policySourceHash"] = json!("44".repeat(32));
    std::fs::write(&source, changed.to_string()).unwrap();
    let output = run(&state, &["stellar", "import", source.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("separate state directory")
    );
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir_all(state).unwrap();
}
#[cfg(unix)]
#[test]
fn call_requires_saved_original_plan_and_recovery_never_loads_any_key() {
    let state = temporary();
    let source = import(&state);
    let call = run(
        &state,
        &[
            "stellar",
            "call",
            "https://agent402.tools/api?query=original",
            "--id",
            "purchase-001",
            "--max-amount",
            "0.001",
            "--approval",
            "/must-not-be-read-approval.json",
        ],
    );
    assert_eq!(call.status.code(), Some(3));
    assert!(
        String::from_utf8(call.stderr)
            .unwrap()
            .contains("Prepare this exact Stellar call first")
    );
    for operation in ["resume", "status", "authorize"] {
        let output = run(&state, &["stellar", operation, "purchase-001", "--json"]);
        assert_eq!(output.status.code(), Some(3));
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("No saved Stellar request"));
        assert!(!error.contains("signing key"));
    }
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir_all(state).unwrap();
}

#[cfg(unix)]
mod cooperating {
    use super::*;
    use allowit_stellar::{Config, PreparedPayment, SignedPayment};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        os::unix::fs::PermissionsExt,
        process::{Child, Stdio},
    };
    use stellar_xdr::{Limits, ReadXdr, SequenceNumber, TransactionEnvelope, WriteXdr};

    struct Fixture {
        directory: PathBuf,
        server: Child,
        port: u16,
        source: Value,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = temporary();
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let status = Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=merchant.example",
                    "-addext",
                    "subjectAltName=DNS:merchant.example",
                ])
                .arg("-keyout")
                .arg(directory.join("key.pem"))
                .arg("-out")
                .arg(directory.join("cert.pem"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success());
            let script =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stellar-server.py");
            let mut server = Command::new("python3")
                .arg(script)
                .arg(&directory)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(server.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            let port = line.trim().parse::<u16>().unwrap();
            let mut source: Value = serde_json::from_str(include_str!(
                "../repos/AllowIt-hq--allowit-sdk/stellar-rust/tests/fixtures/x402-vault.json"
            ))
            .unwrap();
            source["config"]["rpcUrl"] = json!(format!("https://merchant.example:{port}/rpc"));
            source["paymentRequired"]["resource"]["url"] =
                json!(format!("https://merchant.example:{port}/api/hash"));
            let config: Config = serde_json::from_value(source["config"].clone()).unwrap();
            source["stateReadTransaction"] =
                json!(allowit_stellar::state_read_transaction(&config).unwrap());
            fs::write(directory.join("config.json"), source["config"].to_string()).unwrap();
            for (file, seed) in [("executor.hex", 2u8), ("authority.hex", 4u8)] {
                let path = directory.join(file);
                fs::write(&path, format!("{seed:02x}").repeat(32)).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let f = Self {
                directory,
                server,
                port,
                source,
            };
            f.save();
            f
        }
        fn save(&self) {
            fs::write(self.directory.join("fixture.json"), self.source.to_string()).unwrap();
        }
        fn url(&self) -> String {
            format!("https://merchant.example:{}/api/hash?text=hi", self.port)
        }
        fn child(&self, args: &[&str], executor: bool, authority: bool) -> Output {
            let mut command = Command::new(std::env::current_exe().unwrap());
            for (name, _) in std::env::vars() {
                if name.starts_with("ALLOWIT_") {
                    command.env_remove(name);
                }
            }
            command
                .args(["--exact", "cooperating::driver", "--nocapture"])
                .env(
                    "ALLOWIT_STELLAR_TEST_DRIVER_ARGS",
                    serde_json::to_string(args).unwrap(),
                )
                .env(
                    "ALLOWIT_STELLAR_TEST_DNS",
                    format!("127.0.0.1:{}", self.port),
                )
                .env("ALLOWIT_STELLAR_STATE_DIR", self.directory.join("state"))
                .env("ALLOWIT_CA_FILE", self.directory.join("cert.pem"))
                .env(
                    "ALLOWIT_STELLAR_EXECUTOR_KEY_FILE",
                    if executor {
                        self.directory.join("executor.hex")
                    } else {
                        self.directory.join("missing-executor")
                    },
                )
                .env(
                    "ALLOWIT_STELLAR_AUTHORITY_KEY_FILE",
                    if authority {
                        self.directory.join("authority.hex")
                    } else {
                        self.directory.join("missing-authority")
                    },
                )
                .env("PATH", "");
            command.output().unwrap()
        }
        fn import(&self) {
            let path = self.directory.join("config.json");
            let out = self.child(&["import", path.to_str().unwrap()], false, false);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        fn prepare(&self, id: &str) -> PreparedPayment {
            let url = self.url();
            let out = self.child(
                &[
                    "prepare",
                    &url,
                    "--id",
                    id,
                    "--max-amount",
                    "0.001",
                    "--json",
                ],
                false,
                false,
            );
            assert_eq!(
                out.status.code(),
                Some(10),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            serde_json::from_value(json_output(&out)["prepared"].clone()).unwrap()
        }
        fn approve(&self, id: &str) -> PathBuf {
            let out = self.child(&["authorize", id], false, true);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let path = self.directory.join(format!("{id}-approval.json"));
            fs::write(&path, json_output(&out).to_string()).unwrap();
            path
        }
        fn bind_receipt(&mut self, prepared: &PreparedPayment) {
            let config = &prepared.config;
            let approval = allowit_stellar::authority_sign(config, prepared, &[4; 32]).unwrap();
            let signed =
                allowit_stellar::sign_payment(config, prepared, &[2; 32], &approval).unwrap();
            self.source["signed"] = serde_json::to_value(&signed).unwrap();
            let mut envelope = TransactionEnvelope::from_xdr_base64(
                &signed.transaction_xdr,
                Limits {
                    depth: 64,
                    len: 1_048_576,
                },
            )
            .unwrap();
            if let TransactionEnvelope::Tx(envelope) = &mut envelope {
                envelope.tx.fee = 2000;
                envelope.tx.seq_num = SequenceNumber(50);
            }
            let hash = allowit_stellar::hex(
                &envelope
                    .hash(allowit_stellar::sha256(
                        allowit_stellar::network_passphrase(&config.network).unwrap(),
                    ))
                    .unwrap(),
            );
            self.source["rpcTransaction"]["envelopeXdr"] = json!(
                envelope
                    .to_xdr_base64(Limits {
                        depth: 64,
                        len: 1_048_576
                    })
                    .unwrap()
            );
            self.source["rpcTransaction"]["txHash"] = json!(hash);
            self.source["paymentResponse"]=json!(STANDARD.encode(serde_json::to_vec(&json!({"success":true,"transaction":hash,"network":config.network,"payer":config.vault})).unwrap()));
            self.save();
        }
        fn paid_count(&self) -> usize {
            fs::read_to_string(self.directory.join("requests.jsonl"))
                .unwrap_or_default()
                .lines()
                .filter(|line| serde_json::from_str::<Value>(line).unwrap()["kind"] == "paid")
                .count()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.server.kill();
            let _ = self.server.wait();
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    fn json_output(out: &Output) -> Value {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|line| {
                serde_json::from_str::<Value>(line)
                    .ok()
                    .filter(|v| v.is_object())
            })
            .unwrap_or_else(|| {
                panic!(
                    "{} {}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
            })
    }

    /// Only this source-identical test driver contains the injected DNS route.
    /// Production binaries have no fixture flag or HTTP transport bypass.
    #[test]
    fn driver() {
        let Ok(args) = std::env::var("ALLOWIT_STELLAR_TEST_DRIVER_ARGS") else {
            return;
        };
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        let mut stdout = String::new();
        let mut stderr = String::new();
        let code = match stellar::run(&args, &mut stdout, &mut stderr) {
            Ok(code) => code,
            Err(error) => {
                stderr += &format!("allowit: {error}\n");
                error.code
            }
        };
        std::io::stdout().write_all(stdout.as_bytes()).unwrap();
        std::io::stderr().write_all(stderr.as_bytes()).unwrap();
        std::process::exit(code);
    }

    #[test]
    fn exact_purchase_query_and_explicit_approval_then_no_paid_replay() {
        let mut fixture = Fixture::new();
        fixture.import();
        let prepared = fixture.prepare("purchase-001");
        assert_eq!(prepared.request.url, fixture.url());
        assert!(prepared.request.body.is_empty());
        let missing = fixture.child(&["authorize", "purchase-001"], false, false);
        assert_eq!(missing.status.code(), Some(3));
        assert!(
            String::from_utf8_lossy(&missing.stderr).contains("designated Stellar signing key")
        );
        let approval = fixture.approve("purchase-001");
        fixture.bind_receipt(&prepared);
        let url = fixture.url();
        let approval = approval.to_str().unwrap();
        let out = fixture.child(
            &[
                "call",
                &url,
                "--id",
                "purchase-001",
                "--max-amount",
                "0.001",
                "--approval",
                approval,
                "--json",
            ],
            true,
            false,
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let result = json_output(&out);
        assert_eq!(result["paymentVerified"], true);
        assert_eq!(result["deliveryAvailable"], true);
        for cmd in ["resume", "status"] {
            let out = fixture.child(&[cmd, "purchase-001", "--json"], false, false);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(json_output(&out)["paymentVerified"], true);
        }
        let replay = fixture.child(
            &[
                "call",
                &url,
                "--id",
                "purchase-001",
                "--max-amount",
                "0.001",
                "--json",
            ],
            false,
            false,
        );
        assert_eq!(replay.status.code(), Some(0));
        assert_eq!(fixture.paid_count(), 1);
        let changed = fixture.child(
            &[
                "call",
                &url,
                "--id",
                "purchase-001",
                "--max-amount",
                "0.002",
                "--json",
            ],
            false,
            false,
        );
        assert_eq!(changed.status.code(), Some(3));
        assert_eq!(fixture.paid_count(), 1);
    }
    #[test]
    fn attempted_timeout_keeps_original_credential_and_never_resends() {
        let mut fixture = Fixture::new();
        fixture.import();
        let prepared = fixture.prepare("purchase-002");
        let approval = fixture.approve("purchase-002");
        fixture.bind_receipt(&prepared);
        fixture.source["timeout"] = json!(true);
        fixture.save();
        let url = fixture.url();
        let out = fixture.child(
            &[
                "call",
                &url,
                "--id",
                "purchase-002",
                "--max-amount",
                "0.001",
                "--approval",
                approval.to_str().unwrap(),
                "--json",
            ],
            true,
            false,
        );
        assert_eq!(out.status.code(), Some(5));
        assert_eq!(fixture.paid_count(), 1);
        for command in ["resume", "status"] {
            let out = fixture.child(&[command, "purchase-002", "--json"], false, false);
            assert_eq!(out.status.code(), Some(5));
            assert_eq!(json_output(&out)["paymentVerified"], false);
        }
        let out = fixture.child(
            &[
                "call",
                &url,
                "--id",
                "purchase-002",
                "--max-amount",
                "0.001",
                "--json",
            ],
            false,
            false,
        );
        assert_eq!(out.status.code(), Some(5));
        assert_eq!(fixture.paid_count(), 1);
        let new = fixture.child(
            &[
                "prepare",
                &url,
                "--id",
                "replacement-01",
                "--max-amount",
                "0.001",
            ],
            false,
            false,
        );
        assert_eq!(new.status.code(), Some(5));
        assert_eq!(fixture.paid_count(), 1);
        let record_path = fixture.directory.join("state/operations").join(format!(
            "request-{}.json",
            allowit_stellar::hex(&allowit_stellar::sha256("purchase-002"))
        ));
        let record: Value = serde_json::from_slice(&fs::read(record_path).unwrap()).unwrap();
        let signed: SignedPayment = serde_json::from_value(record["signed"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(signed).unwrap(),
            fixture.source["signed"]
        );
        assert_eq!(record["attempted"], true);
        let wrong = fixture.child(
            &[
                "resume",
                "purchase-002",
                "--transaction",
                &"00".repeat(32),
                "--json",
            ],
            false,
            false,
        );
        assert_eq!(wrong.status.code(), Some(3));
        assert_eq!(fixture.paid_count(), 1);
        let hash = fixture.source["rpcTransaction"]["txHash"].as_str().unwrap();
        let settled = fixture.child(
            &["resume", "purchase-002", "--transaction", hash, "--json"],
            false,
            false,
        );
        assert_eq!(
            settled.status.code(),
            Some(5),
            "{}",
            String::from_utf8_lossy(&settled.stderr)
        );
        let result = json_output(&settled);
        assert_eq!(result["paymentVerified"], true);
        assert_eq!(result["deliveryAvailable"], false);
        assert_eq!(result["response"], Value::Null);
        let wrong_after = fixture.child(
            &[
                "resume",
                "purchase-002",
                "--transaction",
                &"00".repeat(32),
                "--json",
            ],
            false,
            false,
        );
        assert_eq!(wrong_after.status.code(), Some(3));
        assert_eq!(fixture.paid_count(), 1);
        let status = fixture.child(&["status", "purchase-002", "--json"], false, false);
        assert_eq!(status.status.code(), Some(5));
        assert_eq!(json_output(&status)["paymentVerified"], true);
        let next = fixture.child(
            &[
                "prepare",
                &url,
                "--id",
                "after-proof-01",
                "--max-amount",
                "0.001",
                "--json",
            ],
            false,
            false,
        );
        assert_eq!(
            next.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&next.stderr)
        );
        assert_eq!(fixture.paid_count(), 1);
    }
    #[test]
    fn mutated_approval_and_agent_supplied_body_cannot_reach_paid_http() {
        let fixture = Fixture::new();
        fixture.import();
        fixture.prepare("tamper-request-01");
        let path = fixture.approve("tamper-request-01");
        let mut approval: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        approval["signature"] = json!("00".repeat(64));
        fs::write(&path, approval.to_string()).unwrap();
        let url = fixture.url();
        let output = fixture.child(
            &[
                "call",
                &url,
                "--id",
                "tamper-request-01",
                "--max-amount",
                "0.001",
                "--approval",
                path.to_str().unwrap(),
                "--json",
            ],
            false,
            false,
        );
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(fixture.paid_count(), 0);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("signing key"));
        let record_path = fixture.directory.join("state/operations").join(format!(
            "request-{}.json",
            allowit_stellar::hex(&allowit_stellar::sha256("tamper-request-01"))
        ));
        let mut record: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        record["prepared"]["request"]["body"] = json!([123, 125]);
        fs::write(&record_path, record.to_string()).unwrap();
        let output = fixture.child(
            &[
                "call",
                &url,
                "--id",
                "tamper-request-01",
                "--max-amount",
                "0.001",
                "--approval",
                path.to_str().unwrap(),
            ],
            false,
            false,
        );
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(fixture.paid_count(), 0);
        assert!(String::from_utf8_lossy(&output.stderr).contains("Contradictory Stellar journal"));
    }
    #[test]
    fn executor_seed_cannot_act_as_trusted_authority() {
        let fixture = Fixture::new();
        fixture.import();
        fixture.prepare("key-boundary-01");
        fs::write(fixture.directory.join("authority.hex"), "02".repeat(32)).unwrap();
        let output = fixture.child(&["authorize", "key-boundary-01"], false, true);
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(fixture.paid_count(), 0);
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .all(|line| !line.starts_with('{'))
        );
    }
    #[test]
    fn restoration_preamble_stops_prepare_before_any_key_or_payment() {
        let mut fixture = Fixture::new();
        fixture.import();
        fixture.source["restore"] = json!(true);
        fixture.save();
        let url = fixture.url();
        let output = fixture.child(
            &[
                "prepare",
                &url,
                "--id",
                "restore-request-01",
                "--max-amount",
                "0.001",
                "--json",
            ],
            false,
            false,
        );
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(fixture.paid_count(), 0);
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported restoration"));
    }
}
