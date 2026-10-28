#![cfg(unix)]
use allowit_policy_sdk::typed_workflow::*;
use allowit_stellar_wallet::{self as sdk, *};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use stellar_xdr::{
    Limits, OperationResult, OperationResultTr, PaymentResult, TransactionResult,
    TransactionResultExt, TransactionResultResult, WriteXdr,
};
const POLICY: &str = "stellar-policy";
const ID: &str = "stellar-run-0001";
const CAP: &str = "Bearer stellar-executor.private-test-capability";
fn nonce() -> [u8; 32] {
    let mut v = b"allowit-workflow-operation-v1\0".to_vec();
    v.extend(POLICY.as_bytes());
    v.push(0);
    v.extend(ID.as_bytes());
    sdk::hash(v)
}
fn acct(s: &str) -> AccountId {
    AccountId {
        chain: Chain::Stellar,
        kind: AccountKind::Wallet,
        address: sdk::account_key(s).unwrap(),
    }
}
fn fixture() -> (WalletConfig, ExecutionRequest, TrustedState, u64) {
    let owner = sdk::account_for_seed(&[1; 32]);
    let agent = sdk::account_for_seed(&[2; 32]);
    let engine = sdk::account_for_seed(&[3; 32]);
    let source="use allowit::v1::prelude::*; async fn _execute(ctx:&Context)->PolicyResult { allowit::require_asset(ctx,\"XLM\")?; Ok(()) }".to_string();
    let mut c = WalletConfig {
        network: "stellar:testnet".into(),
        policy_instance: [7; 32],
        wallet: owner.clone(),
        owner: owner.clone(),
        agent: agent.clone(),
        engine: engine.clone(),
        route: WalletRoute::Native,
        asset: String::new(),
        asset_symbol: "XLM".into(),
        asset_issuer: None,
        source_hash: sdk::hash(&source),
        policy_source: source,
        module_digest: [5; 32],
        max_fee_stroops: 50000,
    };
    c.asset = sdk::sac_address(&c.network, &sdk::asset_xdr(&c).unwrap()).unwrap();
    let dest = sdk::account_for_seed(&[6; 32]);
    let asset = WorkflowAsset::Native {
        chain: Chain::Stellar,
        network: sdk::network_id(&c.network).unwrap(),
    };
    let r = ExecutionRequest {
        operation: OperationRef {
            policy_instance: c.policy_instance,
            nonce: nonce(),
        },
        input: ExecutionInput::Instructions(vec![NativeInstruction::StellarNativeTransfer {
            source: acct(&owner),
            destination: acct(&dest),
            stroops: 1_000_000,
        }]),
        effect_bounds: vec![WorkflowEffectBound {
            asset: asset.clone(),
            source: acct(&owner),
            beneficiary: acct(&dest),
            max_debit: 1_000_000u64.into(),
            min_credit: 1_000_000u64.into(),
            max_burn: 0u64.into(),
        }],
        fee_bounds: Some(vec![WorkflowFeeBound {
            payer: acct(&owner),
            asset,
            max_fee: 50000u64.into(),
        }]),
        evidence: vec![],
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let s = TrustedState {
        source: AccountState {
            address: owner.clone(),
            sequence: 40,
            master_weight: 3,
            low_threshold: 2,
            medium_threshold: 2,
            high_threshold: 3,
            signers: vec![
                AccountSigner {
                    key: agent.clone(),
                    weight: 1,
                },
                AccountSigner {
                    key: engine.clone(),
                    weight: 1,
                },
            ],
        },
        nonce: 9,
        revision: 4,
        spent_daily: 0,
        spent_total: 0,
        spent_day: now / 86400,
        calls: 0,
        ledger: 100,
        module_digest: c.module_digest,
        source_hash: c.source_hash,
        owner,
        agent,
        engine,
        policy_instance: c.policy_instance,
    };
    (c, r, s, now)
}
fn seed_text() -> String {
    let mut raw = vec![144];
    raw.extend([2; 32]);
    let mut crc = 0u16;
    for b in &raw {
        crc ^= (*b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    raw.extend(crc.to_le_bytes());
    data_encoding::BASE32_NOPAD.encode(&raw)
}
fn private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn root() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "allowit-stellar-cli-{}-{}-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&p).unwrap();
    p
}
fn setup(c: &WalletConfig, r: &ExecutionRequest) -> PathBuf {
    let p = root();
    private(&p.join("bundle.json"),&json!({"version":1,"profile":PROFILE,"network":c.network,"policyId":POLICY,"sourceHash":sdk::hex(&c.source_hash),"irHash":sdk::hex(&[4;32]),"moduleDigest":sdk::hex(&c.module_digest),"wallet":c.wallet,"route":c.route,"config":c,"endpoints":{"execute":"/api/native/execute","status":"/api/native/execute/status"},"authorization":CAP}).to_string());
    private(&p.join("signer"), &seed_text());
    std::fs::write(
        p.join("request.json"),
        json!({"requestId":ID,"input":{"kind":"execution-request","request":r}}).to_string(),
    )
    .unwrap();
    p
}
fn run(p: &Path, url: &str, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_allowit"));
    for (k, _) in std::env::vars() {
        if k.starts_with("ALLOWIT_") {
            c.env_remove(k);
        }
    }
    c.args(args)
        .env("ALLOWIT_URL", url)
        .env("ALLOWIT_STELLAR_BUNDLE", p.join("bundle.json"))
        .env("ALLOWIT_STELLAR_SIGNER", p.join("signer"))
        .env("ALLOWIT_STELLAR_STATE_DIR", p.join("journal"))
        .output()
        .unwrap()
}
fn read(stream: &mut TcpStream) -> (String, Value) {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut h = vec![];
    let mut b = [0];
    while !h.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut b).unwrap();
        h.push(b[0]);
    }
    let h = String::from_utf8(h).unwrap();
    assert!(
        h.to_ascii_lowercase()
            .contains(&format!("authorization: {}", CAP.to_ascii_lowercase()))
    );
    let n = h
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|v| v.parse::<usize>().ok())
        })
        .unwrap();
    let mut body = vec![0; n];
    stream.read_exact(&mut body).unwrap();
    (h, serde_json::from_slice(&body).unwrap())
}
fn reply(s: &mut TcpStream, v: Value) {
    let body = v.to_string();
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .unwrap();
}
fn response(p: &PreparedOperation, s: Option<&SignedOperation>, status: &str) -> Value {
    let receipt = if status == "confirmed" {
        s.map(|signed| {
            let result = TransactionResult {
                fee_charged: 100,
                result: TransactionResultResult::TxSuccess(
                    vec![OperationResult::OpInner(OperationResultTr::Payment(
                        PaymentResult::Success,
                    ))]
                    .try_into()
                    .unwrap(),
                ),
                ext: TransactionResultExt::V0,
            };
            sdk::rpc::VerifiedReceipt {
                transaction_hash: signed.transaction_hash,
                status: OperationStatus::Confirmed,
                ledger: 777,
                envelope_xdr: signed.transaction_xdr.clone(),
                result_xdr: result.to_xdr_base64(Limits::none()).unwrap(),
            }
        })
    } else {
        None
    };
    json!({"prepared":p,"operation":{"id":ID,"status":status,"transactionHash":sdk::hex(&p.transaction_hash)},"signedOperation":s,"receipt":receipt})
}
#[test]
fn two_phase_exec_verifies_real_signatures_and_unknown_retry_only_recovers() {
    let (c, r, s, now) = fixture();
    let path = setup(&c, &r);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let request = r.clone();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let (h, b) = read(&mut conn);
        assert!(h.starts_with("POST /api/native/execute "));
        assert_eq!(
            b,
            json!({"policyId":POLICY,"requestId":ID,"phase":"prepare","request":request})
        );
        let expires = (now + 120).min((now / 86400 + 1) * 86400 - 1);
        let prepared = sdk::prepare(&c, &request, &s, now, expires).unwrap();
        reply(&mut conn, response(&prepared, None, "prepared"));
        let (mut conn, _) = listener.accept().unwrap();
        let (_, b) = read(&mut conn);
        let signature: DetachedSignature =
            serde_json::from_value(b["agentSignature"].clone()).unwrap();
        assert_eq!(b.as_object().unwrap().len(), 4);
        assert_eq!(b["phase"], "submit");
        let engine = sdk::sign(&prepared, &[3; 32], now).unwrap();
        let signed = sdk::authorize(&prepared, &[signature, engine], now).unwrap();
        sdk::validate_signed(&signed, now).unwrap();
        drop(conn); // broadcast receipt lost
        let (mut conn, _) = listener.accept().unwrap();
        let (h, b) = read(&mut conn);
        assert!(h.starts_with("POST /api/native/execute/status "));
        assert_eq!(b, json!({"policyId":POLICY,"requestId":ID}));
        reply(&mut conn, response(&prepared, Some(&signed), "confirmed"));
    });
    let req = path.join("request.json");
    let args = [
        "exec",
        POLICY,
        "--request-file",
        req.to_str().unwrap(),
        "--wait",
        "0s",
    ];
    let first = run(&path, &url, &args);
    assert_eq!(
        first.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    std::fs::remove_file(path.join("signer")).unwrap();
    let recovered = run(&path, &url, &args);
    assert_eq!(
        recovered.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let output = String::from_utf8_lossy(&recovered.stdout);
    assert!(output.contains("confirmed"));
    assert!(!output.contains(CAP));
    assert!(!output.contains(&seed_text()));
    for entry in std::fs::read_dir(path.join("journal")).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_file() {
            let text = std::fs::read_to_string(entry.path()).unwrap();
            assert!(!text.contains(CAP));
            assert!(!text.contains(&seed_text()));
        }
    }
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn changed_prepared_request_never_reaches_signing_or_submit() {
    let (c, r, s, now) = fixture();
    let path = setup(&c, &r);
    std::fs::remove_file(path.join("signer")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        read(&mut conn);
        let p = sdk::prepare(
            &c,
            &r,
            &s,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        let mut v = response(&p, None, "prepared");
        v["prepared"]["request"]["operation"]["nonce"][0] = json!(99);
        reply(&mut conn, v);
    });
    let req = path.join("request.json");
    let output = run(
        &path,
        &url,
        &[
            "exec",
            POLICY,
            "--request-file",
            req.to_str().unwrap(),
            "--wait",
            "0s",
        ],
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&output.stderr).contains("identity"));
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn unsafe_bundle_permissions_and_scalar_requests_fail_before_network() {
    let (c, r, _, _) = fixture();
    let path = setup(&c, &r);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::fs::set_permissions(
        path.join("bundle.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let output = run(
        &path,
        &url,
        &[
            "exec",
            POLICY,
            "--request-file",
            path.join("request.json").to_str().unwrap(),
        ],
    );
    assert_eq!(output.status.code(), Some(3));
    std::fs::set_permissions(
        path.join("bundle.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let output = run(&path, &url, &["exec", POLICY, "--action", "transfer"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn substituted_receipt_never_becomes_a_confirmed_cli_result() {
    let (c, r, s, now) = fixture();
    let path = setup(&c, &r);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        read(&mut conn);
        let p = sdk::prepare(
            &c,
            &r,
            &s,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        let mut value = response(&p, None, "prepared");
        value["receipt"] = json!({"transactionHash":vec![0u8;32],"status":"confirmed","ledger":777,"envelopeXdr":"substituted","resultXdr":"substituted"});
        reply(&mut conn, value);
    });
    let output = run(
        &path,
        &url,
        &[
            "exec",
            POLICY,
            "--request-file",
            path.join("request.json").to_str().unwrap(),
            "--wait",
            "0s",
        ],
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("receipt"));
    assert!(output.stdout.is_empty());
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn signed_packet_without_terminal_receipt_never_proves_settlement() {
    let (c, r, s, now) = fixture();
    let path = setup(&c, &r);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let (head, body) = read(&mut conn);
        assert!(head.starts_with("POST /api/native/execute/status "));
        assert_eq!(body["requestId"], ID);
        let prepared = sdk::prepare(
            &c,
            &r,
            &s,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        let signed = sdk::authorize(
            &prepared,
            &[
                sdk::sign(&prepared, &[2; 32], now).unwrap(),
                sdk::sign(&prepared, &[3; 32], now).unwrap(),
            ],
            now,
        )
        .unwrap();
        let mut value = response(&prepared, Some(&signed), "confirmed");
        value["receipt"] = Value::Null;
        reply(&mut conn, value);
    });
    let output = run(&path, &url, &["status", POLICY, ID, "--wait", "0s"]);
    assert_eq!(output.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&output.stderr).contains("verified chain receipt"));
    assert!(output.stdout.is_empty());
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

fn reply_error(stream: &mut TcpStream, status: u16) {
    let body = "{\"error\":\"fixture rejected before signing\"}";
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
}
fn signed_from_submit(
    stream: &mut TcpStream,
    prepared: &PreparedOperation,
    now: u64,
) -> SignedOperation {
    let (head, body) = read(stream);
    assert!(head.starts_with("POST /api/native/execute "));
    assert_eq!(body["policyId"], POLICY);
    assert_eq!(body["requestId"], ID);
    assert_eq!(body["phase"], "submit");
    assert_eq!(body.as_object().unwrap().len(), 4);
    let agent: DetachedSignature = serde_json::from_value(body["agentSignature"].clone()).unwrap();
    sdk::authorize(
        prepared,
        &[agent, sdk::sign(prepared, &[3; 32], now).unwrap()],
        now,
    )
    .unwrap()
}
#[test]
fn never_prepared_intent_retries_only_same_identity_after_status_404() {
    let (c, request, state, now) = fixture();
    let path = setup(&c, &request);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        let (head, original) = read(&mut first);
        assert!(head.starts_with("POST /api/native/execute "));
        assert_eq!(original["phase"], "prepare");
        reply_error(&mut first, 409);
        let (mut status, _) = listener.accept().unwrap();
        let (head, body) = read(&mut status);
        assert!(head.starts_with("POST /api/native/execute/status "));
        assert_eq!(body, json!({"policyId":POLICY,"requestId":ID}));
        reply_error(&mut status, 404);
        let (mut retry, _) = listener.accept().unwrap();
        let (_, body) = read(&mut retry);
        assert_eq!(body, original);
        let prepared = sdk::prepare(
            &c,
            &request,
            &state,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        reply(&mut retry, response(&prepared, None, "prepared"));
        let (mut submit, _) = listener.accept().unwrap();
        let signed = signed_from_submit(&mut submit, &prepared, now);
        reply(&mut submit, response(&prepared, Some(&signed), "confirmed"));
    });
    let request = path.join("request.json");
    let args = [
        "exec",
        POLICY,
        "--request-file",
        request.to_str().unwrap(),
        "--wait",
        "0s",
    ];
    assert_eq!(run(&path, &url, &args).status.code(), Some(4));
    let out = run(&path, &url, &args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn unsigned_prepared_resumes_exact_packet_only_on_explicit_exec() {
    let (c, request, state, now) = fixture();
    let path = setup(&c, &request);
    std::fs::remove_file(path.join("signer")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let prepared = sdk::prepare(
            &c,
            &request,
            &state,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        let (mut first, _) = listener.accept().unwrap();
        let (_, body) = read(&mut first);
        assert_eq!(body["phase"], "prepare");
        reply(&mut first, response(&prepared, None, "prepared"));
        for _ in 0..2 {
            let (mut status, _) = listener.accept().unwrap();
            let (head, body) = read(&mut status);
            assert!(head.starts_with("POST /api/native/execute/status "));
            assert_eq!(body, json!({"policyId":POLICY,"requestId":ID}));
            reply(&mut status, response(&prepared, None, "prepared"));
        }
        let (mut submit, _) = listener.accept().unwrap();
        let signed = signed_from_submit(&mut submit, &prepared, now);
        reply(&mut submit, response(&prepared, Some(&signed), "confirmed"));
    });
    let request = path.join("request.json");
    let args = [
        "exec",
        POLICY,
        "--request-file",
        request.to_str().unwrap(),
        "--wait",
        "0s",
    ];
    assert_eq!(run(&path, &url, &args).status.code(), Some(3));
    assert_eq!(
        run(&path, &url, &["status", POLICY, ID, "--wait", "0s"])
            .status
            .code(),
        Some(12)
    );
    private(&path.join("signer"), &seed_text());
    let out = run(&path, &url, &args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn retained_unsigned_prepared_is_never_replaced_after_status_404() {
    let (c, request, state, now) = fixture();
    let path = setup(&c, &request);
    std::fs::remove_file(path.join("signer")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let prepared = sdk::prepare(
            &c,
            &request,
            &state,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        let (mut first, _) = listener.accept().unwrap();
        read(&mut first);
        reply(&mut first, response(&prepared, None, "prepared"));
        let (mut status, _) = listener.accept().unwrap();
        let (head, _) = read(&mut status);
        assert!(head.starts_with("POST /api/native/execute/status "));
        reply_error(&mut status, 404);
    });
    let request = path.join("request.json");
    let args = [
        "exec",
        POLICY,
        "--request-file",
        request.to_str().unwrap(),
        "--wait",
        "0s",
    ];
    assert_eq!(run(&path, &url, &args).status.code(), Some(3));
    private(&path.join("signer"), &seed_text());
    assert_eq!(run(&path, &url, &args).status.code(), Some(4));
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn unsigned_resume_rejects_changed_server_packet_before_signing() {
    let (c, request, state, now) = fixture();
    let path = setup(&c, &request);
    std::fs::remove_file(path.join("signer")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let prepared = sdk::prepare(
            &c,
            &request,
            &state,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        let (mut first, _) = listener.accept().unwrap();
        read(&mut first);
        reply(&mut first, response(&prepared, None, "prepared"));
        let mut changed = state;
        changed.source.sequence += 1;
        let changed = sdk::prepare(
            &c,
            &request,
            &changed,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        let (mut status, _) = listener.accept().unwrap();
        let (head, _) = read(&mut status);
        assert!(head.starts_with("POST /api/native/execute/status "));
        reply(&mut status, response(&changed, None, "prepared"));
    });
    let request = path.join("request.json");
    let args = [
        "exec",
        POLICY,
        "--request-file",
        request.to_str().unwrap(),
        "--wait",
        "0s",
    ];
    assert_eq!(run(&path, &url, &args).status.code(), Some(3));
    private(&path.join("signer"), &seed_text());
    let out = run(&path, &url, &args);
    assert_eq!(out.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&out.stderr).contains("identity"));
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn imported_unknown_signed_operation_never_authorizes_from_unsigned_local_state() {
    let (c, request, state, now) = fixture();
    let path = setup(&c, &request);
    std::fs::remove_file(path.join("signer")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let prepared = sdk::prepare(
            &c,
            &request,
            &state,
            now,
            (now + 120).min((now / 86400 + 1) * 86400 - 1),
        )
        .unwrap();
        let signed = sdk::authorize(
            &prepared,
            &[
                sdk::sign(&prepared, &[2; 32], now).unwrap(),
                sdk::sign(&prepared, &[3; 32], now).unwrap(),
            ],
            now,
        )
        .unwrap();
        for status in ["submissionUnknown", "confirmed"] {
            let (mut conn, _) = listener.accept().unwrap();
            let (head, body) = read(&mut conn);
            assert!(head.starts_with("POST /api/native/execute/status "));
            assert_eq!(body, json!({"policyId":POLICY,"requestId":ID}));
            reply(&mut conn, response(&prepared, Some(&signed), status));
        }
    });
    assert_eq!(
        run(&path, &url, &["status", POLICY, ID, "--wait", "0s"])
            .status
            .code(),
        Some(5)
    );
    let request = path.join("request.json");
    let out = run(
        &path,
        &url,
        &[
            "exec",
            POLICY,
            "--request-file",
            request.to_str().unwrap(),
            "--wait",
            "0s",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn expired_unsigned_packet_observation_prevents_repreparation_after_404() {
    let (c, request, mut state, now) = fixture();
    let path = setup(&c, &request);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let created = (now / 86400 - 1) * 86400 + 1;
        state.spent_day = created / 86400;
        let prepared = sdk::prepare(&c, &request, &state, created, created + 120).unwrap();
        let (mut first, _) = listener.accept().unwrap();
        read(&mut first);
        drop(first);
        let (mut status, _) = listener.accept().unwrap();
        let (head, _) = read(&mut status);
        assert!(head.starts_with("POST /api/native/execute/status "));
        reply(&mut status, response(&prepared, None, "prepared"));
        let (mut status, _) = listener.accept().unwrap();
        let (head, _) = read(&mut status);
        assert!(head.starts_with("POST /api/native/execute/status "));
        reply_error(&mut status, 404);
    });
    let request = path.join("request.json");
    let args = [
        "exec",
        POLICY,
        "--request-file",
        request.to_str().unwrap(),
        "--wait",
        "0s",
    ];
    assert_eq!(run(&path, &url, &args).status.code(), Some(5));
    let expired = run(&path, &url, &args);
    assert_eq!(expired.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&expired.stderr).contains("stale"));
    assert_eq!(run(&path, &url, &args).status.code(), Some(4));
    server.join().unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
