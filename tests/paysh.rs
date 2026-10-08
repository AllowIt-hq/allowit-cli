//! Process-level PaySH agent command checks against a loopback server: exact
//! method, route and body, capability-only auth, single attempt, bounded I/O,
//! secret redaction and exit codes.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Command, Output},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const POLICY: &str = "abababababababababababababababababababababababababababababababab";
const TOKEN: &str = "capability-0123456789abcdefghijklmnopqrstuvwxyz";
const SERVICE: &str = "solana-foundation/google/airquality";
const INPUT: &str = r#"{"location":{"latitude":43.6532,"longitude":-79.3832},"universalAqi":true}"#;

#[derive(Debug)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// Serves `replies` in order, then keeps listening briefly so a retry would be seen.
fn serve(replies: Vec<String>) -> (String, mpsc::Receiver<Vec<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut seen = vec![];
        let mut idle = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline
            && (seen.len() < replies.len() || idle.elapsed() < Duration::from_millis(600))
        {
            let Ok((conn, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            conn.set_nonblocking(false).unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut parts = line.split_whitespace();
            let (method, path) = (
                parts.next().unwrap().to_string(),
                parts.next().unwrap().to_string(),
            );
            let mut headers = vec![];
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                let h = h.trim_end();
                if h.is_empty() {
                    break;
                }
                let (k, v) = h.split_once(':').unwrap();
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            let size = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.parse().unwrap())
                .unwrap_or(0);
            let mut body = vec![0; size];
            reader.read_exact(&mut body).unwrap();
            let reply = replies.get(seen.len()).cloned().unwrap_or_else(|| {
                http(
                    500,
                    &json!({"error":"unexpected extra request"}).to_string(),
                )
            });
            let mut conn = conn;
            let _ = conn.write_all(reply.as_bytes());
            seen.push(Seen {
                method,
                path,
                headers,
                body,
            });
            idle = Instant::now();
        }
        tx.send(seen).unwrap();
    });
    (url, rx)
}
fn http(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
fn run(url: &str, args: &[&str], token: Option<&str>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_allowit"));
    for (name, _) in std::env::vars() {
        if name.starts_with("ALLOWIT_") {
            c.env_remove(name);
        }
    }
    c.env("ALLOWIT_URL", url);
    if let Some(t) = token {
        c.env("ALLOWIT_PAYSH_TOKEN", t);
    }
    c.args(args).output().unwrap()
}
fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}
fn op(status: &str) -> Value {
    json!({"operationId":"op-1","status":status,"signatures":["sigA","sigB"],"receipts":[],"response":null})
}

#[test]
fn call_posts_the_exact_request_with_only_the_capability() {
    let delivered = json!({"operationId":"op-1","status":"delivered","signatures":["sigA","sigB"],"receipts":[
        {"signature":"sigA","requestHash":"h","challengeHash":"c","invocationIndex":2,"finalizedSlot":7,"action":{"type":"swap","amountInLamports":1200,"minOutUsdc":1000}},
        {"signature":"sigB","requestHash":"h","challengeHash":"c","invocationIndex":2,"finalizedSlot":9,"action":{"type":"pay","amountUsdc":1000}}],
        "response":{"indexes":[{"aqi":42}]}});
    let (url, seen) = serve(vec![http(200, &delivered.to_string())]);
    let out = run(
        &url,
        &["paysh", "call", POLICY, "op-1", SERVICE, INPUT],
        Some(TOKEN),
    );
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    let seen = seen.recv().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", "/api/paysh/call")
    );
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(seen[0].header("cookie"), None);
    assert_eq!(seen[0].header("content-type"), Some("application/json"));
    assert_eq!(
        seen[0].json(),
        json!({"policyId":POLICY,"operationId":"op-1","serviceId":SERVICE,"input":serde_json::from_str::<Value>(INPUT).unwrap()})
    );
    assert!(stdout.contains("state: delivered"));
    assert!(stdout.contains("payment: finalized"));
    assert!(stdout.contains(
        "swap 1200 lamports in, at least 1000 test-token units out; slot 7; signature sigA"
    ));
    assert!(stdout.contains("pay 1000 test-token units; slot 9; signature sigB"));
    assert!(stdout.contains("delivery: delivered"));
    assert!(stdout.contains("\"aqi\": 42"));
    assert!(stderr.contains("allowit paysh status"));
}

#[test]
fn status_posts_policy_and_operation_and_reports_pending() {
    let (url, seen) = serve(vec![http(200, &op("submitted").to_string())]);
    let out = run(
        &url,
        &["paysh", "status", POLICY, "op-1", "--json"],
        Some(TOKEN),
    );
    assert_eq!(out.status.code(), Some(12));
    let seen = seen.recv().unwrap();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", "/api/paysh/status")
    );
    assert_eq!(
        seen[0].json(),
        json!({"policyId":POLICY,"operationId":"op-1"})
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (v["state"].as_str(), v["exitCode"].as_i64()),
        (Some("pending"), Some(12))
    );
}

#[test]
fn only_delivery_exits_zero() {
    for (status, code) in [
        ("evaluating", 12),
        ("signed", 12),
        ("confirmed", 12),
        ("delivering", 12),
        ("delivered", 0),
        ("denied", 20),
        ("failed", 20),
        ("unknown", 5),
        ("settlement_unknown", 5),
        ("absent", 5),
        ("settled", 5),
    ] {
        let (url, _) = serve(vec![http(200, &op(status).to_string())]);
        let out = run(&url, &["paysh", "status", POLICY, "op-1"], Some(TOKEN));
        assert_eq!(out.status.code(), Some(code), "{status}: {:?}", text(&out));
    }
    let (url, _) = serve(vec![http(200, &op("delivering").to_string())]);
    let (stdout, _) = text(&run(
        &url,
        &["paysh", "status", POLICY, "op-1"],
        Some(TOKEN),
    ));
    assert!(stdout.contains("no finalized payment receipt is available"));
    assert!(!stdout.contains("payment: finalized"));
    assert!(stdout.contains("no refund is reported"));
}

#[test]
fn an_owner_resolved_unknown_delivery_is_neither_failed_nor_delivered() {
    let unknown = json!({"operationId":"op-1","status":"unknown","signatures":["sigB"],"receipts":[
        {"signature":"sigB","requestHash":"h","challengeHash":"c","invocationIndex":0,"finalizedSlot":9,"action":{"type":"pay","amountUsdc":1000}}],
        "response":null});
    let (url, seen) = serve(vec![http(200, &unknown.to_string())]);
    let out = run(&url, &["paysh", "status", POLICY, "op-1"], Some(TOKEN));
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(5), "{stdout}{stderr}");
    assert_eq!(seen.recv().unwrap().len(), 1);
    assert!(stdout.contains("state: unknown"));
    assert!(stdout.contains("payment: finalized"));
    assert!(stdout.contains("pay 1000 test-token units; slot 9; signature sigB"));
    assert!(stdout.contains("neither failed nor delivered"));
    assert!(!stdout.contains("delivery: delivered") && !stdout.contains("response:"));
    assert!(stdout.contains("Never create a replacement payment"));
    let (url, _) = serve(vec![http(200, &unknown.to_string())]);
    let out = run(
        &url,
        &["paysh", "status", POLICY, "op-1", "--json"],
        Some(TOKEN),
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (
            v["state"].as_str(),
            v["exitCode"].as_i64(),
            out.status.code()
        ),
        (Some("unknown"), Some(5), Some(5))
    );
}

#[test]
fn unknown_results_are_never_retried_and_keep_the_operation_id() {
    for reply in [
        http(502, r#"{"error":"Backend reply unavailable."}"#),
        http(400, r#"{"error":"Unverified refusal."}"#),
        http(403, r#"{"error":"Capability rejected after a previous timeout."}"#),
        "HTTP/1.1 307 X\r\nLocation: https://elsewhere.example/api/paysh/call\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
        http(200, "not json"),
        http(200, &json!({"operationId":"op-2","status":"delivered"}).to_string()),
        http(409, r#"{"error":"Operation ID already binds a different request."}"#),
    ] {
        let (url, seen) = serve(vec![reply.clone()]);
        let out = run(&url, &["paysh", "call", POLICY, "op-1", SERVICE, INPUT], Some(TOKEN));
        let (_, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(5), "{reply}: {stderr}");
        assert_eq!(seen.recv().unwrap().len(), 1, "retried after {reply}");
        assert!(stderr.contains(&format!("allowit paysh status {POLICY} op-1")), "{stderr}");
        assert!(stderr.contains("Do not retry with a new OPERATION_ID"), "{stderr}");
    }
}

#[test]
fn an_untyped_http_refusal_cannot_prove_no_payment() {
    let (url, _) = serve(vec![http(
        403,
        r#"{"error":"Swap quote exceeds the policy."}"#,
    )]);
    let out = run(
        &url,
        &["paysh", "call", POLICY, "op-1", SERVICE, INPUT],
        Some(TOKEN),
    );
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(5));
    assert!(stderr.contains("Swap quote exceeds the policy."));
    assert!(!stdout.contains("Nothing was paid"));
    assert!(stderr.contains("Do not retry with a new OPERATION_ID"));
}

#[test]
fn the_capability_is_redacted_even_when_echoed() {
    let echoed =
        json!({"operationId":"op-1","status":"delivered","receipts":[],"response":{"echo":TOKEN}});
    let (url, _) = serve(vec![http(200, &echoed.to_string())]);
    let out = run(
        &url,
        &["paysh", "call", POLICY, "op-1", SERVICE, INPUT],
        Some(TOKEN),
    );
    let (stdout, stderr) = text(&out);
    assert!(!stdout.contains(TOKEN) && !stderr.contains(TOKEN));
    assert!(stdout.contains("[redacted]"));
    let (url, _) = serve(vec![http(
        401,
        &json!({"error":format!("bad token {TOKEN}")}).to_string(),
    )]);
    let out = run(&url, &["paysh", "status", POLICY, "op-1"], Some(TOKEN));
    let (stdout, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(3));
    assert!(!stdout.contains(TOKEN) && !stderr.contains(TOKEN));
}

#[test]
fn services_reads_the_catalog_without_credentials() {
    let catalog = json!({"providers":[{"fqn":SERVICE,"title":"Air Quality API","min_price_usd":0.001,"max_price_usd":0.001}]});
    let (url, seen) = serve(vec![http(200, &catalog.to_string())]);
    let out = run(&url, &["paysh", "services"], Some(TOKEN));
    let (stdout, _) = text(&out);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout, format!("{SERVICE}\tAir Quality API\t0.001 USD\n"));
    let seen = seen.recv().unwrap();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("GET", "/api/paysh/catalog")
    );
    assert_eq!(seen[0].header("authorization"), None);
}

#[test]
fn rejects_unsafe_configuration_and_unbounded_input_before_any_request() {
    let (url, seen) = serve(vec![]);
    let big = format!(r#"{{"x":"{}"}}"#, "a".repeat(5000));
    for (args, token, code) in [
        (
            vec!["paysh", "call", POLICY, "op-1", SERVICE, INPUT],
            None,
            3,
        ),
        (
            vec!["paysh", "call", POLICY, "op-1", SERVICE, INPUT],
            Some("short"),
            3,
        ),
        (
            vec!["paysh", "call", POLICY, "op 1", SERVICE, INPUT],
            Some(TOKEN),
            2,
        ),
        (
            vec!["paysh", "call", "ABAB", "op-1", SERVICE, INPUT],
            Some(TOKEN),
            2,
        ),
        (
            vec!["paysh", "call", POLICY, "op-1", SERVICE, "{not json"],
            Some(TOKEN),
            2,
        ),
        (
            vec!["paysh", "call", POLICY, "op-1", SERVICE, big.as_str()],
            Some(TOKEN),
            2,
        ),
        (
            vec!["paysh", "call", POLICY, "op-1", SERVICE],
            Some(TOKEN),
            2,
        ),
        (
            vec!["paysh", "status", POLICY, "op-1", "--wait"],
            Some(TOKEN),
            2,
        ),
    ] {
        let out = run(&url, &args, token);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {:?}", text(&out));
    }
    assert!(seen.recv().unwrap().is_empty());
    for origin in [
        "http://example.com",
        "https://user@example.com",
        "https://example.com/api",
    ] {
        let out = run(origin, &["paysh", "status", POLICY, "op-1"], Some(TOKEN));
        assert_eq!(out.status.code(), Some(3), "{origin}");
    }
}

#[test]
fn an_oversized_reply_is_an_unknown_result() {
    let huge = format!(
        r#"{{"operationId":"op-1","status":"delivered","response":"{}"}}"#,
        "a".repeat((1 << 20) + 10)
    );
    let (url, _) = serve(vec![http(200, &huge)]);
    let out = run(&url, &["paysh", "status", POLICY, "op-1"], Some(TOKEN));
    assert_eq!(out.status.code(), Some(5));
    assert!(text(&out).1.contains("1 MB"));
}

#[test]
fn help_lists_the_paysh_commands() {
    let out = run("https://example.com", &["paysh", "help"], None);
    let (stdout, _) = text(&out);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout.contains("allowit paysh call POLICY OPERATION_ID SERVICE_ID INPUT_JSON"));
    assert!(stdout.contains("ALLOWIT_PAYSH_TOKEN"));
}

#[test]
fn settlement_and_owner_unknown_do_not_claim_payment_finality_from_a_nonce_or_swap() {
    for status in ["settlement_unknown", "unknown"] {
        for receipts in [
            json!([]),
            json!([{"signature":"swapSig","requestHash":"h","challengeHash":"c","invocationIndex":0,"finalizedSlot":9,"action":{"type":"swap","amountInLamports":1000,"minOutUsdc":990}}]),
        ] {
            let reply = json!({"operationId":"op-1","status":status,"signatures":["unlocated"],"receipts":receipts,"response":null});
            let (url, seen) = serve(vec![http(200, &reply.to_string())]);
            let out = run(&url, &["paysh", "status", POLICY, "op-1"], Some(TOKEN));
            let (stdout, stderr) = text(&out);
            assert_eq!(out.status.code(), Some(5), "{stdout}{stderr}");
            assert_eq!(seen.recv().unwrap().len(), 1);
            assert!(stdout.contains("payment: unresolved"), "{stdout}");
            assert!(!stdout.contains("payment: finalized"));
            assert!(!stdout.contains("payment is finalized"));
            assert!(stdout.contains("Never retry or create a replacement payment"));
            assert!(stdout.contains("unverified signature unlocated"));
        }
    }
}

#[test]
fn json_payment_finality_is_derived_from_receipts_and_failed_payments_remain_unknown() {
    for (phase, receipts, paid, exit) in [
        ("delivered", json!([]), false, 0),
        (
            "failed",
            json!([{"signature":"paySig","finalizedSlot":9,"action":{"type":"pay","amountUsdc":1000}}]),
            true,
            5,
        ),
        (
            "delivered",
            json!([{"signature":"swapSig","finalizedSlot":9,"action":{"type":"swap"}}]),
            false,
            0,
        ),
    ] {
        let reply =
            json!({"operationId":"op-1","status":phase,"receipts":receipts,"response":null});
        let (url, _) = serve(vec![http(200, &reply.to_string())]);
        let out = run(
            &url,
            &["paysh", "status", POLICY, "op-1", "--json"],
            Some(TOKEN),
        );
        assert_eq!(out.status.code(), Some(exit));
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(value["paymentFinalized"], json!(paid));
        if phase == "failed" {
            assert_eq!(value["state"], "unknown");
        }
    }
}
