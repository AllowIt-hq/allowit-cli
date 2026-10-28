//! Public command contracts. Mock backends and native programs never move funds.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Command, Output},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const DIRECT: &str = "direct-account-test-capability-0123456789";
const POLICY_TOKEN: &str = "owner.policy.policy-test-secret-0123456789";
const SELECTOR: &str = "v1@GACCOUNT";
const OP: &str = "compat-operation-0001";

struct Seen {
    method: String,
    path: String,
    authorization: String,
    body: Value,
}
fn response(status: u16, value: Value) -> String {
    let body = value.to_string();
    format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
fn serve(replies: Vec<String>) -> (String, mpsc::Receiver<Vec<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut seen = Vec::new();
        let end = Instant::now() + Duration::from_secs(4);
        let mut last = Instant::now();
        while Instant::now() < end
            && (seen.len() < replies.len() || last.elapsed() < Duration::from_millis(150))
        {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(5));
                continue;
            };
            // macOS can inherit the listener's nonblocking flag on accepted sockets.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut read = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            read.read_line(&mut first).unwrap();
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap().to_owned();
            let path = parts.next().unwrap().to_owned();
            let mut length = 0;
            let mut authorization = String::new();
            loop {
                let mut line = String::new();
                read.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
                let (name, value) = line.split_once(':').unwrap();
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap();
                }
                if name.eq_ignore_ascii_case("authorization") {
                    authorization = value.trim().to_owned();
                }
            }
            assert!(length < 100_000);
            let mut bytes = vec![0; length];
            read.read_exact(&mut bytes).unwrap();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let reply = replies
                .get(seen.len())
                .cloned()
                .unwrap_or_else(|| response(500, json!({"error":"unexpected request"})));
            stream.write_all(reply.as_bytes()).unwrap();
            seen.push(Seen {
                method,
                path,
                authorization,
                body,
            });
            last = Instant::now();
        }
        tx.send(seen).unwrap();
    });
    (origin, rx)
}
fn command(origin: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_allowit"));
    for (key, _) in std::env::vars() {
        if key.starts_with("ALLOWIT_") {
            c.env_remove(key);
        }
    }
    c.env("ALLOWIT_URL", origin)
        .env("ALLOWIT_ACCOUNT_TOKEN", DIRECT)
        .env("ALLOWIT_TOKEN", POLICY_TOKEN);
    c
}
fn run(origin: &str, args: &[&str]) -> Output {
    command(origin).args(args).output().unwrap()
}
fn quote() -> Value {
    json!({"operationId":OP,"quoteId":"quote-1","expiresAt":"2099-01-01T00:00:00Z","requestDigest":"request-digest","maxDebitMoney":{"currency":"USD","amount":"0.01"},"state":"quoted"})
}
fn delivered() -> Value {
    json!({"operationId":OP,"state":"delivered","result":{"status":200,"headers":[],"body":"paid-result"}})
}
fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn root_help_exposes_the_selected_command_groups() {
    let out = run("http://127.0.0.1:9", &["--help"]);
    assert!(out.status.success(), "{}", text(&out));
    for group in [
        "curl",
        "wget",
        "http",
        "claude",
        "codex",
        "whoami",
        "server",
        "gate",
        "catalog",
        "mcp",
        "skills",
        "topup",
        "account",
        "setup",
        "send",
        "subscriptions",
        "fetch",
        "install",
    ] {
        assert!(text(&out).contains(group), "missing {group}");
    }
}

#[test]
fn plain_call_uses_only_direct_authority_and_one_bound_quote() {
    let (url, seen) = serve(vec![response(200, quote()), response(200, delivered())]);
    let out = run(
        &url,
        &[
            "call",
            "vendor/tool",
            "--input",
            "{\"q\":\"hello\"}",
            "--request-id",
            OP,
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(out.stdout, b"paid-result");
    let requests = seen.recv().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        (&*requests[0].method, &*requests[0].path),
        ("POST", "/api/gateway/quote")
    );
    assert_eq!(requests[0].body["serviceId"], "vendor/tool");
    assert_eq!(requests[0].body["input"], json!({"q":"hello"}));
    assert_eq!(requests[0].body["sandbox"], false);
    assert!(requests[0].body.get("policySelector").is_none());
    assert_eq!(requests[1].path, "/api/gateway/call");
    assert_eq!(requests[1].body["quoteId"], "quote-1");
    for r in &requests {
        assert_eq!(r.authorization, format!("Bearer {DIRECT}"));
        assert_eq!(r.body["operationId"], OP);
    }
    assert!(!text(&out).contains(DIRECT));
    assert!(!text(&out).contains(POLICY_TOKEN));
}

#[test]
fn sandbox_policy_keeps_exact_version_rail_and_rpc() {
    let (url, seen) = serve(vec![response(200, quote()), response(200, delivered())]);
    let out = run(
        &url,
        &[
            "call",
            "vendor/tool",
            "--policy",
            SELECTOR,
            "--sandbox",
            "--rail",
            "stellar",
            "--rpc",
            "https://sandbox-rpc.example.com",
            "--request-id",
            OP,
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    for r in seen.recv().unwrap() {
        assert_eq!(r.authorization, format!("Bearer {POLICY_TOKEN}"));
        assert_eq!(r.body["policySelector"], SELECTOR);
        assert_eq!(r.body["sandbox"], true);
        assert_eq!(r.body["rail"], "stellar");
        assert_eq!(r.body["rpcUrl"], "https://sandbox-rpc.example.com");
    }
}

#[test]
fn inactive_production_policy_does_not_fall_back_to_direct_account() {
    let (url, seen) = serve(vec![response(
        403,
        json!({"code":"POLICY_NOT_ACTIVE","error":"version is not actively deployed"}),
    )]);
    let out = run(
        &url,
        &[
            "call",
            "vendor/tool",
            "--policy",
            SELECTOR,
            "--request-id",
            OP,
        ],
    );
    assert_eq!(out.status.code(), Some(20), "{}", text(&out));
    let requests = seen.recv().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].authorization, format!("Bearer {POLICY_TOKEN}"));
    assert_eq!(requests[0].body["sandbox"], false);
    assert!(text(&out).contains("POLICY_NOT_ACTIVE"));
}

#[test]
fn binding_rejection_never_changes_mode_rail_or_rpc() {
    for code in ["SANDBOX_BINDING_REQUIRED", "DEPLOYMENT_BINDING_MISMATCH"] {
        let (url, seen) = serve(vec![response(
            403,
            json!({"code":code,"error":"binding refused"}),
        )]);
        let out = run(
            &url,
            &[
                "call",
                "vendor/tool",
                "--policy",
                SELECTOR,
                "--sandbox",
                "--rail",
                "stellar",
                "--rpc",
                "https://bound-rpc.example.com",
                "--request-id",
                OP,
            ],
        );
        assert_eq!(out.status.code(), Some(20), "{}", text(&out));
        assert!(text(&out).contains(code));
        assert_eq!(seen.recv().unwrap().len(), 1);
    }
}

#[test]
fn malformed_selectors_and_missing_policy_token_cannot_use_direct_authority() {
    for selector in ["policy-id", "@wallet", "v1@", "v1@wallet@other"] {
        let out = run(
            "http://127.0.0.1:9",
            &["call", "vendor/tool", "--policy", selector],
        );
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    }
    let out = command("http://127.0.0.1:9")
        .env_remove("ALLOWIT_TOKEN")
        .args(["call", "vendor/tool", "--policy", SELECTOR])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    assert!(text(&out).contains("ALLOWIT_TOKEN"));
}

#[test]
fn all_http_spellings_send_only_normalized_backend_requests() {
    let cases: &[(&str, &[&str])] = &[
        (
            "curl",
            &[
                "https://merchant.example.com/data",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                "{\"q\":\"x\"}",
            ],
        ),
        (
            "wget",
            &[
                "https://merchant.example.com/data",
                "--method",
                "POST",
                "--body",
                "{\"q\":\"x\"}",
            ],
        ),
        (
            "http",
            &["POST", "https://merchant.example.com/data", "q=x"],
        ),
        (
            "fetch",
            &[
                "https://merchant.example.com/data",
                "--method",
                "POST",
                "--body",
                "{\"q\":\"x\"}",
            ],
        ),
    ];
    for (group, tail) in cases {
        let (url, seen) = serve(vec![response(200, quote()), response(200, delivered())]);
        let mut args = vec![*group];
        args.extend(*tail);
        args.extend(["--request-id", OP]);
        let out = run(&url, &args);
        assert_eq!(out.status.code(), Some(0), "{group}: {}", text(&out));
        let requests = seen.recv().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body["request"]["method"], "POST");
        assert_eq!(
            requests[0].body["request"]["url"],
            "https://merchant.example.com/data"
        );
        assert_eq!(
            serde_json::from_str::<Value>(requests[0].body["request"]["body"].as_str().unwrap())
                .unwrap(),
            json!({"q":"x"})
        );
    }
}

#[test]
fn backend_uncertainty_and_quote_mismatch_never_resubmit_payment() {
    let (url, seen) = serve(vec![
        response(200, quote()),
        response(
            503,
            json!({"code":"PAYMENT_UNCERTAIN","error":"reconcile first"}),
        ),
    ]);
    let out = run(&url, &["call", "vendor/tool", "--request-id", OP]);
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert!(text(&out).contains(OP));
    assert_eq!(seen.recv().unwrap().len(), 2);
    let mut wrong = quote();
    wrong["operationId"] = json!("different-operation");
    let (url, seen) = serve(vec![response(200, wrong)]);
    let out = run(&url, &["call", "vendor/tool", "--request-id", OP]);
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert_eq!(seen.recv().unwrap().len(), 1);
}

#[test]
fn json_output_requires_a_real_delivered_result() {
    for mut result in [
        json!({"operationId":OP,"state":"delivered"}),
        json!({"operationId":OP,"state":"delivered","result":{"body":"incomplete"}}),
    ] {
        let (url, seen) = serve(vec![response(200, quote()), response(200, result.take())]);
        let out = run(&url, &["call", "vendor/tool", "--request-id", OP, "--json"]);
        assert_eq!(out.status.code(), Some(5), "{}", text(&out));
        assert_eq!(seen.recv().unwrap().len(), 2);
    }
    let mut result = delivered();
    result["result"]["status"] = json!(500);
    let (url, seen) = serve(vec![response(200, quote()), response(200, result)]);
    let out = run(&url, &["call", "vendor/tool", "--request-id", OP, "--json"]);
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(seen.recv().unwrap().len(), 2);
}

#[test]
fn explicit_maximum_cannot_be_raised_by_a_quote() {
    let mut q = quote();
    q["maxDebitMoney"] = json!({"currency":"USDC","amount":"99"});
    let (url, seen) = serve(vec![response(200, q), response(200, delivered())]);
    let out = run(
        &url,
        &[
            "call",
            "vendor/tool",
            "--request-id",
            OP,
            "--max-payment",
            "0.01",
            "--currency",
            "USDC",
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    let rows = seen.recv().unwrap();
    assert_eq!(
        rows[0].body["maxDebitMoney"],
        json!({"currency":"USDC","amount":"0.01"})
    );
    assert_eq!(rows[1].body["maxDebitMoney"], rows[0].body["maxDebitMoney"]);
}

#[test]
fn mcp_preserves_policy_context_and_never_exposes_an_account_capability() {
    use std::process::Stdio;
    let (url, seen) = serve(vec![response(200, json!({"services":[]}))]);
    let mut child = command(&url)
        .args(["mcp", "--policy", SELECTOR, "--sandbox"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin,"{}",json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}})).unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})
    )
    .unwrap();
    writeln!(stdin,"{}",json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"allowit_services","arguments":{}}})).unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let lines = String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[1]["result"]["tools"][0]["name"], "allowit_call");
    let requests = seen.recv().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].authorization, format!("Bearer {POLICY_TOKEN}"));
    assert!(requests[0].path.contains("policySelector=v1%40GACCOUNT"));
    assert!(requests[0].path.contains("sandbox=true"));
    assert!(!text(&out).contains(DIRECT));
    assert!(!text(&out).contains(POLICY_TOKEN));
}

#[test]
fn local_seller_requires_a_registered_resource_and_relays_without_owner_authority() {
    use std::{net::TcpStream, process::Stdio};
    let resource = "/api/providers/demo/weather";
    let (url, seen) = serve(vec![
        response(
            200,
            json!({"sellerResources":[{"id":"demo/weather","path":resource,"methods":["GET"]}]}),
        ),
        response(402, json!({"error":"synthetic unpaid quote"})),
    ]);
    let mut child = command(&url)
        .args([
            "gate",
            "api",
            "--resource",
            resource,
            "--listen",
            "127.0.0.1:0",
            "--once",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut ready = String::new();
    err.read_line(&mut ready).unwrap();
    let address = ready
        .split_once("serving ")
        .unwrap()
        .1
        .split_whitespace()
        .next()
        .unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    client.write_all(b"GET /?q=hello HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer caller-not-owner\r\nPayment-Signature: synthetic-unpaid-fixture\r\nConnection: close\r\n\r\n").unwrap();
    let mut returned = String::new();
    client.read_to_string(&mut returned).unwrap();
    assert!(returned.starts_with("HTTP/1.1 402"));
    assert!(!returned.contains(DIRECT));
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let requests = seen.recv().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/api/gateway/config");
    assert_eq!(requests[1].path, format!("{resource}?q=hello"));
    assert!(requests.iter().all(|r| r.authorization.is_empty()));
    let (url, seen) = serve(vec![response(200, json!({"sellerResources":[]}))]);
    let out = run(&url, &["gate", "api", "--once"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(!text(&out).contains("serving "));
    assert_eq!(seen.recv().unwrap().len(), 1);
}

#[test]
fn excluded_harnesses_are_not_commands() {
    for excluded in ["goose", "qodercli"] {
        let out = run("http://127.0.0.1:9", &[excluded, "--help"]);
        assert_eq!(out.status.code(), Some(2));
    }
}

#[cfg(unix)]
mod native {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(program: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "allowit-native-{}-{}-{}",
                std::process::id(),
                program,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let script = r#"#!/bin/sh
prev=''
for arg in "$@"; do
  if [ "$prev" = auth ] && [ "$arg" = status ]; then
    if [ "${NATIVE_TEST_NO_AUTH-}" = 1 ]; then printf '{"loggedIn":false,"authMethod":"none"}\n'; exit 1; fi
    printf '{"loggedIn":true,"authMethod":"oauth_token"}\n'; exit 0
  fi
  if [ "$prev" = login ] && [ "$arg" = status ]; then
    if [ "${NATIVE_TEST_NO_AUTH-}" = 1 ]; then printf 'Not logged in\n' >&2; exit 1; fi
    printf 'Logged in using ChatGPT\n' >&2; exit 0
  fi
  prev=$arg
done
for arg in "$@"; do printf '%s\000' "$arg"; done > "$CAPTURE_ARGS"
printf '%s\n' "${ANTHROPIC_API_KEY-unset}" "${OPENAI_API_KEY-unset}" "${CODEX_API_KEY-unset}" "${ANTHROPIC_BASE_URL-unset}" "${OPENAI_BASE_URL-unset}" "${CLAUDE_CODE_OAUTH_TOKEN-unset}" "${UNRELATED_CREDENTIAL-unset}" "${ALLOWIT_ACCOUNT_TOKEN-unset}" "${ALLOWIT_TOKEN-unset}" > "$CAPTURE_ENV"
exit 17
"#;
            fs::write(root.join(program), script).unwrap();
            fs::set_permissions(root.join(program), fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
        fn run(&self, program: &str, extra: &[&str]) -> Output {
            self.run_auth(program, extra, false)
        }
        fn run_auth(&self, program: &str, extra: &[&str], no_auth: bool) -> Output {
            let mut c = command("http://127.0.0.1:9");
            c.env(
                "PATH",
                format!(
                    "{}:{}",
                    self.0.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("CAPTURE_ARGS", self.0.join("args"))
            .env("CAPTURE_ENV", self.0.join("env"))
            .env("ANTHROPIC_API_KEY", "synthetic-anthropic")
            .env("OPENAI_API_KEY", "synthetic-openai")
            .env("CODEX_API_KEY", "synthetic-codex")
            .env("ANTHROPIC_BASE_URL", "https://unwanted.example.com")
            .env("OPENAI_BASE_URL", "https://unwanted.example.com")
            .env("CLAUDE_CODE_OAUTH_TOKEN", "synthetic-subscription-token")
            .env("UNRELATED_CREDENTIAL", "preserved-synthetic")
            .env("NATIVE_TEST_NO_AUTH", if no_auth { "1" } else { "0" });
            c.arg(program).args(extra).output().unwrap()
        }
        fn args(&self) -> Vec<String> {
            fs::read(self.0.join("args"))
                .unwrap()
                .split(|b| *b == 0)
                .filter(|b| !b.is_empty())
                .map(|b| String::from_utf8(b.to_vec()).unwrap())
                .collect()
        }
        fn env(&self) -> Vec<String> {
            fs::read_to_string(self.0.join("env"))
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn claude_uses_subscription_and_mcp_without_changing_model_or_permissions() {
        let f = Fixture::new("claude");
        let out = f.run(
            "claude",
            &[
                "--policy",
                SELECTOR,
                "--sandbox",
                "--",
                "--model",
                "opus",
                "--permission-mode",
                "plan",
                "inspect",
            ],
        );
        assert_eq!(out.status.code(), Some(17), "{}", text(&out));
        let args = f.args();
        assert!(args.windows(2).any(|a| a == ["--model", "opus"]));
        assert!(args.windows(2).any(|a| a == ["--permission-mode", "plan"]));
        assert!(
            !args
                .iter()
                .any(|a| a == "--dangerously-skip-permissions" || a == "--allowedTools")
        );
        let settings: Value =
            serde_json::from_str(&args[args.iter().position(|a| a == "--settings").unwrap() + 1])
                .unwrap();
        assert_eq!(settings["forceLoginMethod"], "claudeai");
        assert_eq!(settings["apiKeyHelper"], "");
        let mcp: Value =
            serde_json::from_str(&args[args.iter().position(|a| a == "--mcp-config").unwrap() + 1])
                .unwrap();
        let mcp_args = mcp["mcpServers"]["allowit"]["args"].as_array().unwrap();
        assert!(mcp_args.contains(&json!("--sandbox")));
        assert!(mcp_args.contains(&json!(SELECTOR)));
        let env = f.env();
        assert_eq!(env[0], "unset");
        assert_eq!(env[3], "unset");
        assert_eq!(env[5], "synthetic-subscription-token");
        assert_eq!(env[6], "preserved-synthetic");
        assert_eq!(env[7], "unset");
        assert!(!args.join(" ").contains("synthetic-subscription-token"));
    }

    #[test]
    fn codex_uses_chatgpt_and_keeps_native_model_sandbox_and_exit_status() {
        let f = Fixture::new("codex");
        let out = f.run(
            "codex",
            &[
                "--",
                "exec",
                "--model",
                "gpt-example",
                "--sandbox",
                "read-only",
                "inspect",
            ],
        );
        assert_eq!(out.status.code(), Some(17), "{}", text(&out));
        let args = f.args();
        assert!(args.contains(&"forced_login_method=\"chatgpt\"".to_owned()));
        assert!(args.contains(&"model_provider=\"openai\"".to_owned()));
        assert!(args.windows(2).any(|a| a == ["--model", "gpt-example"]));
        assert!(args.windows(2).any(|a| a == ["--sandbox", "read-only"]));
        assert!(
            !args
                .iter()
                .any(|a| a == "--yolo" || a.contains("approval_policy="))
        );
        let env = f.env();
        assert_eq!(env[1], "unset");
        assert_eq!(env[2], "unset");
        assert_eq!(env[4], "unset");
        assert_eq!(env[6], "preserved-synthetic");
        assert_eq!(env[8], "unset");
    }

    #[test]
    fn explicit_api_provider_override_is_rejected_before_native_launch() {
        let f = Fixture::new("codex");
        let out = f.run(
            "codex",
            &["--", "-c", "model_provider=paid-fallback", "inspect"],
        );
        assert_eq!(out.status.code(), Some(2), "{}", text(&out));
        assert!(!f.0.join("args").exists());
    }

    #[test]
    fn unavailable_subscription_stops_without_api_fallback() {
        for program in ["claude", "codex"] {
            let f = Fixture::new(program);
            let out = f.run_auth(program, &["--", "inspect"], true);
            assert_eq!(out.status.code(), Some(3), "{}", text(&out));
            assert!(text(&out).contains("subscription authentication is unavailable"));
            assert!(!f.0.join("args").exists());
        }
    }

    #[test]
    fn help_looking_option_value_cannot_skip_subscription_admission() {
        let f = Fixture::new("claude");
        let out = f.run_auth(
            "claude",
            &["--", "--append-system-prompt", "--help", "inspect"],
            true,
        );
        assert_eq!(out.status.code(), Some(3));
        assert!(!f.0.join("args").exists());
    }
}
