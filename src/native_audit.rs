//! Capability-scoped SQL audit reporting; it grants no signing or owner authority.
use crate::{config::parse_origin, error::Error};
use allowit_native::{
    client::Binding,
    crypto::Key,
    error::Result,
    journal::FileJournal,
    lifecycle::{AuthorizedExecution, Record},
    native::{ApprovalCommitment, ApprovalRequest, ExecutionRequestIdentity, Simulation},
    rpc::Rpc,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditConfig {
    pub origin: String,
    pub token: String,
}
impl AuditConfig {
    pub fn validate(&self) -> crate::error::Result<()> {
        if parse_origin(&self.origin)? != self.origin
            || self
                .token
                .strip_prefix("native-report.")
                .is_none_or(|secret| {
                    secret.len() != 32
                        || !secret
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                })
        {
            return Err(Error::config("Invalid native audit capability"));
        }
        Ok(())
    }
}
pub(crate) struct Reporter {
    config: AuditConfig,
    policy_id: String,
    client: reqwest::blocking::Client,
    pub blocked: AtomicBool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecuteResponse {
    binding: Binding,
    request: ApprovalRequest,
    approval: ApprovalCommitment,
    intent: String,
    message: String,
    partial_transaction: String,
    operation: PreparedOperation,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedOperation {
    id: String,
    policy_id: String,
    method: String,
    status: String,
    blockhash: Key,
    last_valid_block_height: u64,
    nonce: String,
    revision: String,
    commitment: String,
    expires_at: u64,
    instance_slot: u64,
    decision_code: String,
    simulation: Simulation,
}
fn unavailable() -> allowit_native::error::Error {
    allowit_native::error::Error::uncertain(
        "Native audit acknowledgment unavailable; retain the original journal and request ID",
    )
}
impl Reporter {
    pub fn new(config: AuditConfig, policy_id: String) -> Result<Self> {
        config.validate().map_err(|_| unavailable())?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| unavailable())?;
        Ok(Self {
            config,
            policy_id,
            client,
            blocked: AtomicBool::new(false),
        })
    }
    pub fn report(&self, record: &Record) -> Result<Value> {
        if record.method != "execute" {
            return Err(unavailable());
        }
        let body = serde_json::to_vec(&json!({"policyId":self.policy_id,"record":record}))
            .map_err(|_| unavailable())?;
        if body.len() > 65_536 {
            return Err(unavailable());
        }
        let mut response = self
            .client
            .post(format!("{}/api/native/report", self.config.origin))
            .bearer_auth(&self.config.token)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|_| unavailable())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(unavailable());
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut response)
            .take(2_097_153)
            .read_to_end(&mut raw)
            .map_err(|_| unavailable())?;
        if raw.len() > 2_097_152 {
            return Err(unavailable());
        }
        let result: Value = serde_json::from_slice(&raw).map_err(|_| unavailable())?;
        let operation = &result["operation"];
        if operation["id"] != record.id
            || operation["signature"] != record.signature
            || operation["policyId"] != self.policy_id
            || operation["method"] != "execute"
            || (record.final_status() && operation["status"] != record.status)
            || !matches!(
                operation["status"].as_str(),
                Some("uncertain" | "submitted" | "settled" | "failed")
            )
        {
            return Err(unavailable());
        }
        Ok(operation.clone())
    }
    pub fn authorize(
        &self,
        identity: &ExecutionRequestIdentity,
        context: &Value,
    ) -> Result<AuthorizedExecution> {
        if identity.vault_policy_id != self.policy_id {
            return Err(allowit_native::error::Error::config(
                "Execution request belongs to a different policy",
            ));
        }
        let body = serde_json::to_vec(&json!({
            "policyId": &self.policy_id,
            "requestId": &identity.operation_id,
            "action": &identity.action,
            "merchant": &identity.merchant,
            "context": context,
            "options": {"amount": &identity.amount, "recipient": identity.recipient},
        }))
        .map_err(|_| unavailable())?;
        if body.len() > 65_536 {
            return Err(allowit_native::error::Error::config(
                "Native execution request is too large",
            ));
        }
        let mut response = self
            .client
            .post(format!("{}/api/native/execute", self.config.origin))
            .bearer_auth(&self.config.token)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|_| unavailable())?;
        let status = response.status();
        let mut raw = Vec::new();
        Read::by_ref(&mut response)
            .take(2_097_153)
            .read_to_end(&mut raw)
            .map_err(|_| unavailable())?;
        if raw.len() > 2_097_152 {
            return Err(unavailable());
        }
        if status != reqwest::StatusCode::OK {
            let message = serde_json::from_slice::<Value>(&raw)
                .ok()
                .and_then(|value| value["error"].as_str().map(str::to_owned))
                .filter(|message| {
                    !message.is_empty()
                        && message.len() <= 1_000
                        && !message.chars().any(char::is_control)
                })
                .unwrap_or_else(|| "Native execution authorization failed".into());
            return Err(match status.as_u16() {
                400 | 401 | 404 | 409 => allowit_native::error::Error::config(message),
                403 => allowit_native::error::Error::denied(message),
                _ => allowit_native::error::Error::uncertain(message),
            });
        }
        let response: ExecuteResponse = serde_json::from_slice(&raw).map_err(|_| unavailable())?;
        let operation = response.operation;
        let commitment = response.approval.digest()?;
        if operation.id != identity.operation_id
            || operation.policy_id != self.policy_id
            || operation.method != "execute"
            || operation.status != "prepared"
            || operation.commitment != commitment
            || operation.expires_at != response.approval.expires_at
            || operation.instance_slot.to_string() != response.approval.instance_slot
            || operation.nonce != response.approval.nonce
            || operation.revision != response.approval.policy_revision
            || operation.decision_code != response.request.decision_code
        {
            return Err(unavailable());
        }
        let message = base64::engine::general_purpose::STANDARD
            .decode(response.message)
            .map_err(|_| unavailable())?;
        let partial_transaction = base64::engine::general_purpose::STANDARD
            .decode(response.partial_transaction)
            .map_err(|_| unavailable())?;
        if message.is_empty()
            || message.len() > 1_232
            || partial_transaction.len() > 1_232
            || operation.simulation.transaction_bytes != partial_transaction.len()
        {
            return Err(unavailable());
        }
        Ok(AuthorizedExecution {
            binding: response.binding,
            request: response.request,
            approval: response.approval,
            intent: response.intent,
            message,
            partial_transaction,
            blockhash: operation.blockhash,
            last_valid_block_height: operation.last_valid_block_height,
            nonce: operation.nonce,
            revision: operation.revision,
            simulation: operation.simulation,
        })
    }
    pub fn finish(&self, journal: &FileJournal, id: &str) -> (bool, bool) {
        let withheld = self.blocked.load(Ordering::Relaxed);
        let acknowledged = journal
            .read::<Record>(&format!("request-{id}"))
            .ok()
            .flatten()
            .is_some_and(|record| self.report(&record).is_ok());
        (withheld, withheld || !acknowledged)
    }
}
pub(crate) struct AuditedRpc {
    pub rpc: Box<dyn Rpc>,
    pub reporter: std::sync::Arc<Reporter>,
    pub journal: FileJournal,
}
impl Rpc for AuditedRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        if method == "sendTransaction" {
            // The SDK has already validated and durably saved this exact proof.
            let records = self.journal.entries::<Record>()?;
            let record = records
                .iter()
                .find(|r| r.method == "execute" && params[0] == r.signed_bytes)
                .ok_or_else(unavailable)?;
            let acknowledgment = self.reporter.report(record);
            if match &acknowledgment {
                Err(_) => true,
                Ok(op) => matches!(op["status"].as_str(), Some("settled" | "failed")),
            } {
                self.reporter.blocked.store(true, Ordering::Relaxed);
                return Err(unavailable());
            }
            self.reporter.blocked.store(false, Ordering::Relaxed);
        }
        self.rpc.call(method, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, atomic::AtomicUsize},
    };
    fn record() -> Record {
        Record {
            id: "audit-proof-0001".into(),
            intent: "test-only".into(),
            method: "execute".into(),
            status: "uncertain".into(),
            signature: "fixture-signature".into(),
            signatures: vec!["fixture-signature".into()],
            signed_bytes: "cHJvb2Y=".into(),
            blockhash: Key([9; 32]),
            last_valid_block_height: 100,
            nonce: Some("0".into()),
            revision: Some("1".into()),
            expires_at: None,
            commitment: None,
            instance_slot: None,
            transaction_url: "fixture".into(),
            extra: Default::default(),
        }
    }
    struct Chain {
        acknowledged: Arc<AtomicBool>,
        sends: Arc<AtomicUsize>,
    }
    impl Rpc for Chain {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            assert_eq!(method, "sendTransaction");
            assert_eq!(params[0], record().signed_bytes);
            assert!(self.acknowledged.load(Ordering::SeqCst));
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(json!(record().signature))
        }
    }
    fn check_report_before_broadcast(status: u16, mut operation: Value, expect_send: bool) {
        let dir = std::env::temp_dir().join(format!(
            "allowit-audit-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let journal = FileJournal::new(&dir);
        journal
            .locked(|| journal.write("request-audit-proof-0001", &record()))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let acknowledged = Arc::new(AtomicBool::new(false));
        let observed = acknowledged.clone();
        let path = dir.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = Vec::new();
            let mut byte = [0];
            while !header.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
            }
            let header = String::from_utf8(header).unwrap();
            assert!(header.starts_with("POST /api/native/report HTTP/1.1"));
            assert!(
                header
                    .to_ascii_lowercase()
                    .contains("authorization: bearer native-report.")
            );
            let length = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|n| n.parse::<usize>().ok())
                })
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let sent: Value = serde_json::from_slice(&body).unwrap();
            let durable = FileJournal::new(path)
                .read::<Record>("request-audit-proof-0001")
                .unwrap()
                .unwrap();
            assert_eq!(sent["policyId"], "fixture-policy");
            assert_eq!(sent["record"], serde_json::to_value(durable).unwrap());
            observed.store(true, Ordering::SeqCst);
            let response = json!({"operation":operation.take()}).to_string();
            write!(stream,"HTTP/1.1 {status} Result\r\nConnection: close\r\nLocation: https://example.invalid/steal\r\nContent-Length: {}\r\n\r\n{response}",response.len()).unwrap();
        });
        let reporter = Arc::new(
            Reporter::new(
                AuditConfig {
                    origin,
                    token: format!("native-report.{}", "a".repeat(32)),
                },
                "fixture-policy".into(),
            )
            .unwrap(),
        );
        let sends = Arc::new(AtomicUsize::new(0));
        let rpc = AuditedRpc {
            rpc: Box::new(Chain {
                acknowledged,
                sends: sends.clone(),
            }),
            reporter: reporter.clone(),
            journal,
        };
        let result = rpc.call("sendTransaction", json!([record().signed_bytes, {}]));
        assert_eq!(result.is_ok(), expect_send);
        assert_eq!(sends.load(Ordering::SeqCst), usize::from(expect_send));
        assert_eq!(reporter.blocked.load(Ordering::Relaxed), !expect_send);
        if let Err(error) = result {
            assert!(!error.message.contains("native-report."));
        }
        server.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    fn acknowledgment() -> Value {
        json!({"id":record().id,"signature":record().signature,"policyId":"fixture-policy","method":"execute","status":"uncertain"})
    }
    #[test]
    fn durable_exact_proof_is_acknowledged_before_chain_broadcast() {
        check_report_before_broadcast(200, acknowledgment(), true);
    }
    #[test]
    fn failed_redirected_or_substituted_acknowledgment_blocks_broadcast() {
        check_report_before_broadcast(503, acknowledgment(), false);
        check_report_before_broadcast(302, acknowledgment(), false);
        let mut wrong = acknowledgment();
        wrong["signature"] = json!("different");
        check_report_before_broadcast(200, wrong, false);
        let mut final_state = acknowledgment();
        final_state["status"] = json!("settled");
        check_report_before_broadcast(200, final_state, false);
    }
    #[test]
    fn withheld_broadcast_stays_pending_after_late_durable_acknowledgment() {
        let directory =
            std::env::temp_dir().join(format!("allowit-audit-late-{}", std::process::id()));
        let journal = FileJournal::new(&directory);
        journal
            .locked(|| journal.write("request-audit-proof-0001", &record()))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut byte = [0];
            while !raw.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                raw.push(byte[0]);
            }
            let header = String::from_utf8(raw).unwrap();
            let length = header
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|n| n.parse::<usize>().ok())
                })
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let submitted: Value = serde_json::from_slice(&body).unwrap();
            assert!(submitted["record"]["replayed"].is_null());
            let body = json!({"operation":acknowledgment()}).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let reporter = Reporter::new(
            AuditConfig {
                origin,
                token: format!("native-report.{}", "a".repeat(32)),
            },
            "fixture-policy".into(),
        )
        .unwrap();
        reporter.blocked.store(true, Ordering::Relaxed);
        assert_eq!(reporter.finish(&journal, "audit-proof-0001"), (true, true));
        server.join().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn audit_capability_refuses_url_credentials_paths_and_unknown_token_formats() {
        let token = format!("native-report.{}", "a".repeat(32));
        for origin in [
            "https://example.invalid/path",
            "https://user:pass@example.invalid",
            "http://example.invalid",
            "https://example.invalid/?token=abc",
        ] {
            assert!(
                AuditConfig {
                    origin: origin.into(),
                    token: token.clone()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            AuditConfig {
                origin: "https://example.invalid".into(),
                token: "wrong".into()
            }
            .validate()
            .is_err()
        );
    }
}
