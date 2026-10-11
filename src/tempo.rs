//! Tempo capability transport. Execution returns a verified wallet plan; this
//! command never reads an owner/authority key or broadcasts a chain transaction.
use crate::{
    VERSION,
    config::{env_value, parse_origin},
    error::{Error, Result},
    output,
};
use reqwest::{blocking::Client, redirect::Policy as Redirect, tls::Version};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

const USAGE: &str = include_str!("tempo-usage.txt");
const MAX_BODY: usize = 65_536;
const MAX_REPLY: u64 = 2_097_152;
fn uncertain() -> Error {
    Error::uncertain(
        "Tempo request outcome is unknown. Preserve the same request ID and check its status; do not authorize another transaction.",
    )
}
fn address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}
fn hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}
fn same_address(a: &Value, b: &Value) -> bool {
    a.as_str()
        .zip(b.as_str())
        .is_some_and(|(a, b)| address(a) && a.eq_ignore_ascii_case(b))
}
fn request_id(value: &str) -> Result<()> {
    if (8..=100).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        Ok(())
    } else {
        Err(Error::usage(
            "Request ID must be 8 to 100 characters from A-Z a-z 0-9 . _ : -",
        ))
    }
}
fn amount(value: &str) -> Result<()> {
    let parts: Vec<_> = value.split('.').collect();
    let whole = parts.first().copied().unwrap_or_default();
    if value.len() > 80
        || parts.len() > 2
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || (whole.len() > 1 && whole.starts_with('0'))
        || parts.get(1).is_some_and(|fraction| {
            fraction.is_empty()
                || fraction.len() > 6
                || !fraction.bytes().all(|b| b.is_ascii_digit())
        })
        || value.bytes().all(|b| b == b'0' || b == b'.')
    {
        Err(Error::usage(
            "AMOUNT must be a positive exact decimal with at most six places",
        ))
    } else {
        allowit_tempo::units(value)
            .map(|_| ())
            .map_err(|_| Error::usage("AMOUNT exceeds the supported exact token range"))
    }
}
fn bundle_path() -> PathBuf {
    let explicit = env_value("ALLOWIT_TEMPO_BUNDLE");
    if explicit.is_empty() {
        PathBuf::from(".allowit-tempo/executor.json")
    } else {
        PathBuf::from(explicit)
    }
}
struct Bundle {
    value: Value,
    origin: String,
    capability: String,
}
impl Bundle {
    fn read(path: &std::path::Path) -> Result<Self> {
        let mut file = std::fs::File::open(path)
            .map_err(|_| Error::config("Cannot read the Tempo executor bundle"))?;
        let mut data = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|_| Error::config("Cannot read the Tempo executor bundle"))?;
        if data.len() > MAX_BODY {
            return Err(Error::config("Tempo executor bundle exceeds 64 KB"));
        }
        let value: Value = serde_json::from_slice(&data)
            .map_err(|_| Error::config("The Tempo executor bundle is not valid JSON"))?;
        let c = &value["config"];
        let p = &value["policy"];
        let capability = value["capability"].as_str().unwrap_or_default().to_owned();
        let secret = capability
            .strip_prefix("tempo-executor.")
            .unwrap_or_default();
        let id = p["id"].as_str().unwrap_or_default();
        let configured_origin = env_value("ALLOWIT_URL");
        let exported_origin = value["origin"].as_str().unwrap_or_default();
        let origin = parse_origin(if configured_origin.is_empty() {
            exported_origin
        } else {
            &configured_origin
        })?;
        if !configured_origin.is_empty()
            && !exported_origin.is_empty()
            && parse_origin(exported_origin)? != origin
        {
            return Err(Error::config(
                "ALLOWIT_URL differs from the exported Tempo service origin",
            ));
        }
        if value["version"] != 1
            || value["profile"] != "tempo-native-v1"
            || p["profile"] != "tempo-native-v1"
            || secret.len() != 32
            || !secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || !(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) || hash(id))
            || !matches!(
                c["network"].as_str(),
                Some("tempo:localnet" | "tempo:testnet")
            )
            || c["network"] != p["network"]
            || c["chainId"] != p["chainId"]
            || c["chainId"].as_u64().is_none_or(|id| id == 0)
            || (c["network"] == "tempo:testnet" && c["chainId"] != 42431)
            || !address(p["owner"].as_str().unwrap_or_default())
            || !address(p["vault"].as_str().unwrap_or_default())
            || ["token", "executor", "authority", "factory"]
                .iter()
                .any(|key| !same_address(&c[*key], &p[*key]))
        {
            return Err(Error::config(
                "Invalid Tempo executor capability or policy binding",
            ));
        }
        let config: allowit_tempo::Config = serde_json::from_value(c.clone())
            .map_err(|_| Error::config("Invalid Tempo SDK configuration"))?;
        let policy: allowit_tempo::Policy = serde_json::from_value(p.clone())
            .map_err(|_| Error::config("Invalid Tempo SDK policy"))?;
        allowit_tempo::validate_policy(&config, &policy)
            .map_err(|_| Error::config("Tempo policy failed exact custody validation"))?;
        Ok(Self {
            value,
            origin,
            capability,
        })
    }
    fn call(&self, route: &str, body: Value) -> Result<Value> {
        if !["execute", "report"].contains(&route) {
            return Err(Error::config("Invalid Tempo capability route"));
        }
        let raw = serde_json::to_vec(&body).map_err(|_| Error::config("Invalid Tempo request"))?;
        if raw.len() > MAX_BODY {
            return Err(Error::config("Tempo request exceeds 64 KB"));
        }
        let mut builder = Client::builder()
            .redirect(Redirect::none())
            .no_proxy()
            .min_tls_version(Version::TLS_1_2)
            .timeout(Duration::from_secs(60));
        let ca = env_value("ALLOWIT_CA_FILE");
        if !ca.is_empty() {
            let pem = fs::read(ca).map_err(|_| Error::config("Cannot read ALLOWIT_CA_FILE"))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| Error::config("Invalid ALLOWIT_CA_FILE"))?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder
            .build()
            .map_err(|_| Error::config("Cannot configure the Tempo capability transport"))?;
        // Exactly one application request; redirects are never followed and POSTs are never resent.
        let mut response = client
            .post(format!("{}/api/tempo/{route}", self.origin))
            .bearer_auth(&self.capability)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", format!("allowit-cli/{VERSION}"))
            .body(raw)
            .send()
            .map_err(|_| uncertain())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(uncertain());
        }
        let mut raw = Vec::new();
        response
            .by_ref()
            .take(MAX_REPLY + 1)
            .read_to_end(&mut raw)
            .map_err(|_| uncertain())?;
        if raw.len() as u64 > MAX_REPLY {
            return Err(uncertain());
        }
        let value: Value = serde_json::from_slice(&raw).map_err(|_| uncertain())?;
        if !value.is_object() {
            return Err(uncertain());
        }
        Ok(value)
    }
}
pub(crate) fn run(args: &[String], stdout: &mut String, stderr: &mut String) -> Result<i32> {
    let Some(command) = args.first() else {
        stderr.push_str(USAGE);
        return Ok(2);
    };
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        stdout.push_str(USAGE);
        return Ok(0);
    }
    let mut pos = Vec::new();
    let mut json_output = false;
    for arg in &args[1..] {
        if arg == "--json" {
            json_output = true;
        } else if arg.starts_with('-') {
            return Err(Error::usage("Tempo commands accept only --json"));
        } else {
            pos.push(arg.as_str());
        }
    }
    let expected = match command.as_str() {
        "import" | "status" => 1,
        "execute" | "submit" => 2,
        _ => {
            return Err(Error::usage(
                "Unknown Tempo command (import, execute, submit, status)",
            ));
        }
    };
    if pos.len() != expected {
        return Err(Error::usage(format!(
            "Invalid arguments. Run allowit tempo help for {command} usage"
        )));
    }
    if command == "import" {
        allowit_native::journal::require_supported_platform().map_err(|_| {
            Error::config("Import requires a local POSIX filesystem for private capability storage")
        })?;
        let bundle = Bundle::read(std::path::Path::new(pos[0]))?;
        let destination = bundle_path();
        let parent = destination
            .parent()
            .ok_or_else(|| Error::config("Invalid Tempo bundle path"))?;
        let parent_existed = parent.exists();
        fs::create_dir_all(parent)
            .map_err(|_| Error::config("Cannot create the Tempo policy directory"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::symlink_metadata(parent)
                .map_err(|_| Error::config("Cannot inspect the Tempo policy directory"))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::config("Use a private local Tempo policy directory"));
            }
            if !parent_existed {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                    .map_err(|_| Error::config("Cannot secure the Tempo policy directory"))?;
            } else if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::config(
                    "The Tempo policy directory must have owner-only permissions",
                ));
            }
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file=options.open(&destination).map_err(|_|Error::config("A Tempo executor bundle already exists or cannot be stored. Keep the earlier bundle for recovery"))?;
        file.write_all(
            serde_json::to_string_pretty(&bundle.value)
                .unwrap()
                .as_bytes(),
        )
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::config("Cannot preserve the Tempo executor bundle"))?;
        stdout.push_str(&format!(
            "Imported Tempo policy {}\n",
            bundle.value["policy"]["id"].as_str().unwrap()
        ));
        return Ok(0);
    }
    let bundle = Bundle::read(&bundle_path())?;
    let policy_id = bundle.value["policy"]["id"].as_str().unwrap();
    let (result, code) = match command.as_str() {
        "execute" => {
            if !address(pos[0]) {
                return Err(Error::usage("RECIPIENT must be a 0x EVM address"));
            }
            amount(pos[1])?;
            let id = env_value("ALLOWIT_REQUEST_ID");
            request_id(&id)?;
            let action = env_value("ALLOWIT_EXECUTION_ACTION");
            let action = if action.is_empty() {
                "transfer"
            } else {
                &action
            };
            let merchant = env_value("ALLOWIT_EXECUTION_MERCHANT");
            let context = env_value("ALLOWIT_EXECUTION_CONTEXT_JSON");
            let context: Value = if context.is_empty() {
                json!({})
            } else {
                serde_json::from_str(&context).map_err(|_| {
                    Error::config("ALLOWIT_EXECUTION_CONTEXT_JSON must be a JSON object")
                })?
            };
            if !context.is_object() {
                return Err(Error::config(
                    "ALLOWIT_EXECUTION_CONTEXT_JSON must be a JSON object",
                ));
            }
            stderr.push_str(&format!("Tempo request {id}: requesting a wallet plan; no chain transaction is broadcast by this command.\n"));
            crate::flush_stderr(stderr);
            let result=bundle.call("execute",json!({"policyId":policy_id,"requestId":id,"recipient":pos[0],"amount":pos[1],"action":action,"merchant":merchant,"context":context}))?;
            let decision = result["decision"].as_str().unwrap_or_default();
            if result["requestId"]
                .as_str()
                .is_some_and(|other| other != id)
                || result["policyId"]
                    .as_str()
                    .is_some_and(|other| other != policy_id)
            {
                return Err(uncertain());
            }
            let code = match decision {
                "deny" => 20,
                "awaiting_input" => {
                    if result["requestId"] != id || result["policyId"] != policy_id {
                        return Err(uncertain());
                    }
                    11
                }
                "settled" => {
                    checked_receipt(&result, policy_id, &id, None)?;
                    if result["operation"]["status"] != "settled" {
                        return Err(uncertain());
                    }
                    6
                }
                "allow" => {
                    let prepared = result.get("prepared").unwrap_or(&result);
                    let config: allowit_tempo::Config =
                        serde_json::from_value(bundle.value["config"].clone())
                            .map_err(|_| Error::config("Invalid Tempo SDK configuration"))?;
                    let policy: allowit_tempo::Policy =
                        serde_json::from_value(bundle.value["policy"].clone())
                            .map_err(|_| Error::config("Invalid Tempo SDK policy"))?;
                    let transaction: allowit_tempo::Transaction =
                        serde_json::from_value(prepared["transaction"].clone())
                            .map_err(|_| uncertain())?;
                    let context_json = serde_json::to_string(&context)
                        .map_err(|_| Error::config("Invalid execution context"))?;
                    allowit_tempo::validate_execution_request(&config,&policy,&transaction,&id,pos[0],pos[1],action,&merchant,Some(&context_json)).map_err(|_|Error::config("Tempo wallet plan failed exact request, policy and authority-signature validation"))?;
                    if prepared["operation"]["id"] != id
                        || prepared["operation"]["policyId"] != policy_id
                        || prepared["operation"]["method"] != "execute"
                    {
                        return Err(uncertain());
                    }
                    10 // A prepared plan still needs the executor's own wallet signature and verified receipt.
                }
                _ => return Err(uncertain()),
            };
            (result, code)
        }
        "submit" => {
            request_id(pos[0])?;
            if !hash(pos[1]) {
                return Err(Error::usage("TRANSACTION_HASH must be a 0x 32-byte hash"));
            }
            let result = bundle.call(
                "report",
                json!({"policyId":policy_id,"requestId":pos[0],"transactionHash":pos[1]}),
            )?;
            checked_receipt(&result, policy_id, pos[0], Some(pos[1]))?;
            let code = receipt_code(&result);
            (result, code)
        }
        _ => {
            request_id(pos[0])?;
            let result = bundle.call("report", json!({"policyId":policy_id,"requestId":pos[0]}))?;
            checked_receipt(&result, policy_id, pos[0], None)?;
            let code = receipt_code(&result);
            (result, code)
        }
    };
    let rendered = if json_output || command == "execute" {
        serde_json::to_string_pretty(&result).unwrap() + "\n"
    } else {
        format!(
            "Tempo request {}: {}\n",
            result["operation"]["id"].as_str().unwrap_or_default(),
            result["operation"]["status"].as_str().unwrap_or_default()
        )
    };
    stdout.push_str(&output::clean(rendered, &bundle.capability));
    Ok(code)
}
fn checked_receipt(value: &Value, policy: &str, id: &str, hash: Option<&str>) -> Result<()> {
    let op = &value["operation"];
    if op["id"] != id
        || op["policyId"] != policy
        || op["method"] != "execute"
        || hash.is_some_and(|expected| {
            op["transactionHash"]
                .as_str()
                .is_none_or(|actual| !actual.eq_ignore_ascii_case(expected))
        })
        || !matches!(
            op["status"].as_str(),
            Some("prepared" | "submitted" | "uncertain" | "settled" | "failed")
        )
    {
        Err(uncertain())
    } else {
        Ok(())
    }
}
fn receipt_code(value: &Value) -> i32 {
    match value["operation"]["status"].as_str() {
        Some("settled") => 0,
        Some("failed") => 20,
        Some("prepared") => 10,
        Some("submitted") => 12,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_amounts_refuse_rounding_and_exponents() {
        for v in ["0", "0.0000001", "1e2", "-1", "01", "1.", "NaN"] {
            assert!(amount(v).is_err(), "{v}");
        }
        for v in ["0.000001", "0.25", "9007199254.740993"] {
            assert!(amount(v).is_ok(), "{v}");
        }
    }
    #[test]
    fn receipt_identity_and_hash_cannot_be_substituted() {
        let good = json!({"operation":{"id":"request-1","policyId":"p","method":"execute","status":"settled","transactionHash":format!("0x{}","ab".repeat(32))}});
        assert!(checked_receipt(&good, "p", "request-1", None).is_ok());
        assert!(checked_receipt(&good, "other", "request-1", None).is_err());
        assert!(checked_receipt(&good, "p", "request-2", None).is_err());
        assert!(
            checked_receipt(
                &good,
                "p",
                "request-1",
                Some(&format!("0x{}", "cd".repeat(32)))
            )
            .is_err()
        );
    }
    #[test]
    fn a_prepared_plan_is_never_settlement() {
        assert_eq!(
            receipt_code(&json!({"operation":{"status":"prepared"}})),
            10
        );
        assert_eq!(
            receipt_code(&json!({"operation":{"status":"submitted"}})),
            12
        );
        assert_eq!(receipt_code(&json!({"operation":{"status":"settled"}})), 0);
    }
    #[test]
    fn capability_post_is_sent_once_and_only_to_the_fixed_tempo_route() {
        use crate::client::tests::{Reply, serve};
        let (client, server) = serve(vec![Reply::Status(200, r#"{"decision":"deny"}"#)]);
        let bundle = Bundle {
            value: json!({}),
            origin: client.cfg.origin.clone(),
            capability: format!("tempo-executor.{}", "a".repeat(32)),
        };
        assert_eq!(
            bundle
                .call("execute", json!({"requestId":"request-1"}))
                .unwrap()["decision"],
            "deny"
        );
        let seen = server.finish();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0]
                .head
                .starts_with("POST /api/tempo/execute HTTP/1.1\r\n")
        );
        assert!(
            seen[0]
                .head
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {}", bundle.capability))
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&seen[0].body).unwrap(),
            json!({"requestId":"request-1"})
        );
    }
    #[test]
    fn capability_gateway_failure_or_redirect_never_retries_or_echoes_secret() {
        use crate::client::tests::{Reply, serve};
        for status in [302, 403, 503] {
            let (client, server) = serve(vec![
                Reply::Status(
                    status,
                    r#"{"error":"tempo-executor.secret private-request"}"#,
                ),
                Reply::Status(200, "{}"),
            ]);
            let bundle = Bundle {
                value: json!({}),
                origin: client.cfg.origin.clone(),
                capability: format!("tempo-executor.{}", "a".repeat(32)),
            };
            let error = bundle
                .call("report", json!({"requestId":"private-request"}))
                .unwrap_err();
            assert_eq!(error.code, 5);
            assert!(!error.message.contains("private-request"));
            assert!(!error.message.contains("secret"));
            assert_eq!(server.finish().len(), 1);
        }
    }
    #[test]
    fn a_capability_never_calls_owner_lifecycle_routes() {
        use crate::client::tests::serve;
        let (client, server) = serve(vec![]);
        let bundle = Bundle {
            value: json!({}),
            origin: client.cfg.origin.clone(),
            capability: format!("tempo-executor.{}", "a".repeat(32)),
        };
        assert!(bundle.call("withdraw", json!({})).is_err());
        assert!(server.finish().is_empty());
    }
}
