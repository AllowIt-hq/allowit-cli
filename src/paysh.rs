//! PaySH agent calls through an owner-deployed policy. The scoped capability is
//! the only credential: no signing key is read, and each request is sent once.
use crate::{
    VERSION,
    config::{env_value, parse_origin},
    error::{Error, Result, quoted},
    output::{self, one_line},
};
use reqwest::{blocking::Client, redirect::Policy as Redirect, tls::Version};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};

pub(crate) const TOKEN_ENV: &str = "ALLOWIT_PAYSH_TOKEN";
const USAGE: &str = include_str!("paysh-usage.txt");
const MAX_INPUT: usize = 4096;
const MAX_REPLY: usize = 1 << 20;
const MAX_SHOWN: usize = 16 << 10;
const PENDING: [&str; 7] = [
    "evaluating",
    "approved",
    "preparing",
    "signed",
    "submitted",
    "confirmed",
    "delivering",
];
const FAILED: [&str; 2] = ["denied", "failed"];
/// Set by the owner for an unresolved operation, which may lack a verified payment transaction.
const UNKNOWN: &str = "unknown";

pub(crate) fn run(args: &[String], stdout: &mut String, stderr: &mut String) -> Result<i32> {
    let Some(command) = args.first() else {
        stderr.push_str(USAGE);
        return Ok(2);
    };
    if matches!(command.as_str(), "help" | "-h" | "--help") {
        stdout.push_str(USAGE);
        return Ok(0);
    }
    let (pos, json) = positional(&args[1..])?;
    match (command.as_str(), pos.len()) {
        ("services", 0) => services(json, stdout),
        ("call", 4) => call(&pos, json, stdout, stderr),
        ("status", 2) => status(&pos, json, stdout),
        ("services" | "call" | "status", _) => Err(Error::usage(match command.as_str() {
            "services" => "usage: allowit paysh services [--json]",
            "call" => {
                "usage: allowit paysh call POLICY OPERATION_ID SERVICE_ID INPUT_JSON [--json]"
            }
            _ => "usage: allowit paysh status POLICY OPERATION_ID [--json]",
        })),
        _ => Err(Error::usage(format!(
            "unknown paysh command {} (services, call, status)",
            quoted(command)
        ))),
    }
}

/// Positional arguments and `--json`. `--` ends options, so INPUT_JSON may start with `-`.
fn positional(args: &[String]) -> Result<(Vec<String>, bool)> {
    let (mut pos, mut json, mut literal) = (Vec::new(), false, false);
    for a in args {
        if literal || !a.starts_with('-') || a == "-" {
            pos.push(a.clone());
        } else if a == "--" {
            literal = true;
        } else if a == "--json" {
            json = true;
        } else {
            return Err(Error::usage(format!("unknown flag {}", quoted(a))));
        }
    }
    Ok((pos, json))
}

fn policy_id(s: &str) -> Result<&str> {
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(s)
    } else {
        Err(Error::usage(
            "POLICY is the 64-character lowercase hex policy ID",
        ))
    }
}
fn operation_id(s: &str) -> Result<&str> {
    if !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(s)
    } else {
        Err(Error::usage(
            "OPERATION_ID must be 1 to 128 characters from A-Z a-z 0-9 _ -",
        ))
    }
}
fn service_id(s: &str) -> Result<&str> {
    if !s.is_empty()
        && s.len() <= 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:".contains(&b))
    {
        Ok(s)
    } else {
        Err(Error::usage(
            "SERVICE_ID must be 1 to 200 characters from A-Z a-z 0-9 - _ . / :",
        ))
    }
}
fn token() -> Result<String> {
    let t = env_value(TOKEN_ENV);
    if t.is_empty() {
        return Err(Error::config(format!(
            "set {TOKEN_ENV} to the policy's PaySH capability from the AllowIt app"
        )));
    }
    if t.len() < 32 || t.len() > 512 || !t.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::config(format!(
            "{TOKEN_ENV} must be the capability exactly as issued"
        )));
    }
    Ok(t)
}

struct Http {
    origin: String,
    client: Client,
}
enum Reply {
    Ok(Value),
    Status(u16, String),
    Redirect(u16),
}
impl Http {
    fn new(timeout: Duration) -> Result<Self> {
        let origin = parse_origin(&env_value("ALLOWIT_URL"))?;
        let mut builder = Client::builder()
            .redirect(Redirect::none())
            .timeout(timeout)
            .min_tls_version(Version::TLS_1_2);
        let ca = env_value("ALLOWIT_CA_FILE");
        if !ca.is_empty() {
            let bad = || Error::config("ALLOWIT_CA_FILE must name a readable PEM certificate file");
            let certs = std::fs::read(&ca)
                .ok()
                .and_then(|pem| reqwest::Certificate::from_pem_bundle(&pem).ok())
                .filter(|c| !c.is_empty())
                .ok_or_else(bad)?;
            for c in certs {
                builder = builder.add_root_certificate(c);
            }
        }
        let client = builder
            .build()
            .map_err(|_| Error::config("could not configure the AllowIt HTTP client"))?;
        Ok(Self { origin, client })
    }
    /// One attempt. Transport and read failures are returned as unknown.
    fn send(&self, route: &str, bearer: Option<&str>, body: Option<&Value>) -> Result<Reply> {
        let url = format!("{}/api/paysh/{route}", self.origin);
        let mut r = match body {
            Some(b) => self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(b).expect("JSON values serialize")),
            None => self.client.get(url),
        }
        .header("Accept", "application/json")
        .header("User-Agent", format!("allowit-cli/{VERSION}"));
        if let Some(t) = bearer {
            r = r.bearer_auth(t);
        }
        let mut response = r.send().map_err(|e| {
            if format!("{e:?}")
                .to_ascii_lowercase()
                .contains("certificate")
            {
                Error::config("TLS certificate for ALLOWIT_URL is not trusted")
            } else {
                Error::uncertain(format!("network error talking to AllowIt: {e}"))
            }
        })?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Ok(Reply::Redirect(status));
        }
        let mut data = Vec::new();
        Read::by_ref(&mut response)
            .take(MAX_REPLY as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|e| {
                Error::uncertain(format!("network error reading the AllowIt response: {e}"))
            })?;
        if data.len() > MAX_REPLY {
            return Err(Error::uncertain("AllowIt response exceeded the 1 MB limit"));
        }
        let value: Option<Value> = serde_json::from_slice(&data).ok();
        if status != 200 {
            let message = value
                .as_ref()
                .and_then(|v| v["error"].as_str())
                .filter(|s| !s.is_empty())
                .map(|s| one_line(&s.chars().take(400).collect::<String>()))
                .unwrap_or_else(|| "no error message".into());
            return Ok(Reply::Status(status, message));
        }
        match value {
            Some(v) if v.is_object() => Ok(Reply::Ok(v)),
            _ => Err(Error::uncertain(
                "AllowIt returned a response that is not a JSON object",
            )),
        }
    }
}

fn services(json: bool, stdout: &mut String) -> Result<i32> {
    let http = Http::new(Duration::from_secs(30))?;
    let catalog = match http.send("catalog", None, None)? {
        Reply::Ok(v) => v,
        Reply::Redirect(s) => {
            return Err(Error::config(format!(
                "AllowIt answered with a redirect (HTTP {s}); check ALLOWIT_URL"
            )));
        }
        Reply::Status(s, m) => return Err(Error::api(s, m)),
    };
    if json {
        *stdout += &output::json(&catalog);
        return Ok(0);
    }
    let providers = catalog["providers"]
        .as_array()
        .ok_or_else(|| Error::unsupported("the PaySH catalog has no provider list"))?;
    for p in providers.iter().take(500) {
        let price = match (p["min_price_usd"].as_f64(), p["max_price_usd"].as_f64()) {
            (Some(a), Some(b)) if a == b => format!("{a} USD"),
            (Some(a), Some(b)) => format!("{a} to {b} USD"),
            _ => "price not listed".into(),
        };
        *stdout += &format!(
            "{}\t{}\t{price}\n",
            one_line(p["fqn"].as_str().unwrap_or("?")),
            one_line(p["title"].as_str().unwrap_or(""))
        );
    }
    Ok(0)
}

fn unknown(e: impl std::fmt::Display, policy: &str, op: &str) -> Error {
    Error::uncertain(format!(
        "{e}\nThe result of operation {op} is unknown and it may have paid. Do not retry with a new OPERATION_ID. Check it with: allowit paysh status {policy} {op}"
    ))
}

fn call(pos: &[String], json: bool, stdout: &mut String, stderr: &mut String) -> Result<i32> {
    let policy = policy_id(&pos[0])?;
    let op = operation_id(&pos[1])?;
    let service = service_id(&pos[2])?;
    let input: Value =
        serde_json::from_str(&pos[3]).map_err(|_| Error::usage("INPUT_JSON must be valid JSON"))?;
    if serde_json::to_vec(&input)
        .expect("JSON values serialize")
        .len()
        > MAX_INPUT
    {
        return Err(Error::usage(format!(
            "INPUT_JSON must be at most {MAX_INPUT} bytes"
        )));
    }
    let token = token()?;
    // The sponsor, evaluator and chain may take most of this.
    let http = Http::new(Duration::from_secs(110))?;
    *stderr += &format!(
        "allowit: paysh call operation {op}; if the result is unknown, check it with allowit paysh status {policy} {op}\n"
    );
    // Recovery instructions leave the process before the request can.
    crate::flush_stderr(stderr);
    let body = json!({"policyId":policy,"operationId":op,"serviceId":service,"input":input});
    let reply = http
        .send("call", Some(&token), Some(&body))
        .map_err(|e| if e.config { e } else { unknown(e, policy, op) })?;
    let value = match reply {
        Reply::Ok(v) => v,
        Reply::Redirect(s) => {
            return Err(unknown(
                format!("AllowIt answered with a redirect (HTTP {s}), which was not followed"),
                policy,
                op,
            ));
        }
        Reply::Status(409, m) => {
            return Err(unknown(
                format!("AllowIt returned HTTP 409: {m}"),
                policy,
                op,
            ));
        }
        Reply::Status(s @ (401 | 404 | 429), m) => return Err(Error::api(s, m)),
        Reply::Status(s, m) => {
            return Err(unknown(
                format!("AllowIt returned HTTP {s}: {m}"),
                policy,
                op,
            ));
        }
    };
    report(value, policy, op, json, stdout)
}

fn status(pos: &[String], json: bool, stdout: &mut String) -> Result<i32> {
    let policy = policy_id(&pos[0])?;
    let op = operation_id(&pos[1])?;
    let token = token()?;
    let http = Http::new(Duration::from_secs(110))?;
    let body = json!({"policyId":policy,"operationId":op});
    let value = match http.send("status", Some(&token), Some(&body)) {
        Ok(Reply::Ok(v)) => v,
        Ok(Reply::Status(404, m)) => {
            return Err(Error::uncertain(format!(
                "AllowIt returned HTTP 404: {m}\nNo operation {op} is recorded for this policy. If a call with this OPERATION_ID may have been sent, rerun that identical call; never use a new OPERATION_ID for it"
            )));
        }
        Ok(Reply::Status(s @ (400 | 401 | 403 | 429), m)) => return Err(Error::api(s, m)),
        Ok(Reply::Status(s, m)) => {
            return Err(unknown(
                format!("AllowIt returned HTTP {s}: {m}"),
                policy,
                op,
            ));
        }
        Ok(Reply::Redirect(s)) => {
            return Err(Error::config(format!(
                "AllowIt answered with a redirect (HTTP {s}); check ALLOWIT_URL"
            )));
        }
        Err(e) if e.config => return Err(e),
        Err(e) => return Err(unknown(e, policy, op)),
    };
    report(value, policy, op, json, stdout)
}

/// Payment and delivery are reported separately. Only a delivered response exits 0;
/// an owner-resolved `unknown` delivery exits 5, as neither failed nor delivered.
fn report(mut v: Value, policy: &str, op: &str, json: bool, stdout: &mut String) -> Result<i32> {
    if v["operationId"].as_str() != Some(op) {
        return Err(unknown(
            "AllowIt returned the result of a different operation",
            policy,
            op,
        ));
    }
    let phase = v["status"].as_str().unwrap_or_default().to_string();
    let (mut state, mut exit) = if phase == "delivered" {
        ("delivered", 0)
    } else if PENDING.contains(&phase.as_str()) {
        ("pending", 12)
    } else if FAILED.contains(&phase.as_str()) {
        ("failed", 20)
    } else if phase == UNKNOWN || phase == "settlement_unknown" {
        ("unknown", 5)
    } else {
        return Err(unknown(
            format!(
                "AllowIt returned an unknown operation status {}",
                quoted(&phase)
            ),
            policy,
            op,
        ));
    };
    let receipts = v["receipts"].as_array().cloned().unwrap_or_default();
    let finalized: Vec<&str> = receipts
        .iter()
        .filter_map(|r| r["signature"].as_str())
        .collect();
    let paid = receipts.iter().any(|r| {
        r["action"]["type"].as_str() == Some("pay")
            && r["signature"].as_str().is_some_and(|s| !s.is_empty())
            && r["finalizedSlot"]
                .as_u64()
                .or_else(|| r["finalizedSlot"].as_str()?.parse().ok())
                .is_some_and(|slot| slot > 0)
    });
    if phase == "failed" && paid {
        state = "unknown";
        exit = 5;
    }
    let payment = if paid {
        "finalized"
    } else {
        match phase.as_str() {
            "evaluating" | "approved" | "preparing" => {
                "not sent; the policy is still checking this call"
            }
            "signed" | "submitted" => "submitted; waiting for finality",
            "denied" => "not sent; the policy denied this call",
            "failed" if receipts.is_empty() => "failed; no payment executed",
            "failed" => "failed after the finalized steps below; the final payment did not execute",
            _ => {
                "unresolved; payment may have been sent, but no finalized payment receipt is available"
            }
        }
    };
    let delivery = match phase.as_str() {
        "delivered" if paid => "delivered",
        "delivered" => "response received; payment remains unresolved",
        "delivering" if paid => {
            "not complete; payment is finalized and the API response is not recovered yet. It is not requested again and no refund is reported"
        }
        "delivering" => {
            "not complete; payment and delivery remain unresolved. Never retry or create a replacement payment; no refund is reported"
        }
        "confirmed" if paid => "not started; payment is finalized",
        "confirmed" => "not started; payment remains unresolved",
        "settlement_unknown" => {
            "unresolved; the execution transaction could not be verified. Payment may have been sent. Never retry or create a replacement payment"
        }
        UNKNOWN if paid => {
            "unknown; payment is finalized and the owner marked delivery unresolved. It is not requested again, it is neither failed nor delivered, and no refund is reported"
        }
        UNKNOWN => {
            "unknown; the owner marked the operation unresolved. Payment may have been sent. It is neither failed nor delivered. Never retry or create a replacement payment; no refund is reported"
        }
        "failed" if paid => {
            "unresolved after finalized payment. Never retry or create a replacement payment"
        }
        "denied" | "failed" => "not delivered",
        _ => "waiting for payment",
    };
    let note = match exit {
        0 if paid => "The API response was delivered after a finalized payment.".to_string(),
        0 => {
            "The API response was received. No finalized payment receipt was provided.".to_string()
        }
        12 => format!(
            "Not complete. Check again with: allowit paysh status {policy} {op}. Never retry with a new OPERATION_ID."
        ),
        5 => "Operation unresolved. Never create a replacement payment for this call.".to_string(),
        _ => "No API response was delivered.".to_string(),
    };
    if json {
        v["state"] = json!(state);
        v["exitCode"] = json!(exit);
        v["paymentFinalized"] = json!(paid);
        *stdout += &output::json(&v);
        return Ok(exit);
    }
    *stdout += &format!(
        "operation: {op}\nstate: {state}\nstatus: {}\npayment: {payment}\n",
        one_line(&phase)
    );
    for r in &receipts {
        let a = &r["action"];
        let what = match a["type"].as_str() {
            Some("swap") => format!(
                "swap {} lamports in, at least {} test-token units out",
                a["amountInLamports"], a["minOutUsdc"]
            ),
            Some("pay") => format!("pay {} test-token units", a["amountUsdc"]),
            _ => "unrecognized action".into(),
        };
        *stdout += &format!(
            "  {what}; slot {}; signature {}\n",
            r["finalizedSlot"],
            one_line(r["signature"].as_str().unwrap_or("?"))
        );
    }
    for s in v["signatures"].as_array().into_iter().flatten() {
        if let Some(s) = s.as_str().filter(|s| !finalized.contains(s)) {
            *stdout += &format!("  unverified signature {}\n", one_line(s));
        }
    }
    *stdout += &format!("delivery: {delivery}\n");
    if phase == "delivered" {
        let mut shown =
            serde_json::to_string_pretty(&v["response"]).expect("JSON values serialize");
        if shown.len() > MAX_SHOWN {
            let cut = (0..=MAX_SHOWN)
                .rev()
                .find(|i| shown.is_char_boundary(*i))
                .unwrap_or(0);
            shown.truncate(cut);
            shown += "\n… truncated; use --json for the full response";
        }
        *stdout += &format!("response:\n{shown}\n");
    }
    *stdout += &format!("{note}\n");
    Ok(exit)
}
