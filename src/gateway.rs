//! Backend-owned service access. This client never constructs vendor payment proofs.
use crate::{
    VERSION,
    config::{env_value, parse_origin},
    error::{Error, Result},
    gateway_args::{self, Common},
    output,
};
use reqwest::{blocking::Client, redirect::Policy, tls::Version};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) const ACCOUNT_TOKEN_ENV: &str = "ALLOWIT_ACCOUNT_TOKEN";
const MAX_REPLY: usize = 2 << 20;
type RawHttpReply = (u16, Vec<(String, String)>, Vec<u8>);
pub(crate) const HELP: &str = "AllowIt service commands:\n  allowit call SERVICE_OR_URL [--input JSON] [--policy version@addr] [--sandbox]\n  allowit curl|wget|http|fetch URL [HTTP options]\n  allowit claude|codex -- [native arguments]\n  allowit whoami\n  allowit account [list|new|import|default|remove|export]\n  allowit setup | topup | send | subscriptions\n  allowit gate|server demo|api|inference|scaffold\n  allowit catalog | skills | install | mcp\n\nCommon flags: --policy version@addr, --sandbox, --account NAME,\n  --request-id ID, --rail RAIL, --rpc URL, --max-payment AMOUNT [--currency USDC], --json.\nPlain calls use the selected account through ALLOWIT_ACCOUNT_TOKEN.\nExplicit --policy uses ALLOWIT_TOKEN and backend policy authorization.\nProduction requires an actively deployed policy revision. Sandbox does not authorize a production RPC.\nA quote is not a payment or a delivery receipt. No vendor payment key is loaded locally.\n";

pub(crate) struct Gateway {
    origin: String,
    token: String,
    http: Client,
}
impl Gateway {
    pub(crate) fn new(common: &Common) -> Result<Self> {
        let name = if common.policy_selector.is_some() {
            "ALLOWIT_TOKEN"
        } else {
            ACCOUNT_TOKEN_ENV
        };
        let token = env_value(name);
        if token.is_empty() {
            return Err(Error::config(format!(
                "set {name} to the {} capability issued by the AllowIt owner app",
                if common.policy_selector.is_some() {
                    "policy"
                } else {
                    "selected account"
                }
            )));
        }
        if token.len() < 16
            || token.len() > 4096
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(Error::config(format!(
                "{name} must contain the capability exactly as issued"
            )));
        }
        if common.policy_selector.is_some() {
            let p = token.split('.').collect::<Vec<_>>();
            if p.len() != 3 || p[0].is_empty() || p[1].is_empty() || p[2].len() < 16 {
                return Err(Error::config(
                    "ALLOWIT_TOKEN must be an owner.policy.secret capability",
                ));
            }
        }
        Self::connect(token)
    }
    pub(crate) fn public() -> Result<Self> {
        Self::connect(String::new())
    }
    fn connect(token: String) -> Result<Self> {
        let origin = parse_origin(&env_value("ALLOWIT_URL"))?;
        let mut builder = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(60))
            .min_tls_version(Version::TLS_1_2);
        let ca = env_value("ALLOWIT_CA_FILE");
        if !ca.is_empty() {
            let pem = std::fs::read(ca).map_err(|_| {
                Error::config("ALLOWIT_CA_FILE must name a readable PEM certificate file")
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| Error::config("ALLOWIT_CA_FILE must contain PEM certificates"))?;
            if certs.is_empty() {
                return Err(Error::config(
                    "ALLOWIT_CA_FILE must contain PEM certificates",
                ));
            }
            for c in certs {
                builder = builder.add_root_certificate(c);
            }
        }
        Ok(Self {
            origin,
            token,
            http: builder
                .build()
                .map_err(|_| Error::config("cannot configure the AllowIt HTTP client"))?,
        })
    }
    /// One request. A payment-bearing POST is never resent after uncertainty.
    pub(crate) fn send(&self, method: &str, route: &str, body: Option<&Value>) -> Result<Value> {
        if !route.starts_with("/api/gateway/") {
            return Err(Error::unsupported(
                "gateway route is outside the AllowIt API",
            ));
        }
        let mut r = self
            .http
            .request(
                method
                    .parse()
                    .map_err(|_| Error::usage("invalid backend request method"))?,
                format!("{}{route}", self.origin),
            )
            .header("Accept", "application/json")
            .header("User-Agent", format!("allowit-cli/{VERSION}"));
        if !self.token.is_empty() {
            r = r.bearer_auth(&self.token);
        }
        if let Some(b) = body {
            let raw = serde_json::to_vec(b).map_err(|_| Error::usage("cannot encode request"))?;
            if raw.len() > 64 << 10 {
                return Err(Error::usage("AllowIt request exceeds 65536 bytes"));
            }
            r = r.header("Content-Type", "application/json").body(raw);
        }
        let mut response = r.send().map_err(|_| {
            Error::uncertain("connection to AllowIt failed; no automatic retry was made")
        })?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        Read::by_ref(&mut response)
            .take(MAX_REPLY as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                Error::uncertain("cannot read AllowIt response; no automatic retry was made")
            })?;
        if bytes.len() > MAX_REPLY {
            return Err(Error::uncertain("AllowIt response exceeds the 2 MB limit"));
        }
        if (300..400).contains(&status) {
            return Err(Error::uncertain(
                "AllowIt returned a redirect; the capability was not forwarded",
            ));
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::uncertain("AllowIt returned invalid JSON"))?;
        if !value.is_object() {
            return Err(Error::uncertain("AllowIt response must be a JSON object"));
        }
        if !(200..300).contains(&status) {
            let code = value.get("code").and_then(Value::as_str).unwrap_or("");
            let message = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("request rejected");
            if matches!(code, "PAYMENT_UNCERTAIN" | "OPERATION_PENDING") || status >= 500 {
                return Err(Error::uncertain(format!(
                    "AllowIt returned HTTP {status}; operation outcome requires status lookup"
                )));
            }
            if matches!(
                code,
                "POLICY_DENIED"
                    | "POLICY_NOT_ACTIVE"
                    | "DEPLOYMENT_BINDING_MISMATCH"
                    | "SANDBOX_BINDING_REQUIRED"
            ) {
                return Err(Error {
                    code: 20,
                    message: format!("{}: {}", output::one_line(code), output::one_line(message)),
                    status: Some(status),
                    config: false,
                });
            }
            return Err(Error::api(status, output::one_line(message)));
        }
        Ok(value)
    }
    /// Relay a caller's request to one pre-advertised backend resource. No owner token is forwarded.
    pub(crate) fn relay_registered(
        &self,
        path: &str,
        query: &str,
        method: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<RawHttpReply> {
        if !path.starts_with("/api/providers/")
            || path.contains(['?', '#', '\\'])
            || body.len() > 65536
            || query.len() > 4096
            || query.contains(['#', '\r', '\n'])
        {
            return Err(Error::usage(
                "use one exact registered AllowIt resource path",
            ));
        }
        let exact_url = format!("{}{path}", self.origin);
        if url::Url::parse(&exact_url)
            .ok()
            .is_none_or(|u| u.path() != path)
        {
            return Err(Error::usage("registered resource path is not canonical"));
        }
        let mut request = self.http.request(
            method
                .parse()
                .map_err(|_| Error::usage("invalid resource method"))?,
            if query.is_empty() {
                exact_url
            } else {
                format!("{exact_url}?{query}")
            },
        );
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if [
                "host",
                "connection",
                "content-length",
                "transfer-encoding",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "trailer",
                "te",
                "upgrade",
                "cookie",
            ]
            .contains(&lower.as_str())
            {
                continue;
            }
            if lower == "authorization" && !value.to_ascii_lowercase().starts_with("payment ") {
                continue;
            }
            request = request.header(name, value);
        }
        let mut response = request
            .body(body)
            .send()
            .map_err(|_| Error::uncertain("registered backend resource connection failed"))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_owned())))
            .collect();
        let mut bytes = vec![];
        Read::by_ref(&mut response)
            .take(MAX_REPLY as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::uncertain("cannot read registered resource response"))?;
        if bytes.len() > MAX_REPLY {
            return Err(Error::uncertain(
                "registered resource response exceeds 2 MB",
            ));
        }
        Ok((status, headers, bytes))
    }
}

pub(crate) fn run(args: &[String], stdout: &mut String, stderr: &mut String) -> Result<i32> {
    let mut inv = gateway_args::parse(args)?;
    if inv.help {
        stdout.push_str(&command_help(&inv.group));
        return Ok(0);
    }
    match inv.group.as_str() {
        "call" => {
            if inv.args.first().is_some_and(|s| s == "status") {
                if inv.args.len() != 2 {
                    return Err(Error::usage(
                        "usage: allowit call status OPERATION_ID [--policy version@addr]",
                    ));
                }
                if !crate::request::request_id_valid(&inv.args[1]) {
                    return Err(Error::usage("status requires the original operation ID"));
                }
                let mut c = gateway_args::context(&inv.common);
                c["operationId"] = json!(inv.args[1]);
                let v = Gateway::new(&inv.common)?.send(
                    "POST",
                    "/api/gateway/operations/status",
                    Some(&c),
                )?;
                if v["operationId"].as_str() != Some(inv.args[1].as_str()) {
                    return Err(Error::uncertain(
                        "status response does not match the requested operation",
                    ));
                }
                return render_operation(&v, &inv.common, stdout, stderr);
            }
            let (service, request, input) = gateway_args::call_target(&inv)?;
            let mut q = gateway_args::context(&inv.common);
            if let Some(s) = service {
                q["serviceId"] = json!(s);
            }
            if let Some(r) = request {
                q["request"] = json!(r);
            }
            if let Some(i) = input {
                q["input"] = i;
            }
            purchase(q, &inv.common, stdout, stderr)
        }
        "curl" | "wget" | "http" | "fetch" => {
            let r = gateway_args::http_request(&mut inv)?;
            let mut q = gateway_args::context(&inv.common);
            q["request"] = json!(r);
            purchase(q, &inv.common, stdout, stderr)
        }
        "claude" | "codex" => crate::gateway_agents::run(&inv.group, &inv.args, &inv.common),
        "mcp" => crate::gateway_mcp::run(&inv, stdout, stderr),
        "server" | "serve" | "gate" => crate::gateway_server::run(&inv, stdout, stderr),
        _ => crate::gateway_control::run(&inv, stdout, stderr),
    }
}

pub(crate) fn operation_id(common: &Common, request: &Value) -> String {
    if let Some(id) = &common.operation_id {
        return id.clone();
    }
    // A fresh invocation is a fresh user intent. Recovery uses the printed ID.
    let mut h = Sha256::new();
    h.update(b"allowit-command-operation-v1\0");
    h.update(std::process::id().to_le_bytes());
    h.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    h.update(request.to_string());
    format!("allowit-{:x}", h.finalize())[..48].into()
}

fn recovery_context(common: &Common) -> String {
    let mut result = String::new();
    for (flag, value) in [
        ("--policy", &common.policy_selector),
        ("--account", &common.account),
        ("--rail", &common.rail),
        ("--rpc", &common.rpc_url),
    ] {
        if let Some(v) = value {
            result += &format!(" {flag} '{}'", v.replace('\'', "'\\''"));
        }
    }
    if common.sandbox {
        result += " --sandbox";
    }
    result
}

pub(crate) fn purchase(
    mut quote: Value,
    common: &Common,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<i32> {
    let id = operation_id(common, &quote);
    quote["operationId"] = json!(id);
    let client = Gateway::new(common)?;
    let response = client.send("POST", "/api/gateway/quote", Some(&quote))?;
    if response.get("operationId").and_then(Value::as_str) != Some(&id)
        || response.get("state").and_then(Value::as_str) != Some("quoted")
    {
        return Err(Error::uncertain(
            "AllowIt quote does not match the requested operation",
        ));
    }
    let quote_id = response
        .get("quoteId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| Error::uncertain("AllowIt quote lacks a valid quoteId"))?;
    if response
        .get("requestDigest")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Error::uncertain("AllowIt quote lacks its request binding"));
    }
    let expires = response
        .get("expiresAt")
        .and_then(Value::as_str)
        .and_then(|s| {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
        })
        .filter(|t| *t > time::OffsetDateTime::now_utc());
    if expires.is_none() {
        return Err(Error::uncertain(
            "AllowIt quote is expired or lacks a valid expiration",
        ));
    }
    let mut call = gateway_args::context(common);
    call["operationId"] = json!(id);
    call["quoteId"] = json!(quote_id);
    if common.max_debit.is_none()
        && let Some(limit) = response.get("maxDebitMoney")
    {
        call["maxDebitMoney"] = limit.clone();
    }
    let recovery = format!("allowit call status {id}{}", recovery_context(common));
    *stderr += &format!("allowit: operation {id}; if uncertain, check with {recovery}\n");
    crate::flush_stderr(stderr);
    let value = client
        .send("POST", "/api/gateway/call", Some(&call))
        .map_err(|mut e| {
            if e.code == 5 {
                e.message += &format!("; check {recovery}; do not create a new operation ID");
            }
            e
        })?;
    if value.get("operationId").and_then(Value::as_str) != Some(&id) {
        return Err(Error::uncertain(format!(
            "AllowIt response does not match operation {id}; check its status"
        )));
    }
    if response.get("payment").is_some_and(Value::is_object)
        && matches!(value["state"].as_str(), Some("settled" | "delivered"))
    {
        let paid = &response["payment"];
        let settlement = &value["settlement"];
        if settlement["finalized"] != true
            || settlement["transactionId"]
                .as_str()
                .is_none_or(str::is_empty)
            || settlement["receiptDigest"]
                .as_str()
                .is_none_or(str::is_empty)
            || settlement["rail"] != paid["rail"]
            || settlement["network"] != paid["network"]
        {
            return Err(Error::uncertain(format!(
                "operation {id} lacks its matching finalized payment receipt; inspect status before retrying"
            )));
        }
    }
    render_operation(&value, common, stdout, stderr)
}

pub(crate) fn render_operation(
    value: &Value,
    common: &Common,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<i32> {
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::uncertain("AllowIt operation lacks a known state"))?;
    let exit = match state {
        "delivered" => 0,
        "denied" => 20,
        "awaiting_input" => 11,
        "pending" | "settled" => 12,
        "failed" => 4,
        "unknown" => 5,
        _ => {
            return Err(Error::uncertain(
                "AllowIt returned an unknown operation state",
            ));
        }
    };
    let delivered = if state == "delivered" {
        let result = value
            .get("result")
            .filter(|v| v.is_object())
            .ok_or_else(|| Error::uncertain("delivered operation lacks its resource result"))?;
        let status = result
            .get("status")
            .and_then(Value::as_u64)
            .filter(|n| (100..=599).contains(n))
            .ok_or_else(|| Error::uncertain("delivered result lacks a valid HTTP status"))?;
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::uncertain("delivered result lacks its response body"))?;
        Some((status, body))
    } else {
        None
    };
    if common.json {
        *stdout += &output::json(value);
        if delivered.is_some_and(|(status, _)| status >= 400) {
            return Ok(4);
        }
    } else if let Some((status, body)) = delivered {
        if let Some(path) = &common.output {
            std::fs::write(path, body)
                .map_err(|_| Error::config("cannot write the selected output file"))?;
        } else {
            stdout.push_str(body);
        }
        if status >= 400 {
            *stderr += &format!("allowit: delivered upstream HTTP {status}\n");
            return Ok(4);
        }
    } else {
        *stderr += &format!(
            "allowit: operation state {state}; settlement and resource delivery remain separate\n"
        );
    }
    Ok(exit)
}

pub(crate) fn command_help(command: &str) -> String {
    let usage = match command {
        "call" => "allowit call SERVICE_OR_URL [--input JSON]\nallowit call status OPERATION_ID",
        "curl" | "wget" | "http" | "fetch" => {
            "allowit COMMAND URL [-X METHOD] [-H 'Name: value'] [-d BODY] [-o FILE]"
        }
        "claude" | "codex" => "allowit COMMAND -- [native arguments]",
        "account" => "allowit account [list|new|import|default|remove|export] [--input JSON]",
        "server" | "serve" | "gate" => "allowit gate demo|api|inference|scaffold [--input JSON]",
        "skills" => {
            "allowit skills search|show|add|remove|list|update|prune-merged|provider [arguments]"
        }
        "catalog" => "allowit catalog scaffold|check|build [arguments]",
        "subscriptions" => "allowit subscriptions [list|new|cancel|status] [--input JSON]",
        "mcp" => "allowit mcp [--policy version@addr] [--sandbox]",
        "install" => "allowit install SOURCE",
        "whoami" => "allowit whoami",
        _ => "allowit COMMAND [--input JSON]",
    };
    format!("{}\n\n{HELP}", usage.replace("COMMAND", command))
}
