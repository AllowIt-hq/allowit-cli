//! Public AllowIt command input. Vendor payment protocols remain on the backend.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Read;
use std::{collections::BTreeMap, path::PathBuf};
use url::Url;

pub(crate) const GROUPS: &[&str] = &[
    "call",
    "curl",
    "wget",
    "http",
    "fetch",
    "claude",
    "codex",
    "whoami",
    "server",
    "serve",
    "gate",
    "catalog",
    "mcp",
    "skills",
    "topup",
    "account",
    "setup",
    "send",
    "subscriptions",
    "install",
];

#[derive(Clone, Debug, Default)]
pub(crate) struct Common {
    pub policy_selector: Option<String>,
    pub sandbox: bool,
    pub account: Option<String>,
    pub operation_id: Option<String>,
    pub rail: Option<String>,
    pub rpc_url: Option<String>,
    pub max_debit: Option<Money>,
    pub currency: Option<String>,
    pub json: bool,
    pub output: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Money {
    pub currency: String,
    pub amount: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpRequest {
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<Header>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Invocation {
    pub group: String,
    pub args: Vec<String>,
    pub common: Common,
    pub help: bool,
}

pub(crate) fn recognizes(args: &[String]) -> bool {
    args.first().is_some_and(|s| {
        GROUPS.contains(&s.as_str())
            || [
                "--policy",
                "--sandbox",
                "--account",
                "--request-id",
                "--operation-id",
                "--rail",
                "--rpc",
                "--max-payment",
                "--budget",
                "--currency",
                "--json",
            ]
            .contains(&s.split('=').next().unwrap_or(s))
    })
}

pub(crate) fn parse(args: &[String]) -> Result<Invocation> {
    let mut common = Common::default();
    let mut rest = Vec::new();
    let mut group = None;
    let mut help = false;
    let mut i = 0;
    let mut literal = false;
    while i < args.len() {
        let arg = &args[i];
        if literal {
            rest.push(arg.clone());
            i += 1;
            continue;
        }
        if arg == "--" {
            literal = true;
            rest.push(arg.clone());
            i += 1;
            continue;
        }
        let (name, inline) = arg
            .split_once('=')
            .map(|(a, b)| (a, Some(b.to_owned())))
            .unwrap_or((arg.as_str(), None));
        let is_value = matches!(
            name,
            "--policy"
                | "--account"
                | "--request-id"
                | "--operation-id"
                | "--rail"
                | "--rpc"
                | "--max-payment"
                | "--budget"
                | "--currency"
        );
        if is_value {
            let value = match inline {
                Some(s) => s,
                None => {
                    i += 1;
                    args.get(i)
                        .cloned()
                        .ok_or_else(|| Error::usage(format!("{name} requires a value")))?
                }
            };
            if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
                return Err(Error::usage(format!("{name} has an invalid value")));
            }
            match name {
                "--policy" => {
                    validate_selector(&value)?;
                    set_once(&mut common.policy_selector, value, name)?;
                }
                "--account" => set_once(&mut common.account, value, name)?,
                "--request-id" | "--operation-id" => {
                    if !crate::request::request_id_valid(&value) {
                        return Err(Error::usage(
                            "--request-id must contain 8 to 100 letters, digits, periods, underscores, colons or hyphens",
                        ));
                    }
                    set_once(&mut common.operation_id, value, name)?;
                }
                "--rail" => set_once(&mut common.rail, value, name)?,
                "--currency" => {
                    if value.len() > 32
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    {
                        return Err(Error::usage("--currency requires a stablecoin symbol"));
                    }
                    if let Some(money) = &mut common.max_debit {
                        money.currency = value.clone();
                    }
                    set_once(&mut common.currency, value, name)?;
                }
                "--rpc" => {
                    public_url(&value)?;
                    set_once(&mut common.rpc_url, value, name)?;
                }
                "--max-payment" | "--budget" => {
                    if common.max_debit.is_some() {
                        return Err(Error::usage("give one payment limit"));
                    }
                    let amount = value.trim_start_matches('$');
                    if amount.is_empty()
                        || !amount.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                        || amount.matches('.').count() > 1
                        || !amount.bytes().any(|b| b.is_ascii_digit())
                    {
                        return Err(Error::usage("--max-payment requires a decimal USD amount"));
                    }
                    common.max_debit = Some(Money {
                        currency: common.currency.clone().unwrap_or_else(|| "USDC".into()),
                        amount: amount.into(),
                    });
                }
                _ => unreachable!(),
            }
        } else if name == "--sandbox" {
            if inline.is_some() {
                return Err(Error::usage("--sandbox does not take a value"));
            }
            common.sandbox = true;
        } else if name == "--json" {
            common.json = true;
        } else if matches!(name, "--help" | "-h") && group.is_some() {
            help = true;
        } else if group.is_none() && GROUPS.contains(&arg.as_str()) {
            group = Some(arg.clone());
        } else if group.is_none() {
            return Err(Error::usage(
                "expected an AllowIt command after global flags",
            ));
        } else {
            rest.push(arg.clone());
        }
        i += 1;
    }
    if common.rail.is_some() != common.rpc_url.is_some() {
        return Err(Error::usage("provide --rail and the exact --rpc together"));
    }
    Ok(Invocation {
        group: group.ok_or_else(|| Error::usage("expected an AllowIt command"))?,
        args: rest,
        common,
        help,
    })
}

fn set_once(slot: &mut Option<String>, value: String, name: &str) -> Result<()> {
    if slot.is_some() {
        return Err(Error::usage(format!("{name} may be given only once")));
    }
    *slot = Some(value);
    Ok(())
}

pub(crate) fn validate_selector(value: &str) -> Result<()> {
    let Some((version, address)) = value.split_once('@') else {
        return Err(Error::usage("--policy requires version@addr"));
    };
    if version.is_empty()
        || version.len() > 128
        || address.is_empty()
        || address.len() > 256
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        || !address
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_:-".contains(&b))
    {
        return Err(Error::usage(
            "--policy requires one bounded version@addr selector",
        ));
    }
    Ok(())
}

pub(crate) fn public_url(raw: &str) -> Result<Url> {
    let u =
        Url::parse(raw).map_err(|_| Error::usage("request URL must be an absolute HTTP(S) URL"))?;
    if !matches!(u.scheme(), "http" | "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
    {
        return Err(Error::usage(
            "request URL must use HTTP(S), without credentials or a fragment",
        ));
    }
    Ok(u)
}

fn header(raw: &str) -> Result<Header> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| Error::usage("--header requires Name: value"))?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        || value.contains(['\r', '\n'])
    {
        return Err(Error::usage("invalid HTTP header"));
    }
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "authorization"
            | "cookie"
            | "proxy-authorization"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "x-payment"
    ) || lower.starts_with("payment-")
    {
        return Err(Error::usage(
            "backend connections own authorization and payment headers",
        ));
    }
    Ok(Header {
        name: name.into(),
        value: value.into(),
    })
}

fn body_file(path: &str) -> Result<String> {
    let meta =
        std::fs::metadata(path).map_err(|_| Error::usage("cannot read the explicit body file"))?;
    if !meta.is_file() || meta.len() > 32 << 10 {
        return Err(Error::usage(
            "body file must be a regular file no larger than 32768 bytes",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|_| Error::usage("cannot open the explicit body file"))?;
    if !file
        .metadata()
        .map_err(|_| Error::usage("cannot inspect body file"))?
        .is_file()
    {
        return Err(Error::usage("body path must remain a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((32 << 10) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::usage("cannot read body file"))?;
    if bytes.len() > 32 << 10 {
        return Err(Error::usage("body file exceeds 32768 bytes"));
    }
    String::from_utf8(bytes).map_err(|_| Error::usage("this HTTP request body requires UTF-8 text"))
}

/// Normalize HTTP tool syntax. No external HTTP tool or merchant transport runs here.
pub(crate) fn http_request(inv: &mut Invocation) -> Result<HttpRequest> {
    let mut method = None;
    let mut headers = vec![];
    let mut body = None;
    let mut target = None;
    let mut fields = BTreeMap::new();
    let mut i = 0;
    let mut literal = false;
    let mut content_type = None;
    let mut forms: Vec<(String, String)> = vec![];
    while i < inv.args.len() {
        let a = &inv.args[i];
        if a == "--" && !literal {
            literal = true;
            i += 1;
            continue;
        }
        let (name, inline) = a
            .split_once('=')
            .filter(|(n, _)| n.starts_with('-'))
            .map(|(n, v)| (n, Some(v.to_owned())))
            .unwrap_or((a.as_str(), None));
        if !literal
            && matches!(
                name,
                "-X" | "--request"
                    | "--method"
                    | "-H"
                    | "--header"
                    | "-d"
                    | "--data"
                    | "--data-raw"
                    | "--data-binary"
                    | "--body"
                    | "--body-data"
                    | "--post-data"
                    | "--body-file"
                    | "--post-file"
                    | "--content-type"
                    | "--form"
                    | "--form-file"
                    | "-o"
                    | "--output"
                    | "-O"
            )
        {
            let v = match inline {
                Some(v) => v,
                None => {
                    i += 1;
                    inv.args
                        .get(i)
                        .cloned()
                        .ok_or_else(|| Error::usage(format!("{name} requires a value")))?
                }
            };
            match name {
                "-X" | "--request" | "--method" => method = Some(v.to_ascii_uppercase()),
                "-H" | "--header" => headers.push(header(&v)?),
                "-o" | "--output" | "-O" => inv.common.output = Some(v.into()),
                "--content-type" => {
                    header(&format!("Content-Type: {v}"))?;
                    content_type = Some(v);
                }
                "--form" | "--form-file" => {
                    let (k, value) = v
                        .split_once('=')
                        .ok_or_else(|| Error::usage("form fields require NAME=VALUE"))?;
                    if k.is_empty() || k.contains(['\r', '\n', '"']) {
                        return Err(Error::usage("invalid form field name"));
                    }
                    forms.push((
                        k.into(),
                        if name == "--form-file" {
                            body_file(value)?
                        } else {
                            value.into()
                        },
                    ));
                }
                _ => {
                    let v = if matches!(name, "--body-file" | "--post-file") {
                        body_file(&v)?
                    } else if name != "--data-raw" && v.starts_with('@') {
                        body_file(&v[1..])?
                    } else {
                        v
                    };
                    if body.replace(v).is_some() {
                        return Err(Error::usage("give one request body"));
                    }
                }
            }
        } else if !literal
            && matches!(
                name,
                "-s" | "--silent" | "-S" | "--show-error" | "-f" | "--fail" | "--yes" | "-y"
            )
        {
            // These local display/confirmation flags never select a payment protocol.
        } else if target.is_none()
            && ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].contains(&a.as_str())
            && inv.group == "http"
        {
            method = Some(a.clone());
        } else if a.starts_with("https://") || a.starts_with("http://") {
            if target.replace(a.clone()).is_some() {
                return Err(Error::usage("one URL is allowed per operation"));
            }
        } else if inv.group == "http" && a.contains('=') && !a.starts_with('-') {
            let (k, v) = a.split_once('=').unwrap();
            fields.insert(k.to_owned(), Value::String(v.to_owned()));
        } else {
            return Err(Error::usage(format!(
                "unsupported {} argument {}",
                inv.group,
                crate::error::quoted(a)
            )));
        }
        i += 1;
    }
    if !fields.is_empty() {
        if body.is_some() || !forms.is_empty() {
            return Err(Error::usage(
                "HTTPie fields and other bodies cannot be combined",
            ));
        }
        body = Some(serde_json::to_string(&fields).unwrap());
        content_type = Some("application/json".into());
    }
    if !forms.is_empty() {
        if body.is_some() {
            return Err(Error::usage("form fields and --body cannot be combined"));
        }
        let boundary = format!("AllowItBoundary{}", std::process::id());
        let mut encoded = String::new();
        for (k, v) in forms {
            encoded += &format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
            );
        }
        encoded += &format!("--{boundary}--\r\n");
        body = Some(encoded);
        content_type = Some(format!("multipart/form-data; boundary={boundary}"));
    }
    if let Some(mime) = content_type {
        headers.retain(|h| !h.name.eq_ignore_ascii_case("content-type"));
        headers.push(Header {
            name: "Content-Type".into(),
            value: mime,
        });
    } else if body.is_some()
        && !headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("content-type"))
    {
        headers.push(Header {
            name: "Content-Type".into(),
            value: if inv.group == "curl" {
                "application/x-www-form-urlencoded"
            } else {
                "text/plain"
            }
            .into(),
        });
    }
    let method = method.unwrap_or_else(|| {
        if body.is_some() {
            "POST".into()
        } else {
            "GET".into()
        }
    });
    if !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].contains(&method.as_str()) {
        return Err(Error::usage("unsupported HTTP request method"));
    }
    let url = target.ok_or_else(|| {
        Error::usage(format!(
            "usage: allowit {} URL [request options]",
            inv.group
        ))
    })?;
    public_url(&url)?;
    if body.as_ref().is_some_and(|s| s.len() > 32 << 10) {
        return Err(Error::usage("request body exceeds 32768 bytes"));
    }
    Ok(HttpRequest {
        method,
        url,
        headers,
        body,
    })
}

pub(crate) fn call_target(
    inv: &Invocation,
) -> Result<(Option<String>, Option<HttpRequest>, Option<Value>)> {
    let mut args: Vec<&String> = vec![];
    let mut explicit_input: Option<String> = None;
    let mut i = 0;
    while i < inv.args.len() {
        let arg = &inv.args[i];
        if arg == "--" {
            i += 1;
            continue;
        }
        if matches!(arg.as_str(), "--input" | "--input-file") {
            i += 1;
            let value = inv.args.get(i).ok_or_else(|| {
                Error::usage("--input requires JSON and --input-file requires a path")
            })?;
            let raw = if arg == "--input-file" {
                body_file(value)?
            } else {
                value.clone()
            };
            if explicit_input.replace(raw).is_some() {
                return Err(Error::usage("give JSON input only once"));
            }
        } else if let Some(value) = arg.strip_prefix("--input=") {
            if explicit_input.replace(value.into()).is_some() {
                return Err(Error::usage("give JSON input only once"));
            }
        } else if arg.starts_with('-') {
            return Err(Error::usage("unknown allowit call option"));
        } else {
            args.push(arg);
        }
        i += 1;
    }
    let target = args.first().ok_or_else(|| {
        Error::usage(
            "usage: allowit call SERVICE_OR_URL [--input JSON] [--policy version@addr] [--sandbox]",
        )
    })?;
    if args.len() > 2 {
        return Err(Error::usage(
            "allowit call accepts one target and one JSON input",
        ));
    }
    if explicit_input.is_some() && args.len() > 1 {
        return Err(Error::usage("give JSON input only once"));
    }
    let raw = explicit_input.as_ref().or_else(|| args.get(1).copied());
    let input = if let Some(raw) = raw {
        if raw.len() > 32 << 10 {
            return Err(Error::usage("input exceeds 32768 bytes"));
        }
        Some(serde_json::from_str(raw).map_err(|_| Error::usage("INPUT_JSON must be valid JSON"))?)
    } else {
        None
    };
    if target.starts_with("http://") || target.starts_with("https://") {
        public_url(target)?;
        let body = input.as_ref().map(Value::to_string);
        Ok((
            None,
            Some(HttpRequest {
                method: if body.is_some() {
                    "POST".into()
                } else {
                    "GET".into()
                },
                url: (*target).clone(),
                headers: if body.is_some() {
                    vec![Header {
                        name: "Content-Type".into(),
                        value: "application/json".into(),
                    }]
                } else {
                    vec![]
                },
                body,
            }),
            None,
        ))
    } else {
        if target.len() > 300
            || !target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
        {
            return Err(Error::usage("service name contains unsupported characters"));
        }
        Ok((Some((*target).clone()), None, input))
    }
}

pub(crate) fn context(common: &Common) -> Value {
    let mut v = json!({"sandbox":common.sandbox});
    for (k, val) in [
        ("policySelector", &common.policy_selector),
        ("account", &common.account),
        ("rail", &common.rail),
        ("rpcUrl", &common.rpc_url),
    ] {
        if let Some(s) = val {
            v[k] = json!(s);
        }
    }
    if let Some(m) = &common.max_debit {
        v["maxDebitMoney"] = json!(m);
    }
    v
}

pub(crate) fn query_context(common: &Common) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in [
        ("account", &common.account),
        ("policySelector", &common.policy_selector),
        ("rail", &common.rail),
        ("rpcUrl", &common.rpc_url),
    ] {
        if let Some(s) = v {
            query.append_pair(k, s);
        }
    }
    query.append_pair("sandbox", if common.sandbox { "true" } else { "false" });
    query.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn policy_is_explicit_version_selector() {
        let v = parse(&args(&[
            "call",
            "hash",
            "--policy",
            "v1@wallet",
            "--sandbox",
        ]))
        .unwrap();
        assert_eq!(v.common.policy_selector.as_deref(), Some("v1@wallet"));
        assert!(v.common.sandbox);
        assert!(parse(&args(&["call", "hash", "--policy", "policy-id"])).is_err());
        assert!(
            parse(&args(&["call", "hash"]))
                .unwrap()
                .common
                .policy_selector
                .is_none()
        );
    }
    #[test]
    fn http_adapters_do_not_accept_payment_headers() {
        let mut i = parse(&args(&[
            "curl",
            "https://example.com",
            "-H",
            "Payment-Signature: forged",
        ]))
        .unwrap();
        assert!(http_request(&mut i).is_err());
    }
    #[test]
    fn curl_body_is_bound_to_backend_request() {
        let mut i = parse(&args(&[
            "curl",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            "{\"q\":\"x\"}",
            "https://example.com",
        ]))
        .unwrap();
        let r = http_request(&mut i).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.body.as_deref(), Some("{\"q\":\"x\"}"));
    }
}
