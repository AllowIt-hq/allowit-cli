mod args;
mod client;
mod config;
mod error;
mod native_audit;
mod output;
mod paysh;
mod policy;
mod policy_native;
mod request;
mod skill;
mod tempo;
mod typed_request;
mod typed_run;
use crate::{
    client::Client,
    config::{Config, env_value},
    error::{Error, Result},
    output::{check_result, classify},
    request::{encode, request_id_valid},
    skill::{Network, Skill, text},
};
use serde_json::{Value, json};
use std::io::Write;
pub const VERSION: &str = "0.3.0-dev";
const USAGE: &str = include_str!("usage.txt");
/// Runs the command with process-local environment and standard streams.
pub fn run(args: Vec<String>) -> i32 {
    let mut stdout = String::new();
    let mut stderr = String::new();
    let result = execute(&args, &mut stdout, &mut stderr);
    let code = match result {
        Ok(c) => c,
        Err(e) => {
            stderr += &format!("allowit: {e}\n");
            e.code
        }
    };
    let stdout = if args.first().is_some_and(|a| a == "policy")
        && serde_json::from_str::<Value>(&stdout).is_ok()
    {
        // Escape display controls within native JSON without changing the
        // parsed policy prompt, identity, or skill content.
        stdout
            .chars()
            .map(|c| {
                if ('\u{7f}'..'\u{a0}').contains(&c)
                    || ('\u{202a}'..='\u{202e}').contains(&c)
                    || ('\u{2066}'..='\u{2069}').contains(&c)
                {
                    format!("\\u{:04x}", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect()
    } else {
        stdout
    };
    let _ = std::io::stdout().write_all(redact(stdout).as_bytes());
    let _ = std::io::stderr().write_all(redact(stderr).as_bytes());
    code
}
/// Removes the harness token and the PaySH capability from any output.
fn redact(s: String) -> String {
    output::clean(
        output::clean(s, &env_value("ALLOWIT_TOKEN")),
        &env_value(paysh::TOKEN_ENV),
    )
}
/// Writes pending stderr now, before a request can leave the process.
pub(crate) fn flush_stderr(stderr: &mut String) {
    let _ = std::io::stderr().write_all(redact(std::mem::take(stderr)).as_bytes());
}
fn execute(args: &[String], stdout: &mut String, stderr: &mut String) -> Result<i32> {
    if args.is_empty() {
        stderr.push_str(USAGE);
        return Ok(2);
    }
    match args[0].as_str() {
        "version" | "--version" => {
            *stdout += &format!("allowit {VERSION}\n");
            Ok(0)
        }
        "help" | "-h" | "--help" => {
            stdout.push_str(USAGE);
            Ok(0)
        }
        "policy" => policy::run(&args[1..], stdout, stderr),
        "paysh" => paysh::run(&args[1..], stdout, stderr),
        "tempo" => tempo::run(&args[1..], stdout, stderr),
        "show" | "eval" | "exec" | "status" => action(&args[0], &args[1..], stdout, stderr),
        _ => Err(Error::usage(format!(
            "unknown command {} (show, eval, exec, status, policy)",
            error::quoted(&args[0])
        ))),
    }
}
fn action(command: &str, argv: &[String], stdout: &mut String, stderr: &mut String) -> Result<i32> {
    let parsed = args::parse(command, argv)?;
    let expected = if command == "status" { 2 } else { 1 };
    if parsed.pos.len() != expected {
        return Err(Error::usage(match command {
            "show" => "usage: allowit show POLICY [--json] [--source]".into(),
            "status" => "usage: allowit status POLICY REQUEST_ID [--wait 60s]".into(),
            _ => format!(
                "usage: allowit {command} POLICY --action ACTION [--rail RAIL --op OP] --addr ADDRESS --amount QUANTITY [--context JSON]"
            ),
        }));
    }
    if parsed.negative_wait || parsed.wait > std::time::Duration::from_secs(600) {
        return Err(Error::usage("--wait must be between 0s and 10m0s"));
    }
    let policy = &parsed.pos[0];
    if command == "status" && !request_id_valid(&parsed.pos[1]) {
        return Err(Error::usage(
            "REQUEST_ID is the requestId printed by eval or exec",
        ));
    }
    if parsed.flags.0.contains_key("request-file") {
        return typed_run::exec(command, &parsed, stderr);
    }
    let id_flag = parsed.flags.get("request-id");
    if !id_flag.is_empty() && !request_id_valid(id_flag) {
        return Err(Error::usage(
            "--request-id must be 8 to 100 characters from A-Z a-z 0-9 . _ : -",
        ));
    }
    let mut c = Client::new(Config::load(policy)?)?;
    if command == "status" {
        return status(&mut c, &parsed, stdout, stderr);
    }
    let s = Skill::read(&mut c)?;
    if command == "show" {
        if parsed.json {
            let mut raw = s.0;
            let map = raw.as_object_mut().ok_or_else(|| {
                Error::unsupported("AllowIt returned an empty policy description")
            })?;
            map.remove("authorization");
            map.remove("accessUrl");
            if !parsed.source {
                map.remove("policy");
            }
            *stdout += &output::json(&raw);
        } else {
            *stdout += &s.show(policy, parsed.source);
        }
        return Ok(0);
    }
    let mut b = request::build_body(command, &parsed.flags, &s, &mut std::io::stdin().lock())?;
    if !parsed.flags.get("budget").is_empty() {
        let want = request::usdc_units(parsed.flags.get("budget"))
            .map_err(|e| Error::usage(format!("--budget: {e}")))?;
        if request::usdc_units(&b.amount).ok() != Some(want) {
            return Err(Error::usage(format!(
                "--budget {} does not match the computed charge of {} USDC",
                parsed.flags.get("budget"),
                b.amount
            )));
        }
    }
    b.request_id = id_flag.into();
    if b.request_id.is_empty() {
        b.request_id = request::derive_id(command, &c.cfg, &mut b);
    }
    *stderr += &format!(
        "allowit: {command} request {} (budget charge {} USDC)\n",
        b.request_id, b.amount
    );
    if command == "exec" {
        *stderr += &format!(
            "allowit: if the result is unknown, retry only with --request-id {}\n",
            b.request_id
        );
    }
    // Flush recovery instructions before a POST can leave the process.
    flush_stderr(stderr);
    let mut r = match c.call(
        "POST",
        if command == "exec" {
            "transactions"
        } else {
            "judge"
        },
        Some(&encode(&b)),
    ) {
        Ok(r) => r,
        Err(e) => {
            if e.code == 5 {
                return Err(Error::uncertain(format!(
                    "{e}\nThe request may have reached AllowIt. Do not retry with a new request ID. Retry only by rerunning the same command with --request-id {}: AllowIt applies a request ID at most once",
                    b.request_id
                )));
            }
            if e.status == Some(409) {
                return Err(Error::uncertain(format!(
                    "{e}\nA request with --request-id {} already exists with different details and may have been applied. Read it with: allowit status --wait 0s -- {policy} {}\nUse a new --request-id only for a different intended operation",
                    b.request_id, b.request_id
                )));
            }
            return Err(e);
        }
    };
    let resent = c.resent;
    let replayed = r["replayed"] == true;
    let created = r.get("createdAt").cloned();
    check_result(&r, command, s.net())
        .map_err(|e| unknown(e, command, &b.request_id, policy, &r))?;
    if text(&r["outcome"]) == "pending" {
        let id = text(&r["requestId"]).to_string();
        if !request_id_valid(&id) {
            return Err(unknown(
                Error::uncertain("AllowIt returned a pending result without a valid requestId"),
                command,
                &b.request_id,
                policy,
                &r,
            ));
        }
        r = poll(&mut c, &id, parsed.wait, &r, command, s.net())
            .map_err(|e| unknown(e, command, &b.request_id, policy, &r))?;
    }
    if replayed {
        r["replayed"] = Value::Bool(true);
        if let Some(v) = created {
            r["createdAt"] = v;
        }
    }
    let mut res = classify(&r, command);
    if r["replayed"] == true {
        if id_flag.is_empty() && !resent {
            r["replayedState"] = json!(res.state);
            res = output::ResultState {
                state: "replayed".into(),
                exit: 6,
                note: format!(
                    "An identical earlier request (derived request ID {}) already has this result; nothing new was submitted. Its state was {}. For another intended operation pass a new --request-id.",
                    b.request_id, res.state
                ),
            };
        } else {
            res.note += " This is the stored result of an earlier request with this --request-id; nothing new was submitted.";
        }
    }
    if parsed.json {
        r["state"] = json!(res.state);
        r["clientRequestId"] = json!(b.request_id);
        r["budgetChargeUSDC"] = json!(b.amount);
        r["exitCode"] = json!(res.exit);
        *stdout += &output::json(&r);
    } else {
        *stdout += &output::print_result(&r, &res, &b.request_id);
        *stdout += &format!("budgetChargeUSDC: {}\n", b.amount);
    }
    Ok(res.exit)
}
fn unknown(e: Error, kind: &str, client_id: &str, policy: &str, r: &Value) -> Error {
    let server_id = text(&r["requestId"]);
    let (label, next) = if request_id_valid(server_id) {
        (
            format!(" (server requestId {server_id})"),
            format!("allowit status --wait 60s -- {policy} {server_id}, or "),
        )
    } else {
        (String::new(), String::new())
    };
    Error::uncertain(format!(
        "{e}\nAllowIt accepted {kind} request {client_id}{label}, but its result is unknown. Do not retry with a new request ID. Check it with {next}rerun the same command with --request-id {client_id}"
    ))
}
fn check_status(r: &Value, id: &str, net: Network) -> Result<()> {
    check_result(r, "status", net)?;
    let got = text(&r["requestId"]);
    if got.is_empty() {
        return Err(Error::uncertain(
            "AllowIt returned a status without its requestId",
        ));
    }
    if got != id && text(&r["clientRequestId"]) != id {
        return Err(Error::uncertain(format!(
            "AllowIt returned the status of a different request ({got})"
        )));
    }
    Ok(())
}
fn poll(
    c: &mut Client,
    id: &str,
    wait: std::time::Duration,
    r: &Value,
    command: &str,
    net: Network,
) -> Result<Value> {
    let start = text(&r["status"]);
    let mut r = r.clone();
    let mut elapsed = std::time::Duration::ZERO;
    while elapsed < wait {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let next = c
            .call("POST", "status", Some(&encode(&json!({"requestId":id}))))
            .map_err(|e| Error::uncertain(format!("checking the request status failed: {e}")))?;
        check_status(&next, id, net)?;
        if command != "status" {
            check_result(&next, command, net)?;
        }
        r = next;
        if text(&r["status"]) != start {
            break;
        }
        elapsed += std::time::Duration::from_secs(2);
    }
    Ok(r)
}
fn status(
    c: &mut Client,
    args: &args::Args,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<i32> {
    let id = &args.pos[1];
    let net = skill::status_network(c, stderr)?;
    let mut r = match c.call("POST", "status", Some(&encode(&json!({"requestId":id})))) {
        Ok(r) => r,
        Err(e) if e.status == Some(404) => match c.call(
            "POST",
            "status",
            Some(&encode(&json!({"clientRequestId":id}))),
        ) {
            Err(e) if e.status == Some(404) => {
                return Err(Error::uncertain(format!(
                    "AllowIt has no request {id} for this policy yet. If an exec with --request-id {id} may have been sent, rerun that identical command: AllowIt applies a request ID at most once"
                )));
            }
            x => x?,
        },
        Err(e) => return Err(e),
    };
    let map_error = |e: Error| {
        Error::uncertain(format!(
            "{e}\nThe state of request {id} is unknown; check again with allowit status"
        ))
    };
    check_status(&r, id, net).map_err(map_error)?;
    let outcome = text(&r["outcome"]);
    if outcome == "pending"
        || (outcome == "awaiting_input" || ["submitted", "ready"].contains(&text(&r["status"])))
            && !args.wait.is_zero()
    {
        r = poll(c, text(&r["requestId"]), args.wait, &r, "status", net).map_err(map_error)?;
    }
    if net == Network::Unknown && output::needs_network(&r) {
        return Err(Error::uncertain(format!(
            "AllowIt reported outcome {} with status {} for request {id}, but the policy's network could not be established, so the CLI cannot tell a Local dev mock recording from a wallet transfer. Nothing is confirmed as recorded, signed or paid. Check again with allowit status once allowit show works",
            error::quoted(text(&r["outcome"])),
            error::quoted(text(&r["status"]))
        )));
    }
    let res = classify(&r, "status");
    if args.json {
        r["state"] = json!(res.state);
        r["exitCode"] = json!(res.exit);
        *stdout += &output::json(&r);
    } else {
        *stdout += &output::print_result(&r, &res, "");
    }
    Ok(res.exit)
}
