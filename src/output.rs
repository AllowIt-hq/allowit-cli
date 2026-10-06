use crate::{
    error::{Error, Result, quoted},
    skill::{Network, text},
};
use serde_json::Value;
pub(crate) struct ResultState {
    pub state: String,
    pub exit: i32,
    pub note: String,
}
impl ResultState {
    fn new(state: &str, exit: i32, note: &str) -> Self {
        Self {
            state: state.into(),
            exit,
            note: note.into(),
        }
    }
}
pub(crate) fn classify(r: &Value, command: &str) -> ResultState {
    let outcome = text(&r["outcome"]);
    let status = text(&r["status"]);
    let mut kind = text(&r["kind"]);
    if kind.is_empty() {
        kind = match command {
            "eval" => "judgment",
            "exec" => "transaction",
            _ => "",
        };
    }
    if r["localRecorded"] == true || status == "recorded" {
        ResultState::new(
            "recorded",
            0,
            "Local dev: the action was recorded against the policy budget. No funds moved; a mock receipt is not proof of payment.",
        )
    } else if r["executed"] == true || status == "settled" {
        ResultState::new("settled", 0, "The transfer is confirmed on chain.")
    } else if outcome == "awaiting_input" {
        ResultState::new(
            "awaiting_input",
            11,
            "The owner must answer this question in AllowIt. Stop, report the prompt, then check again with `allowit status`.",
        )
    } else if outcome == "pending" {
        ResultState::new(
            "pending",
            12,
            "The policy is still evaluating. Check again with `allowit status`.",
        )
    } else if outcome != "pass" {
        ResultState::new("denied", 20, "The policy did not permit this request.")
    } else if status == "submitted" {
        ResultState::new(
            "owner_signature",
            10,
            "The owner's wallet transaction was submitted and is waiting for network confirmation. Nothing is confirmed yet.",
        )
    } else if status == "ready" && kind == "judgment" {
        ResultState::new(
            "passed",
            0,
            "The policy permits this exact request. Nothing was spent or reserved.",
        )
    } else if status == "ready" && kind == "transaction" {
        ResultState::new(
            "owner_signature",
            10,
            "The policy passed. The owner must review and sign this transfer in AllowIt; nothing has been paid yet.",
        )
    } else {
        ResultState::new(
            "ready",
            10,
            "The policy passed, but this request is not complete: nothing is confirmed as recorded or paid. Check again with `allowit status`.",
        )
    }
}
pub(crate) fn check_result(r: &Value, command: &str, net: Network) -> Result<()> {
    if r.is_null() {
        return Err(Error::uncertain("AllowIt returned an empty result"));
    }
    let Some(outcome) = r["outcome"].as_str() else {
        return Err(Error::uncertain(
            "AllowIt returned a result without an outcome",
        ));
    };
    for k in ["status", "kind", "requestId"] {
        if !r[k].is_null() && !r[k].is_string() {
            return Err(Error::uncertain(format!(
                "AllowIt returned a result with an invalid {k}"
            )));
        }
    }
    for k in ["executed", "localRecorded"] {
        if !r[k].is_null() && !r[k].is_boolean() {
            return Err(Error::uncertain(format!(
                "AllowIt returned a result with an invalid {k}"
            )));
        }
    }
    let status = text(&r["status"]);
    let kind = text(&r["kind"]);
    let good = match outcome {
        "pass" => ["ready", "submitted", "recorded", "settled"].contains(&status),
        "pending" => status == "evaluating",
        "awaiting_input" => status == "awaiting_input",
        "fail" => status == "denied",
        _ => {
            return Err(Error::uncertain(format!(
                "AllowIt returned an unknown outcome {}",
                quoted(outcome)
            )));
        }
    };
    let msg = if !good {
        format!(
            "AllowIt returned outcome {} with status {}",
            quoted(outcome),
            quoted(status)
        )
    } else if (r["executed"] == true) != (status == "settled") {
        format!(
            "AllowIt returned status {} with executed {}",
            quoted(status),
            go_display(&r["executed"])
        )
    } else if (r["localRecorded"] == true) != (status == "recorded") {
        format!(
            "AllowIt returned status {} with localRecorded {}",
            quoted(status),
            go_display(&r["localRecorded"])
        )
    } else if net == Network::Local && ["settled", "submitted"].contains(&status) {
        "AllowIt reported an on-chain transaction for a Local dev policy".into()
    } else if net == Network::Wallet && status == "recorded" {
        "AllowIt reported a mock recording for a wallet policy".into()
    } else if !kind.is_empty() && !["judgment", "transaction"].contains(&kind) {
        format!("AllowIt returned an unknown kind {}", quoted(kind))
    } else if command == "eval" && kind == "transaction" || command == "exec" && kind == "judgment"
    {
        format!("AllowIt returned a {} result for {command}", quoted(kind))
    } else if (command == "eval" || kind == "judgment")
        && ["settled", "recorded", "submitted"].contains(&status)
    {
        "AllowIt reported a spend for a permission check".into()
    } else {
        return Ok(());
    };
    Err(Error::uncertain(msg))
}
fn go_display(v: &Value) -> String {
    if v.is_null() {
        "<nil>".into()
    } else {
        v.to_string()
    }
}
pub(crate) fn needs_network(r: &Value) -> bool {
    match text(&r["status"]) {
        "recorded" | "settled" | "submitted" => true,
        "ready" => text(&r["kind"]) != "judgment",
        _ => false,
    }
}
pub(crate) fn short(s: &str) -> String {
    String::from_utf8_lossy(&s.as_bytes()[..s.len().min(12)]).into_owned()
}
pub(crate) fn one_line(s: &str) -> String {
    if s.contains(['\r', '\n', '\u{85}', '\u{2028}', '\u{2029}']) {
        quoted(s)
            .replace('\u{85}', "\\u0085")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029")
    } else {
        s.into()
    }
}
pub(crate) fn clean(mut s: String, token: &str) -> String {
    for secret in [token, token.trim()] {
        if !secret.is_empty() {
            s = s.replace(secret, "[redacted]");
        }
    }
    let p: Vec<_> = token.trim().split('.').collect();
    if p.len() == 3 && p[2].len() >= 8 {
        s = s.replace(p[2], "[redacted]");
    }
    s.chars()
        .map(|c| {
            if matches!(c, '\n' | '\t') {
                c
            } else if c < '\u{20}'
                || ('\u{7f}'..'\u{a0}').contains(&c)
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
            {
                '?'
            } else {
                c
            }
        })
        .collect()
}
pub(crate) fn json(v: &Value) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(v)
            .unwrap()
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029")
    )
}
pub(crate) fn print_result(r: &Value, res: &ResultState, id: &str) -> String {
    let mut out = format!("state: {}\n{}\n", res.state, res.note);
    if !id.is_empty() {
        out += &format!("clientRequestId: {id}\n");
    }
    let leading = [
        "outcome",
        "status",
        "kind",
        "reason",
        "decisionCode",
        "workflowNodeId",
        "prompt",
        "requestId",
        "revision",
        "sourceHash",
        "expiresAt",
        "signature",
        "executed",
        "localRecorded",
    ];
    for k in leading {
        field(&mut out, k, &r[k]);
    }
    if let Some(m) = r.as_object() {
        for (k, v) in m {
            if !leading.contains(&k.as_str()) {
                field(&mut out, k, v);
            }
        }
    }
    out
}
fn field(out: &mut String, k: &str, v: &Value) {
    match v {
        Value::Null => {}
        Value::String(s) => {
            if !s.is_empty() {
                *out += &format!("{k}: {}\n", one_line(s));
            }
        }
        Value::Object(m) => {
            for (key, val) in m {
                field(out, &format!("{k}.{key}"), val);
            }
        }
        Value::Array(a) => {
            if a.is_empty() {
                return;
            }
            if a.iter().all(Value::is_string) {
                *out += &format!(
                    "{k}: {}\n",
                    one_line(&a.iter().map(text).collect::<Vec<_>>().join("; "))
                );
            } else {
                for (i, v) in a.iter().enumerate() {
                    field(out, &format!("{k}[{i}]"), v);
                }
            }
        }
        _ => *out += &format!("{k}: {v}\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn contradictory_receipts_are_uncertain() {
        for r in [
            json!({"outcome":"pass","status":"ready","executed":true}),
            json!({"outcome":"pending","status":"denied"}),
            json!({"outcome":"pass","status":"settled","executed":true}),
        ] {
            assert!(check_result(&r, "eval", Network::Local).is_err());
        }
        let r = json!({"outcome":"pass","status":"recorded","localRecorded":true});
        assert!(check_result(&r, "exec", Network::Local).is_ok());
        assert!(check_result(&r, "exec", Network::Wallet).is_err());
    }
    #[test]
    fn credentials_and_terminal_sequences_are_scrubbed() {
        let s = clean(
            "a.b.abcdefghijklmnop \u{1b}[2J abcdefghijklmnop \u{202e}x".into(),
            "a.b.abcdefghijklmnop",
        );
        assert!(!s.contains("abcdefghijklmnop"));
        assert!(!s.contains('\u{1b}'));
        assert!(!s.contains('\u{202e}'));
    }
}
