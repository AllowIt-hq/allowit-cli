use crate::{
    error::{Error, Result, quoted},
    request::{matches, solana_address},
};
const USAGE: &str = include_str!("policy-usage.txt");
pub(crate) fn run(args: &[String], stdout: &mut String, stderr: &mut String) -> Result<i32> {
    if args.is_empty() {
        stderr.push_str(USAGE);
        return Ok(2);
    }
    let name = args[0].as_str();
    if ["help", "-h", "--help", "-help"].contains(&name) {
        stdout.push_str(USAGE);
        return Ok(0);
    }
    let parameters: &[&str] = match name {
        "generate" => &["PROMPT"],
        "import" => &["EXECUTOR_JSON"],
        "deploy" | "status" | "revoke" => &[],
        "fund" | "withdraw" => &["AMOUNT"],
        "execute" => &["RECIPIENT", "AMOUNT"],
        "tune" => &["VALUE"],
        _ => {
            return Err(Error::usage(format!(
                "unknown policy command {} (generate, import, deploy, fund, execute, status, revoke, withdraw, tune)",
                quoted(name)
            )));
        }
    };
    let synopsis = format!(
        "allowit policy {name}{} [--json]",
        if parameters.is_empty() {
            String::new()
        } else {
            format!(" {}", parameters.join(" "))
        }
    );
    let mut pos = Vec::new();
    let mut json = false;
    let mut help = false;
    let mut literal = false;
    for a in &args[1..] {
        if literal {
            pos.push(a.clone());
            continue;
        }
        match a.as_str() {
            "--" => literal = true,
            "--json" | "-json" => json = true,
            "-h" | "--help" | "-help" => help = true,
            _ if a.starts_with('-') && a != "-" => {
                return Err(Error::usage(format!(
                    "unknown flag {a} (only --json is accepted; put -- before a PROMPT that begins with -)"
                )));
            }
            _ => pos.push(a.clone()),
        }
    }
    if help {
        stdout.push_str(&format!("usage: {synopsis}\n\n{USAGE}"));
        return Ok(0);
    }
    if pos.len() != parameters.len() {
        return Err(Error::usage(format!(
            "usage: {synopsis}{}",
            if name == "generate" && pos.len() > 1 {
                " (quote the prompt so it is one argument)"
            } else {
                ""
            }
        )));
    }
    if pos.iter().any(|p| p.contains('\0')) {
        return Err(Error::usage("arguments must not contain NUL characters"));
    }
    match name {
        "generate" if pos[0].trim().is_empty() => {
            return Err(Error::usage("PROMPT must not be empty"));
        }
        "fund" | "withdraw" => decimal("AMOUNT", &pos[0], true)?,
        "execute" => {
            if !solana_address(&pos[0]) {
                return Err(Error::usage(format!(
                    "RECIPIENT {} is not a Solana token account address",
                    quoted(&pos[0])
                )));
            }
            decimal("AMOUNT", &pos[1], true)?;
        }
        "tune" => decimal("VALUE", &pos[0], false)?,
        _ => {}
    }
    crate::policy_native::run(name, &pos, json, stdout, stderr)
}
fn decimal(name: &str, v: &str, positive: bool) -> Result<()> {
    if v.len() > 40
        || !matches(v, r"^(0|[1-9][0-9]*)(\.[0-9]+)?$")
        || positive && v.trim_matches(['0', '.']).is_empty()
    {
        return Err(Error::usage(format!(
            "{name} {} must be {} such as 5 or 0.25 (no sign, exponent or separator)",
            quoted(v),
            if positive {
                "a positive decimal"
            } else {
                "a non-negative decimal"
            }
        )));
    }
    Ok(())
}
