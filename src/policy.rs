use crate::{
    config::env_value,
    error::{Error, Result, quoted},
    request::{matches, solana_address},
};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
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
    let configured = env_value("ALLOWIT_SDK_CLI");
    let cli = if !configured.is_empty() {
        let path = PathBuf::from(&configured);
        if !path.is_absolute() {
            return Err(Error::config(format!(
                "ALLOWIT_SDK_CLI must be an absolute path to the SDK's cli.mjs, not {}",
                quoted(&configured)
            )));
        }
        if !path.is_file() {
            return Err(Error::config(format!(
                "ALLOWIT_SDK_CLI {} is not a readable file",
                quoted(&configured)
            )));
        }
        path
    } else {
        let self_path=std::env::current_exe().and_then(std::fs::canonicalize).map_err(|e|Error::config(format!("cannot locate the allowit executable ({e}); set ALLOWIT_SDK_CLI to the SDK's cli.mjs")))?;
        let path = self_path.parent().unwrap().join("native-sdk/cli.mjs");
        if !path.is_file() {
            return Err(Error::config(format!(
                "the AllowIt SDK CLI is not installed at {}; set ALLOWIT_SDK_CLI to the absolute path of the SDK's native/cli.mjs",
                path.display()
            )));
        }
        path
    };
    let node = env_value("ALLOWIT_NODE");
    let node = if node.is_empty() { "node" } else { &node };
    let mut command = Command::new(node);
    command
        .arg(cli)
        .arg(name)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if json {
        command.arg("--json");
    }
    if !pos.is_empty() {
        command.arg("--").args(pos);
    }
    // The child shares the terminal process group. Terminal SIGINT reaches it
    // directly; SIGTERM addressed only to this wrapper is forwarded.
    #[cfg(unix)]
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ])
    .map_err(|e| Error::config(format!("cannot monitor SDK CLI signals: {e}")))?;
    let mut child=command.spawn().map_err(|e|Error::config(format!("cannot run the AllowIt SDK CLI with {node} (set ALLOWIT_NODE to a Node 22 executable): {e}")))?;
    #[cfg(unix)]
    let handle = signals.handle();
    #[cfg(unix)]
    let forwarding = {
        let pid = child.id();
        std::thread::spawn(move || {
            for signal in signals.forever() {
                if signal == signal_hook::consts::SIGTERM {
                    let _ = Command::new("/bin/kill")
                        .arg("-TERM")
                        .arg(pid.to_string())
                        .status();
                }
            }
        })
    };
    let status=child.wait().map_err(|e|Error::config(format!("cannot run the AllowIt SDK CLI with {node} (set ALLOWIT_NODE to a Node 22 executable): {e}")));
    #[cfg(unix)]
    {
        handle.close();
        let _ = forwarding.join();
    }
    let status = status?;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(unix)]
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    #[cfg(not(unix))]
    let code = status.code().unwrap_or(3);
    if code != 0 {
        stderr.push_str(&format!(
            "allowit: policy {name}: the SDK CLI exited with status {code}\n"
        ));
    }
    Ok(code)
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
