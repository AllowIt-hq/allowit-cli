//! Native agent launchers. Payments stay in the remote AllowIt MCP service.
use crate::{
    error::{Error, Result},
    gateway_args::Common,
};
use serde_json::{Value, json};
use std::process::{Command, Stdio};

const CLAUDE_API_ENV: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AWS_API_KEY",
    "ANTHROPIC_AWS_BASE_URL",
    "ANTHROPIC_AWS_WORKSPACE_ID",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_AWS",
    "CLAUDE_CODE_API_KEY_HELPER",
];
const CODEX_API_ENV: &[&str] = &[
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "OPENAI_HOST",
    "OPENAI_BASE_PATH",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT",
    "CHATGPT_BASE_URL",
    "CODEX_MODEL_PROVIDER",
    "CODEX_PROVIDER",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
];

/// Launch the user's native agent without changing its saved configuration.
pub(crate) fn run(program: &str, args: &[String], common: &Common) -> Result<i32> {
    let args = args.strip_prefix(&["--".to_owned()]).unwrap_or(args);
    if !matches!(program, "claude" | "codex") {
        return Err(Error::usage("unknown native agent"));
    }
    validate_auth_args(program, args)?;
    let executable = std::env::current_exe()
        .map_err(|_| Error::config("cannot locate the AllowIt executable"))?;
    let mcp_args = mcp_args(common);
    let mcp = json!({"mcpServers":{"allowit":{
        "command":executable,"args":mcp_args
    }}});
    // A help-looking option value must not skip subscription admission for a real run.
    let metadata =
        args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h" | "--version" | "-V");
    if !metadata && matches!(program, "claude" | "codex") {
        require_subscription(program, common)?;
    }
    let mut command = native_command(program, common);
    let mut injected = Vec::new();
    match program {
        "claude" => {
            injected.extend(["--settings".into(), claude_settings().to_string()]);
            injected.extend(["--mcp-config".into(), mcp.to_string()]);
        }
        "codex" => {
            for setting in [
                "forced_login_method=\"chatgpt\"".to_owned(),
                "model_provider=\"openai\"".to_owned(),
                format!("mcp_servers.allowit.command={}", json!(executable)),
                format!("mcp_servers.allowit.args={}", json!(mcp_args)),
            ] {
                injected.extend(["-c".into(), setting]);
            }
        }
        _ => unreachable!(),
    }
    if metadata {
        command.args(args);
    } else {
        // Put session overrides after caller options, but before a literal prompt boundary.
        let boundary = args
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or(args.len());
        command
            .args(&args[..boundary])
            .args(injected)
            .args(&args[boundary..]);
    }
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|_| {
            Error::config(format!(
                "cannot launch {program}; install and sign in to the native application"
            ))
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
    }
    #[cfg(not(unix))]
    Ok(status.code().unwrap_or(1))
}

fn mcp_args(common: &Common) -> Vec<String> {
    let mut args = vec!["mcp".to_owned()];
    if common.sandbox {
        args.push("--sandbox".into());
    }
    for (flag, value) in [
        ("--policy", &common.policy_selector),
        ("--account", &common.account),
        ("--rail", &common.rail),
        ("--rpc", &common.rpc_url),
    ] {
        if let Some(value) = value {
            args.extend([flag.into(), value.clone()]);
        }
    }
    if let Some(money) = &common.max_debit {
        args.extend(["--max-payment".into(), money.amount.clone()]);
        args.extend(["--currency".into(), money.currency.clone()]);
    }
    args
}

fn native_command(program: &str, common: &Common) -> Command {
    let mut command = Command::new(program);
    if program == "claude" {
        for key in CLAUDE_API_ENV {
            command.env_remove(key);
        }
        // The OAuth token and native Keychain remain available for subscription renewal.
    } else if program == "codex" {
        for key in CODEX_API_ENV {
            command.env_remove(key);
        }
    }
    // Give the agent only the authority selected for this session.
    if common.policy_selector.is_some() {
        command.env_remove("ALLOWIT_ACCOUNT_TOKEN");
    } else {
        command
            .env_remove("ALLOWIT_TOKEN")
            .env_remove("ALLOWIT_PAYSH_TOKEN");
    }
    command
}

fn claude_settings() -> Value {
    let mut env = serde_json::Map::new();
    for key in CLAUDE_API_ENV {
        env.insert((*key).into(), json!(""));
    }
    json!({"forceLoginMethod":"claudeai","apiKeyHelper":"","env":env})
}

fn require_subscription(program: &str, common: &Common) -> Result<()> {
    let mut command = native_command(program, common);
    if program == "claude" {
        command.args([
            "--settings",
            &claude_settings().to_string(),
            "auth",
            "status",
        ]);
    } else {
        // Inspect the native auth mode without changing or copying its credentials.
        command.args(["login", "status"]);
    }
    let output = command.stdin(Stdio::null()).output().map_err(|_| {
        Error::config(format!(
            "cannot inspect {program} subscription authentication"
        ))
    })?;
    let signed_in = if program == "claude" {
        serde_json::from_slice::<Value>(&output.stdout)
            .ok()
            .is_some_and(|v| {
                v.get("loggedIn").and_then(Value::as_bool) == Some(true)
                    && matches!(
                        v.get("authMethod").and_then(Value::as_str),
                        Some("claude.ai" | "oauth_token")
                    )
            })
    } else {
        let text = format!(
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .to_ascii_lowercase();
        text.contains("logged in using chatgpt") && !text.contains("api key")
    };
    if !output.status.success() || !signed_in {
        return Err(Error::config(format!(
            "{program} subscription authentication is unavailable in this execution context; sign in through the native application"
        )));
    }
    Ok(())
}

fn validate_auth_args(program: &str, args: &[String]) -> Result<()> {
    if !matches!(program, "claude" | "codex") {
        return Ok(());
    }
    for (i, arg) in args.iter().enumerate() {
        if arg == "--" {
            break;
        }
        if matches!(
            arg.split('=').next().unwrap_or(arg),
            "--oss"
                | "--local-provider"
                | "--with-api-key"
                | "--api-key"
                | "--console"
                | "--alt"
                | "--bare"
        ) {
            return Err(Error::usage(
                "this launcher requires native subscription authentication",
            ));
        }
        if program == "claude" && (arg == "--settings" || arg.starts_with("--settings=")) {
            return Err(Error::usage(
                "this launcher reserves --settings for subscription authentication; native saved settings and model/permission flags remain available",
            ));
        }
        let config = if matches!(arg.as_str(), "-c" | "--config") && program == "codex" {
            args.get(i + 1).map(String::as_str)
        } else if program == "codex" {
            arg.strip_prefix("--config=")
                .or_else(|| arg.strip_prefix("-c").filter(|s| !s.is_empty()))
        } else {
            None
        };
        if let Some(config) = config {
            let key = config
                .split('=')
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace() && !matches!(c, '\'' | '"'))
                .collect::<String>();
            if [
                "model_provider",
                "model_providers",
                "forced_login_method",
                "chatgpt_base_url",
                "api_key_helper",
            ]
            .iter()
            .any(|prefix| key == *prefix || key.starts_with(&format!("{prefix}.")))
            {
                return Err(Error::usage(
                    "model-provider and authentication overrides are not accepted by this subscription launcher",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auth_overrides_are_rejected_without_restricting_models_or_permissions() {
        for args in [
            vec!["-c", "model_provider=other"],
            vec!["--config=\"forced_login_method\"=\"api\""],
            vec!["--oss"],
        ] {
            assert!(
                validate_auth_args(
                    "codex",
                    &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
                )
                .is_err()
            );
        }
        assert!(
            validate_auth_args(
                "codex",
                &[
                    "--model".into(),
                    "gpt-custom".into(),
                    "--sandbox".into(),
                    "read-only".into()
                ]
            )
            .is_ok()
        );
    }
    #[test]
    fn mcp_keeps_policy_network_context_without_reusing_operation_ids() {
        let common = Common {
            policy_selector: Some("v1@wallet".into()),
            sandbox: true,
            operation_id: Some("one-request-only".into()),
            rail: Some("stellar".into()),
            rpc_url: Some("https://rpc.example.com".into()),
            ..Default::default()
        };
        let args = mcp_args(&common);
        assert!(args.windows(2).any(|a| a == ["--policy", "v1@wallet"]));
        assert!(args.contains(&"--sandbox".to_owned()));
        assert!(!args.contains(&"one-request-only".to_owned()));
    }
}
