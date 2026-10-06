//! Local policy configuration and presentation. Chain and journal semantics belong
//! to the pinned SDK library; this module never launches another command process.
use crate::{
    config::env_value,
    error::{Error, Result},
};
use allowit_native::{
    client::{Config, Deployment, NativeClient},
    crypto::{Key, LocalSigner},
    journal::FileJournal,
    lifecycle::{PolicyLifecycle, Record},
    native::Options,
    policy::{Policy, genesis},
    rpc::HttpRpc,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Context {
    policy_id: String,
    owner: Key,
    network: String,
    mint: Key,
    executor: Key,
    deployment: Deployment,
}
#[derive(Deserialize)]
struct Bundle {
    version: u32,
    policy: Policy,
    context: Context,
}
struct Local {
    directory: PathBuf,
    policy_file: PathBuf,
    context: Option<Context>,
    network: String,
    config: Config,
    rpc_url: String,
}
impl Local {
    fn load(name: &str) -> Result<Self> {
        let directory = absolute(&configured("ALLOWIT_POLICY_DIR", ".allowit"))?;
        let policy_file = absolute(&configured(
            "ALLOWIT_POLICY_FILE",
            directory.join("policy.json").to_string_lossy().as_ref(),
        ))?;
        let context: Option<Context> = read_optional(&directory.join("context.json"))?;
        if let Some(c) = &context {
            for (name, value) in [
                ("ALLOWIT_NETWORK", c.network.clone()),
                ("ALLOWIT_MINT", c.mint.to_string()),
                ("ALLOWIT_EXECUTOR", c.executor.to_string()),
            ] {
                let present = env_value(name);
                if !present.is_empty() && present != value {
                    return Err(Error::config(format!(
                        "Environment {name} differs from the imported policy context"
                    )));
                }
            }
        }
        let network = configured(
            "ALLOWIT_NETWORK",
            context
                .as_ref()
                .map(|c| c.network.as_str())
                .unwrap_or("solana:testnet"),
        );
        native(genesis(&network))?;
        let mint = if matches!(name, "generate" | "import") {
            context.as_ref().map(|c| c.mint)
        } else {
            public_setting("ALLOWIT_MINT", context.as_ref().map(|c| c.mint))?
        };
        let executor = if matches!(name, "generate" | "import") {
            context.as_ref().map(|c| c.executor)
        } else {
            public_setting("ALLOWIT_EXECUTOR", context.as_ref().map(|c| c.executor))?
        };
        let rpc_url = configured(
            "ALLOWIT_RPC_URL",
            if network == "solana:devnet" {
                "https://api.devnet.solana.com"
            } else {
                "https://api.testnet.solana.com"
            },
        );
        let config = Config {
            network: network.clone(),
            mint,
            executor,
            deployment: context.as_ref().map(|c| c.deployment.clone()),
        };
        Ok(Self {
            directory,
            policy_file,
            context,
            network,
            config,
            rpc_url,
        })
    }
    fn client(&self) -> Result<NativeClient> {
        native(NativeClient::new(
            self.config.clone(),
            Arc::new(native(HttpRpc::new(&self.rpc_url))?),
        ))
    }
    fn save_policy(&self, policy: &Policy) -> Result<()> {
        create_private(
            &self.policy_file,
            policy,
            "A policy already exists here. Choose a new ALLOWIT_POLICY_DIR; keep the previous policy and journal for recovery.",
        )
    }
}
pub(crate) fn run(
    name: &str,
    pos: &[String],
    json: bool,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<i32> {
    let mut local = Local::load(name)?;
    if name == "generate" {
        let policy = native(Policy::generate(&local.network, &pos[0]))?;
        native(
            FileJournal::new(local.directory.join("journal"))
                .locked(|| local.save_policy(&policy).map_err(to_native)),
        )?;
        if json {
            stdout.push_str(&serde_json::to_string(&policy).unwrap());
            stdout.push('\n');
        } else {
            stdout.push_str(&format!(
                "Policy {}\nNetwork: {}\nDaily limit: {} test tokens\n\n{}\n\nSaved {}\n",
                policy.id,
                policy.network,
                policy.daily_limit,
                policy.rust,
                local.policy_file.display()
            ));
        }
        return Ok(0);
    }
    if name == "import" {
        let bundle: Bundle = read_optional(Path::new(&pos[0]))?
            .ok_or_else(|| Error::config("Cannot read executor bundle"))?;
        native(bundle.policy.validate())?;
        let c = &bundle.context;
        if bundle.version != 1
            || c.policy_id != bundle.policy.id
            || c.network != bundle.policy.network
        {
            return Err(Error::config("Bundle network/owner mismatch"));
        }
        let imported = native(NativeClient::new(
            Config {
                network: c.network.clone(),
                mint: Some(c.mint),
                executor: Some(c.executor),
                deployment: Some(c.deployment.clone()),
            },
            Arc::new(OfflineRpc),
        ))?;
        native(imported.public_binding(&bundle.policy, c.owner))?;
        let journal = FileJournal::new(local.directory.join("journal"));
        native(journal.locked(|| {
            if fs::symlink_metadata(&local.policy_file).is_ok() {return Err(allowit_native::error::Error::config("A policy already exists here. Choose a new ALLOWIT_POLICY_DIR; keep the previous policy and journal for recovery."));}
            if let Some(existing)=&local.context {
                if serde_json::to_vec(existing).unwrap()!=serde_json::to_vec(c).unwrap() {return Err(allowit_native::error::Error::config("A different public context already exists here; choose a new policy directory"));}
            } else {create_private(&local.directory.join("context.json"),c,"A different public context already exists here; choose a new policy directory").map_err(to_native)?;}
            local.save_policy(&bundle.policy).map_err(to_native)
        }))?;
        if json {
            stdout.push_str(&format!(
                "{}\n",
                serde_json::json!({"policyId":bundle.policy.id,"owner":c.owner,"imported":true})
            ));
        } else {
            stdout.push_str(&format!("Imported policy {}. Configure only ALLOWIT_EXECUTOR_KEYPAIR on the executor device; never the owner key.\n",bundle.policy.id));
        }
        return Ok(0);
    }
    let policy: Policy = read_optional(&local.policy_file)?
        .ok_or_else(|| Error::config("Cannot read saved policy"))?;
    native(policy.validate())?;
    if local
        .context
        .as_ref()
        .is_some_and(|c| c.policy_id != policy.id)
    {
        return Err(Error::config(
            "Saved context belongs to a different policy instance",
        ));
    }
    let deployment_file = env_value("ALLOWIT_DEPLOYMENT_FILE");
    if !deployment_file.is_empty() {
        let d: Deployment = read_optional(Path::new(&deployment_file))?
            .ok_or_else(|| Error::config("Cannot read native deployment"))?;
        if local.context.as_ref().is_some_and(|c| {
            serde_json::to_vec(&c.deployment).unwrap() != serde_json::to_vec(&d).unwrap()
        }) {
            return Err(Error::config(
                "Deployment differs from the imported policy context",
            ));
        }
        local.config.deployment = Some(d);
    }
    if local.config.deployment.is_none() {
        return Err(Error::config(
            "Configure ALLOWIT_DEPLOYMENT_FILE or import the executor bundle",
        ));
    }
    let owner_role = !matches!(name, "execute" | "status");
    let signer = if owner_role {
        Some(load_signer("ALLOWIT_OWNER_KEYPAIR")?)
    } else {
        None
    };
    let owner=match &signer {Some(s)=>s.public_key(),None=>public_setting("ALLOWIT_OWNER",local.context.as_ref().map(|c|c.owner))?.ok_or_else(||Error::config("Configure ALLOWIT_OWNER with the vault owner public key for execute/status; no owner key is needed"))?};
    if local.context.as_ref().is_some_and(|c| c.owner != owner) {
        return Err(Error::config(
            "Configured owner differs from the imported policy",
        ));
    }
    let client = local.client()?;
    let journal = FileJournal::new(local.directory.join("journal"));
    if owner_role && local.context.is_none() {
        let bundle = native(client.bundle(&policy, owner))?;
        let context: Context = serde_json::from_value(bundle["context"].clone())
            .map_err(|_| Error::config("Invalid generated policy context"))?;
        native(journal.locked(|| {
            create_private(
                &local.directory.join("context.json"),
                &context,
                "A public context already exists here; recover it before continuing",
            )
            .map_err(to_native)
        }))?;
    }
    let lifecycle = PolicyLifecycle::new(&client, &journal);
    if name == "status" {
        let records = native(journal.entries::<Record>())?;
        let mut operations = Vec::new();
        for record in records {
            operations.push(match lifecycle.recover(&record.id,&policy,owner){Ok(r)=>r.public(),Err(_)=>serde_json::json!({"id":record.id,"status":"uncertain","error":"Saved operation could not be verified against this configuration"})});
        }
        let last = native(journal.read::<serde_json::Value>("last"))?;
        let operation = last
            .as_ref()
            .and_then(|last| operations.iter().find(|r| r["id"] == last["id"]));
        let state = native(client.state(&policy, owner, true, None))?;
        if json {
            stdout.push_str(&format!("{}\n",serde_json::json!({"policyId":policy.id,"network":policy.network,"state":state,"operations":operations,"operation":operation})));
        } else {
            stdout.push_str(&format!("Policy {}\n", policy.id));
            if let Some(s) = state {
                stdout.push_str(&format!(
                    "Vault {}\nApproved: {}\nBalance: {}\nSpent today counter: {}\n",
                    s.binding.vault,
                    s.approved,
                    allowit_native::policy::decimal(native(allowit_native::native::number(
                        &s.balance
                    ))?),
                    allowit_native::policy::decimal(native(allowit_native::native::number(
                        &s.spent
                    ))?)
                ));
            } else {
                stdout.push_str("Not deployed\n");
            }
            if let Some(op) = operation {
                stdout.push_str(&format!(
                    "Last operation: {}\n{}\n",
                    op["status"].as_str().unwrap_or("uncertain"),
                    op["transactionUrl"].as_str().unwrap_or("")
                ));
            }
        }
        return Ok(0);
    }
    let options = match name {
        "execute" => Options {
            recipient: Some(native(Key::parse(&pos[0]))?),
            amount: Some(pos[1].clone()),
            ..Options::default()
        },
        "fund" | "withdraw" => Options {
            amount: Some(pos[0].clone()),
            additional_owner_operation: env_value("ALLOWIT_ADDITIONAL_OWNER_OPERATION") == "1",
            ..Options::default()
        },
        "tune" => Options {
            amount: Some(pos[0].clone()),
            ..Options::default()
        },
        _ => Options::default(),
    };
    let request_id = env_value("ALLOWIT_REQUEST_ID");
    let mut result = native(lifecycle.submit(
        &policy,
        owner,
        name,
        &options,
        if std::env::var_os("ALLOWIT_REQUEST_ID").is_none() {
            None
        } else {
            Some(&request_id)
        },
        |tx, role| {
            if role == "executor" {
                let signer = load_signer("ALLOWIT_EXECUTOR_KEYPAIR").map_err(to_native)?;
                if tx.payer != signer.public_key() {
                    return Err(allowit_native::error::Error::config(
                        "Configured signer does not match the prepared fee payer",
                    ));
                }
                Ok(signer.sign(&tx.message))
            } else {
                let signer = signer.as_ref().ok_or_else(|| {
                    allowit_native::error::Error::config(
                        "Owner signing is unavailable in executor mode",
                    )
                })?;
                if tx.payer != signer.public_key() {
                    return Err(allowit_native::error::Error::config(
                        "Configured signer does not match the prepared fee payer",
                    ));
                }
                Ok(signer.sign(&tx.message))
            }
        },
    ))?;
    let replayed = result.extra.get("replayed") == Some(&serde_json::json!(true));
    let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !result.final_status() && !result.expired() && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_secs(1));
        match lifecycle.recover(&result.id, &policy, owner) {
            Ok(observed) => result = observed,
            Err(_) => {
                // The signed proof is already durable and may have landed.
                // A failed observation cannot turn it into a config-only exit.
                let name = format!("request-{}", result.id);
                match journal.locked(|| {
                    let mut current = journal.read::<Record>(&name)?.ok_or_else(|| allowit_native::error::Error::config("Operation journal disappeared"))?;
                    if current.signature != result.signature || current.signed_bytes != result.signed_bytes || current.intent != result.intent {
                        return Err(allowit_native::error::Error::config("Operation journal changed"));
                    }
                    if !current.final_status() && !current.expired() {
                        current.status = "uncertain".into();
                        current.extra.remove("replayed");
                        current.extra.insert("error".into(),serde_json::json!("Recovery observation failed; keep this request ID and original journal, and run allowit policy status"));
                        journal.write(&name,&current)?;
                    }
                    Ok(current)
                }) {
                    Ok(current) => result = current,
                    Err(_) => {
                        result.status = "uncertain".into();
                        stderr.push_str("Recovery observation could not be saved; retain the original journal and request ID.\n");
                    }
                }
                break;
            }
        }
    }
    if replayed {
        result
            .extra
            .insert("replayed".into(), serde_json::json!(true));
    }
    let mut output = result.public();
    if result.status == "settled" && name == "deploy" {
        let state = native(client.state(&policy, owner, true, None))?
            .ok_or_else(|| Error::config("Deployed vault is unavailable"))?;
        let skill = native(client.skill(&policy, &state))?;
        save_text(&local.directory.join("SKILL.md"), &skill)?;
        output["skill"] = serde_json::json!(skill);
    }
    if json {
        stdout.push_str(&format!("{output}\n"));
    } else {
        stdout.push_str(&format!(
            "Policy {}\n{name}: {}\nRequest: {}\n{}\n",
            policy.id,
            if replayed {
                format!("replayed ({})", result.status)
            } else {
                result.status.clone()
            },
            result.id,
            result.transaction_url
        ));
        if let Some(skill) = output["skill"].as_str() {
            stdout.push('\n');
            stdout.push_str(skill);
        }
    }
    if result.expired() {
        stderr.push_str("The original operation remains uncertain and cannot be broadcast again. For an explicitly additional fund/withdraw, set both a fresh ALLOWIT_REQUEST_ID and ALLOWIT_ADDITIONAL_OWNER_OPERATION=1; retain the old proof.\n");
    }
    if result.extra.get("decisionCode") == Some(&serde_json::json!("EXPIRED_UNEXECUTED")) {
        stderr.push_str("This request expired without execution. For a deliberate retry, set a new ALLOWIT_REQUEST_ID; keep the original journal.\n");
    }
    Ok(if result.status == "failed" {
        20
    } else if result.status != "settled" {
        5
    } else if replayed {
        6
    } else {
        0
    })
}
fn load_signer(name: &str) -> Result<LocalSigner> {
    let path = env_value(name);
    if path.is_empty() {
        return Err(Error::config(format!(
            "Configure {name} with a dedicated test-network key file"
        )));
    }
    native(LocalSigner::load(Path::new(&path)))
}
fn save_text(path: &Path, text: &str) -> Result<()> {
    // Atomic replacement avoids following a pre-existing skill symlink.
    let parent = path
        .parent()
        .ok_or_else(|| Error::config("Invalid skill path"))?;
    let temp = parent.join(format!(".skill-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|_| Error::config("Cannot save generated skill"))?;
    let result = (|| {
        file.write_all(text.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::config("Cannot persist generated skill"))?;
        drop(file);
        fs::rename(&temp, path).map_err(|_| Error::config("Cannot save generated skill"))?;
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::config("Cannot persist generated skill directory"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
struct OfflineRpc;
impl allowit_native::rpc::Rpc for OfflineRpc {
    fn call(
        &self,
        _: &str,
        _: serde_json::Value,
    ) -> allowit_native::error::Result<serde_json::Value> {
        Err(allowit_native::error::Error::config(
            "Offline policy operation cannot access RPC",
        ))
    }
}

fn configured(name: &str, fallback: &str) -> String {
    let v = env_value(name);
    if v.is_empty() { fallback.into() } else { v }
}
fn public_setting(name: &str, fallback: Option<Key>) -> Result<Option<Key>> {
    let v = env_value(name);
    if v.is_empty() {
        Ok(fallback)
    } else {
        native(Key::parse(&v)).map(Some)
    }
}
fn absolute(path: &str) -> Result<PathBuf> {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        Ok(p)
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .map_err(|_| Error::config("Cannot locate policy directory"))
    }
}
fn read_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::config("Unreadable policy context or file")),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(2_097_153)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::config("Unreadable policy context or file"))?;
    if bytes.len() > 2_097_152 {
        return Err(Error::config("Policy file exceeded its size limit"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Error::config("Unreadable policy context or file"))
}
fn create_private(path: &Path, value: &impl Serialize, occupied: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::config("Invalid policy path"))?;
    let mut dirs = fs::DirBuilder::new();
    dirs.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        dirs.mode(0o700);
    }
    dirs.create(parent)
        .map_err(|_| Error::config("Cannot create policy directory"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        Error::config(if e.kind() == std::io::ErrorKind::AlreadyExists {
            occupied
        } else {
            "Cannot save policy file"
        })
    })?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|_| Error::config("Cannot serialize policy file"))?;
    file.write_all(b"\n")
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::config("Cannot persist policy file"))?;
    fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::config("Cannot persist policy directory"))
}
fn native<T>(result: allowit_native::error::Result<T>) -> Result<T> {
    result.map_err(|e| Error {
        code: e.code,
        message: e.message,
        status: None,
        config: e.code == 3,
    })
}
fn to_native(e: Error) -> allowit_native::error::Error {
    allowit_native::error::Error {
        code: e.code,
        message: e.message,
    }
}
