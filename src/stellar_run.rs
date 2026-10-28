//! Existing exec/status transport for an explicitly installed Stellar wallet profile.
use crate::tempo_store::Store;
use crate::{
    args::Args,
    config::{env_value, parse_origin},
    error::{Error, Result},
    typed_request::{decode_bytes, operation_nonce},
    typed_run::{TypedInput, read_typed_file},
};
use allowit_policy_sdk::typed_workflow::ExecutionRequest;
use allowit_stellar_wallet::{
    self as sdk, DetachedSignature, OperationStatus, PreparedOperation, SignedOperation,
    WalletConfig, WalletRoute,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::Read,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Bundle {
    version: u8,
    profile: String,
    network: String,
    policy_id: String,
    source_hash: String,
    ir_hash: String,
    module_digest: String,
    wallet: String,
    route: WalletRoute,
    config: WalletConfig,
    endpoints: Endpoints,
    /// Customer secret. This field is decoded locally and never serialized or sent.
    signing_seed: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoints {
    execute: String,
    status: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Response {
    prepared: PreparedOperation,
    operation: Operation,
    signed_operation: Option<SignedOperation>,
    receipt: Option<sdk::rpc::VerifiedReceipt>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Operation {
    id: String,
    status: OperationStatus,
    transaction_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Record {
    policy_id: String,
    request_id: String,
    config: WalletConfig,
    request: ExecutionRequest,
    prepared: Option<PreparedOperation>,
    agent_signature: Option<DetachedSignature>,
    status: Option<OperationStatus>,
}
struct Client {
    http: reqwest::blocking::Client,
    origin: String,
    bundle: Bundle,
    seed: Zeroizing<[u8; 32]>,
}
fn clock() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::config("System clock precedes the Unix epoch"))
}
fn checked<T>(v: sdk::Result<T>) -> Result<T> {
    v.map_err(Error::config)
}
fn journal_error(_: Error) -> Error {
    Error::config("Stellar operation journal is unsafe or unreadable; retain the original journal")
}
fn same_policy_config(expected: &WalletConfig, actual: &WalletConfig) -> bool {
    let mut current = actual.clone();
    // The engine signer is checked against the prepared live chain state, not frozen token metadata.
    current.engine = expected.engine.clone();
    &current == expected
}
impl Client {
    fn load(policy: &str) -> Result<Self> {
        let raw = Zeroizing::new(env_value("ALLOWIT_TOKEN"));
        let encoded = raw
            .strip_prefix("allowit-stellar-v1.")
            .ok_or_else(|| Error::config("Set ALLOWIT_TOKEN to the customer-held Stellar token"))?;
        if encoded.len() > 131_072
            || encoded.len() % 2 != 0
            || !encoded.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::config("Invalid Stellar token encoding"));
        }
        let bytes = Zeroizing::new(
            (0..encoded.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>(),
        );
        let mut bundle: Bundle = decode_bytes(&bytes)?;
        let seed = Zeroizing::new(checked(sdk::decode_seed(&bundle.signing_seed))?);
        use zeroize::Zeroize;
        bundle.signing_seed.zeroize();
        // Signer membership is checked against current chain authority by the service.
        bundle.config.agent = sdk::account_for_seed(&seed);
        if bundle.version != 1
            || bundle.profile != sdk::PROFILE
            || bundle.policy_id != policy
            || bundle.network != bundle.config.network
            || bundle.wallet != bundle.config.wallet
            || bundle.route != bundle.config.route
            || checked(sdk::unhex::<32>(&bundle.source_hash))? != bundle.config.source_hash
            || checked(sdk::unhex::<32>(&bundle.module_digest))? != bundle.config.module_digest
            || sdk::unhex::<32>(&bundle.ir_hash).is_err()
            || bundle.endpoints.execute != "/api/native/execute"
            || bundle.endpoints.status != "/api/native/execute/status"
        {
            return Err(Error::config(
                "The Stellar bundle does not match the installed policy profile",
            ));
        }
        checked(sdk::validate_config(&bundle.config))?;
        let origin = parse_origin(&env_value("ALLOWIT_URL"))?;
        let builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none());
        Ok(Self {
            http: builder
                .build()
                .map_err(|_| Error::config("Cannot initialize Stellar transport"))?,
            origin,
            bundle,
            seed,
        })
    }
    fn post(&self, path: &str, body: serde_json::Value) -> Result<Response> {
        use ed25519_dalek::{Signer, SigningKey};
        let issued_at = clock()?;
        let canonical = serde_json_canonicalizer::to_vec(&body)
            .map_err(|_| Error::config("Cannot encode Stellar request"))?;
        let mut message = format!("allowit-stellar-request-v1\n{issued_at}\n{path}\n").into_bytes();
        message.extend_from_slice(&canonical);
        let signature = SigningKey::from_bytes(&self.seed).sign(&sdk::hash(message));
        let proof = format!(
            "Bearer stellar-proof.{}.{issued_at}.{}",
            sdk::account_for_seed(&self.seed),
            sdk::hex(&signature.to_bytes())
        );
        let response = self
            .http
            .post(format!("{}{path}", self.origin))
            .header("Authorization", proof)
            .json(&body)
            .send()
            .map_err(|_| {
                Error::uncertain(
                    "Stellar transport is uncertain; recover the original request ID with status",
                )
            })?;
        let code = response.status().as_u16();
        if !(200..300).contains(&code) {
            return Err(Error::api(
                code,
                "Stellar operation was not resolved; retain the original request ID",
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                Error::uncertain("Cannot read Stellar response; recover the original request ID")
            })?;
        if bytes.len() > 1_048_576 {
            return Err(Error::uncertain(
                "Stellar response exceeds its limit; recover the original request ID",
            ));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            Error::uncertain("Invalid Stellar response; recover the original request ID")
        })
    }
    fn validate(&self, r: &Response, id: &str, record: Option<&Record>) -> Result<()> {
        let p = &r.prepared;
        if r.operation.id != id
            || !same_policy_config(&self.bundle.config, &p.config)
            || p.request.operation.nonce != operation_nonce(&self.bundle.policy_id, id)
            || r.operation.transaction_hash != sdk::hex(&p.transaction_hash)
            || record.is_some_and(|old| {
                old.request != p.request
                    || !same_policy_config(&old.config, &p.config)
                    || old.prepared.as_ref().is_some_and(|v| v != p)
            })
        {
            return Err(Error::uncertain(
                "Stellar response changed the original operation identity",
            ));
        }
        if terminal(&r.operation.status) && r.receipt.is_none() {
            return Err(Error::uncertain(
                "Terminal Stellar status requires a verified chain receipt",
            ));
        }
        if let Some(receipt) = &r.receipt {
            checked(sdk::rpc::validate_receipt(
                receipt,
                &p.config.network,
                &p.transaction_hash,
            ))?;
            if receipt.status != r.operation.status
                || r.signed_operation
                    .as_ref()
                    .is_none_or(|v| v.transaction_xdr != receipt.envelope_xdr)
            {
                return Err(Error::uncertain(
                    "Stellar receipt differs from its retained signed operation",
                ));
            }
        }
        // Status verifies retained bytes at their preparation time, including after expiry.
        checked(sdk::validate_retained_prepared(p))?;
        if let Some(s) = &r.signed_operation {
            if s.prepared != *p {
                return Err(Error::uncertain(
                    "Stellar signed packet differs from the original operation",
                ));
            }
            checked(sdk::validate_retained_signed(s))?;
        }
        if matches!(
            r.operation.status,
            OperationStatus::Submitted | OperationStatus::Confirmed | OperationStatus::Failed
        ) && r.signed_operation.is_none()
        {
            return Err(Error::uncertain(
                "Stellar settlement omitted its signed packet",
            ));
        }
        if let Some(old) = record.and_then(|v| v.status.as_ref())
            && matches!(old, OperationStatus::Confirmed | OperationStatus::Failed)
            && *old != r.operation.status
        {
            return Err(Error::uncertain("A terminal Stellar receipt changed"));
        }
        Ok(())
    }
    fn status(&self, id: &str, record: Option<&Record>) -> Result<Response> {
        let r = self.post(
            &self.bundle.endpoints.status,
            json!({"policyId":self.bundle.policy_id,"requestId":id}),
        )?;
        self.validate(&r, id, record)?;
        Ok(r)
    }
}
pub(crate) fn run(
    command: &str,
    args: &Args,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<i32> {
    let client = Client::load(&args.pos[0])?;
    let journal = Store::open(Path::new(".allowit/stellar-journal")).map_err(journal_error)?;
    run_locked(command, args, stdout, stderr, &client, &journal)
}
fn run_locked(
    command: &str,
    args: &Args,
    stdout: &mut String,
    stderr: &mut String,
    c: &Client,
    journal: &Store,
) -> Result<i32> {
    if command == "status" {
        let id = &args.pos[1];
        let name = sdk::hex(&operation_nonce(&args.pos[0], id));
        let old: Option<Record> = journal.load(&name).map_err(journal_error)?;
        if old.as_ref().is_some_and(|v| {
            v.policy_id != args.pos[0] || v.request_id != *id || v.config != c.bundle.config
        }) {
            return Err(Error::config(
                "The journal does not bind this installed Stellar policy",
            ));
        }
        return poll(c, id, old, journal, &name, args.wait, stdout);
    }
    if args.flags.get("request-file").is_empty()
        || args
            .flags
            .0
            .keys()
            .any(|k| !matches!(k.as_str(), "request-file" | "request-id"))
    {
        return Err(Error::usage(
            "Stellar exec requires --request-file without scalar request flags",
        ));
    }
    let typed = read_typed_file(Path::new(args.flags.get("request-file")))?;
    let TypedInput::Execution(request) = typed.input else {
        return Err(Error::usage(
            "The Stellar profile accepts only execution-request input",
        ));
    };
    let id = typed.request_id;
    if !args.flags.get("request-id").is_empty() && args.flags.get("request-id") != id {
        return Err(Error::usage("--request-id differs from the request file"));
    }
    if request.operation.nonce != operation_nonce(&args.pos[0], &id) {
        return Err(Error::usage(
            "The operation nonce does not bind this policy and request ID",
        ));
    }
    checked(sdk::transfer_from_request(&c.bundle.config, &request))?;
    let name = sdk::hex(&request.operation.nonce);
    let old = journal.load::<Record>(&name).map_err(journal_error)?;
    let (mut record, resumed) = if let Some(old) = old {
        if old.policy_id != args.pos[0]
            || old.request_id != id
            || old.config != c.bundle.config
            || old.request != request
        {
            return Err(Error::config(
                "The original request ID already binds different input",
            ));
        }
        if old.agent_signature.is_some()
            || !matches!(&old.status, None | Some(OperationStatus::Prepared))
        {
            return poll(c, &id, Some(old), journal, &name, args.wait, stdout);
        }
        let pure_intent = old.prepared.is_none() && old.status.is_none();
        let resumed = match c.status(&id, Some(&old)) {
            Ok(response)
                if response.operation.status == OperationStatus::Prepared
                    && response.signed_operation.is_none() =>
            {
                Some(response)
            }
            Ok(_) => return poll(c, &id, Some(old), journal, &name, args.wait, stdout),
            Err(error) if error.status == Some(404) && pure_intent => None,
            Err(error) => return Err(error),
        };
        (old, resumed)
    } else {
        (
            Record {
                policy_id: args.pos[0].clone(),
                request_id: id.clone(),
                config: c.bundle.config.clone(),
                request: request.clone(),
                prepared: None,
                agent_signature: None,
                status: None,
            },
            None,
        )
    };
    // Preserve the original intent. Only an explicit exec can continue unsigned preparation.
    journal.save(&name, &record).map_err(journal_error)?;
    *stderr += &format!("requestId={id}\n");
    crate::flush_stderr(stderr);
    let prepared = if let Some(response) = resumed {
        response
    } else {
        c.post(
            &c.bundle.endpoints.execute,
            json!({"policyId":args.pos[0],"requestId":id,"phase":"prepare","request":request}),
        )?
    };
    c.validate(&prepared, &id, Some(&record))?;
    if prepared.operation.status != OperationStatus::Prepared || prepared.signed_operation.is_some()
    {
        return Err(Error::uncertain(
            "Stellar prepare returned an unexpected lifecycle state",
        ));
    }
    // Retain observed bytes even when stale. They must never become a fresh all-None intent.
    record.prepared = Some(prepared.prepared.clone());
    record.status = Some(OperationStatus::Prepared);
    journal.save(&name, &record).map_err(journal_error)?;
    checked(sdk::validate_prepared(&prepared.prepared, clock()?))?;
    let signature = checked(sdk::sign(&prepared.prepared, &c.seed, clock()?))?;
    record.prepared = Some(prepared.prepared);
    record.agent_signature = Some(signature.clone());
    record.status = Some(OperationStatus::SubmissionUnknown);
    journal.save(&name, &record).map_err(journal_error)?;
    let response = c.post(
        &c.bundle.endpoints.execute,
        json!({"policyId":args.pos[0],"requestId":id,"phase":"submit","agentSignature":signature}),
    )?;
    c.validate(&response, &id, Some(&record))?;
    record.status = Some(response.operation.status.clone());
    journal.save(&name, &record).map_err(journal_error)?;
    if terminal(&response.operation.status) || args.wait.is_zero() {
        return render(&response, stdout);
    }
    poll(c, &id, Some(record), journal, &name, args.wait, stdout)
}
fn terminal(status: &OperationStatus) -> bool {
    matches!(status, OperationStatus::Confirmed | OperationStatus::Failed)
}
fn poll(
    c: &Client,
    id: &str,
    mut record: Option<Record>,
    journal: &Store,
    name: &str,
    wait: Duration,
    stdout: &mut String,
) -> Result<i32> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        let r = c.status(id, record.as_ref())?;
        let mut old = record.unwrap_or_else(|| Record {
            policy_id: c.bundle.policy_id.clone(),
            request_id: id.into(),
            config: c.bundle.config.clone(),
            request: r.prepared.request.clone(),
            prepared: Some(r.prepared.clone()),
            agent_signature: None,
            status: None,
        });
        if old.prepared.is_none() {
            old.prepared = Some(r.prepared.clone());
        }
        old.status = Some(r.operation.status.clone());
        journal.save(name, &old).map_err(journal_error)?;
        record = Some(old);
        if terminal(&r.operation.status) || std::time::Instant::now() >= deadline {
            return render(&r, stdout);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
fn render(r: &Response, stdout: &mut String) -> Result<i32> {
    *stdout += &format!(
        "{}\n",
        json!({"requestId":r.operation.id,"status":r.operation.status,"transactionHash":r.operation.transaction_hash})
    );
    Ok(match r.operation.status {
        OperationStatus::Confirmed => 0,
        OperationStatus::Failed => 20,
        OperationStatus::SubmissionUnknown => 5,
        OperationStatus::Prepared | OperationStatus::Submitted => 12,
    })
}
