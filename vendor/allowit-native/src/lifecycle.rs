//! Signed-proof recovery. Persist the exact transaction and unresolved operation
//! slots before broadcasting; lost evidence never permits automatic replacement.
use crate::{
    client::{Binding, NativeClient, TOKEN_PROGRAM},
    crypto::Key,
    error::{Error, Result},
    journal::FileJournal,
    native::{
        ApprovalCommitment, ApprovalRequest, ExecutionRequestIdentity, Options, Simulation, number,
        safe_height,
    },
    policy::{Policy, decimal, digest, units},
    transaction::{Signed, Transaction},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Intent {
    policy_id: String,
    network: String,
    owner: Key,
    method: String,
    amount: Option<String>,
    recipient: Option<Key>,
    expires_at: Option<u64>,
    commitment: Option<String>,
    instance_slot: Option<u64>,
    binding: Binding,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub id: String,
    pub intent: String,
    pub method: String,
    pub status: String,
    pub signature: String,
    #[serde(default)]
    pub signatures: Vec<String>,
    pub signed_bytes: String,
    pub blockhash: Key,
    pub last_valid_block_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_slot: Option<String>,
    pub transaction_url: String,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}
/// A trusted server's exact authorization response. The lifecycle validates
/// every field against local policy, state, and instruction reconstruction
/// before it accepts the authority signature.
#[derive(Clone)]
pub struct AuthorizedExecution {
    pub binding: Binding,
    pub request: ApprovalRequest,
    pub approval: ApprovalCommitment,
    pub intent: String,
    pub message: Vec<u8>,
    pub partial_transaction: Vec<u8>,
    pub blockhash: Key,
    pub last_valid_block_height: u64,
    pub nonce: String,
    pub revision: String,
    pub simulation: Simulation,
}
impl Record {
    pub fn public(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap();
        v.as_object_mut().unwrap().remove("signedBytes");
        v.as_object_mut().unwrap().remove("intent");
        v
    }
    pub fn final_status(&self) -> bool {
        matches!(self.status.as_str(), "settled" | "failed")
    }
    pub fn expired(&self) -> bool {
        self.extra.get("blockhashExpired") == Some(&json!(true))
    }
    fn update(&mut self, v: Value) {
        if let Some(obj) = v.as_object() {
            for (k, v) in obj {
                match k.as_str() {
                    "status" => self.status = v.as_str().unwrap_or("uncertain").into(),
                    "signature" | "transactionUrl" => (),
                    _ => {
                        self.extra.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
}
pub fn intent_for(
    sdk: &NativeClient,
    policy: &Policy,
    owner: Key,
    method: &str,
    options: &Options,
) -> Result<String> {
    let binding = sdk.public_binding(policy, owner)?;
    let intent = Intent {
        policy_id: policy.id.clone(),
        network: policy.network.clone(),
        owner,
        method: method.into(),
        amount: options
            .amount
            .as_deref()
            .map(units)
            .transpose()?
            .map(decimal),
        recipient: options.recipient,
        expires_at: options.expires_at,
        commitment: options.commitment.clone(),
        instance_slot: options.instance_slot,
        binding,
    };
    serde_json::to_string(&intent).map_err(|_| Error::config("Invalid operation intent"))
}
pub fn validate_record(
    sdk: &NativeClient,
    policy: &Policy,
    owner: Key,
    record: &Record,
) -> Result<Signed> {
    valid_id(&record.id)?;
    if record.last_valid_block_height > 9_007_199_254_740_991 {
        return Err(Error::config("Invalid operation journal"));
    }
    let intent: Intent = serde_json::from_str(&record.intent)
        .map_err(|_| Error::config("Invalid operation journal"))?;
    let options = Options {
        amount: intent.amount,
        recipient: intent.recipient,
        expires_at: intent.expires_at,
        commitment: intent.commitment,
        instance_slot: intent.instance_slot,
        ..Options::default()
    };
    if intent_for(sdk, policy, owner, &record.method, &options)? != record.intent
        || record.method != intent.method
    {
        return Err(Error::config("Operation binding changed"));
    }
    let b = sdk.public_binding(policy, owner)?;
    let expected = Transaction::new(
        if record.method == "execute" {
            b.executor
        } else {
            b.owner
        },
        record.blockhash,
        sdk.expected_instructions(
            policy,
            &b,
            &record.method,
            &options,
            record.nonce.as_deref(),
            record.revision.as_deref(),
        )?,
    )?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&record.signed_bytes)
        .map_err(|_| Error::config("Invalid operation journal"))?;
    let proof = Signed::parse(&raw)?;
    proof.matches(&expected)?;
    let signatures: Vec<_> = proof
        .signatures
        .iter()
        .map(|signature| bs58::encode(signature).into_string())
        .collect();
    if bs58::encode(proof.primary_signature()?).into_string() != record.signature
        || signatures != record.signatures
        || record.expires_at != options.expires_at
        || record.commitment != options.commitment
        || record.instance_slot.as_deref().map(number).transpose()? != options.instance_slot
        || sdk.transaction_url(&record.signature)? != record.transaction_url
    {
        return Err(Error::config(
            "Saved signed transaction does not match this operation",
        ));
    }
    Ok(proof)
}
/// Host interface for lifecycle tests or alternative transports. The default
/// implementation enforces the pinned release, account, and signer bindings.
pub trait NativeOperations {
    fn client(&self) -> &NativeClient;
    fn verify_release(&self, recovery: bool) -> Result<()>;
    fn status(&self, signature: &str) -> Result<Value>;
    fn state(
        &self,
        policy: &Policy,
        owner: Key,
        recovery: bool,
        min_context_slot: Option<u64>,
    ) -> Result<Option<crate::native::State>>;
    fn prepare(
        &self,
        policy: &Policy,
        owner: Key,
        method: &str,
        options: &Options,
    ) -> Result<crate::native::Prepared>;
}
impl NativeOperations for NativeClient {
    fn client(&self) -> &NativeClient {
        self
    }
    fn verify_release(&self, recovery: bool) -> Result<()> {
        NativeClient::verify_release(self, recovery).map(|_| ())
    }
    fn status(&self, signature: &str) -> Result<Value> {
        NativeClient::status(self, signature)
    }
    fn state(
        &self,
        policy: &Policy,
        owner: Key,
        recovery: bool,
        min_context_slot: Option<u64>,
    ) -> Result<Option<crate::native::State>> {
        NativeClient::state(self, policy, owner, recovery, min_context_slot)
    }
    fn prepare(
        &self,
        policy: &Policy,
        owner: Key,
        method: &str,
        options: &Options,
    ) -> Result<crate::native::Prepared> {
        NativeClient::prepare(self, policy, owner, method, options)
    }
}
/// Reconcile a durable signed operation without reading or writing a journal.
/// Hosts must persist the exact validated record before any broadcast and commit
/// this returned observation atomically in their own storage. This function never
/// signs, broadcasts, replaces a proof, or trusts a status without receipt checks.
/// Caller-supplied status and `extra` observations are discarded. They are not
/// signed transaction fields and cannot establish settlement or nonexecution.
/// Imported validity heights cannot establish expiry. Without a final network
/// result, imported proofs stay uncertain even when a node lacks their blockhash.
pub fn reconcile_record(
    sdk: &dyn NativeOperations,
    mut record: Record,
    policy: &Policy,
    owner: Key,
) -> Result<Record> {
    record.status = "uncertain".into();
    record.extra.clear();
    reconcile_saved_record(sdk, record, policy, owner, false)
}

// Only records read from the private local journal may trust validity heights or absence observations.
fn reconcile_saved_record(
    sdk: &dyn NativeOperations,
    mut record: Record,
    policy: &Policy,
    owner: Key,
    trusted_journal: bool,
) -> Result<Record> {
    record.extra.remove("error");
    record.extra.remove("replayed");
    let proof = validate_record(sdk.client(), policy, owner, &record)?;
    sdk.verify_release(matches!(
        record.method.as_str(),
        "revoke" | "withdraw" | "close"
    ))?;
    if record
        .extra
        .get("absence")
        .and_then(|a| a["kind"].as_str())
        .is_some_and(|k| k.starts_with("expired-"))
    {
        return Ok(record);
    }
    let mut result = sdk.status(&record.signature)?;
    if trusted_journal && result["status"] == "uncertain" {
        let height = safe_height(
            &sdk.client()
                .rpc
                .call("getBlockHeight", json!([{"commitment":"finalized"}]))?,
        )?;
        if height > record.last_valid_block_height {
            // Validity height is journal metadata, not signed bytes. An imported
            // low height cannot release a proof while its blockhash is valid.
            let validity = sdk.client().rpc.call(
                "isBlockhashValid",
                json!([record.blockhash,{"commitment":"finalized"}]),
            )?;
            let valid = validity["value"]
                .as_bool()
                .ok_or_else(|| Error::config("Invalid blockhash validity observation"))?;
            if valid {
                record.update(result);
                return Ok(record);
            }
            let slot = safe_height(
                &sdk.client()
                    .rpc
                    .call("getSlot", json!([{"commitment":"finalized"}]))?,
            )?;
            // A newer processed blockhash is absent from finalized state too.
            // Confirm it is also invalid on a node at least this finalized slot.
            let processed = sdk.client().rpc.call(
                "isBlockhashValid",
                json!([record.blockhash,{"commitment":"processed","minContextSlot":slot}]),
            )?;
            if safe_height(&processed["context"]["slot"])? < slot {
                return Err(Error::config(
                    "Blockhash validity observation is behind finalized state",
                ));
            }
            let valid = processed["value"]
                .as_bool()
                .ok_or_else(|| Error::config("Invalid blockhash validity observation"))?;
            if valid {
                record.update(result);
                return Ok(record);
            }
            let block = sdk.client().rpc.call(
                "getBlock",
                json!([slot,{"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]),
            )?;
            let finalized = block
                .get("blockHeight")
                .filter(|v| !v.is_null())
                .map(safe_height)
                .transpose()?;
            if let Some(height) = finalized.filter(|h| *h > record.last_valid_block_height) {
                let state = sdk.state(policy, owner, true, Some(slot))?;
                if matches!(record.method.as_str(), "fund" | "withdraw" | "close") {
                    // Reobserve status after the coherent expiry boundary;
                    // a lagging initial RPC node cannot authorize addition.
                    result = sdk.status(&record.signature)?;
                    if result["status"] == "uncertain" {
                        record.extra.insert("blockhashExpired".into(), json!(true));
                        record.update(result);
                        return Ok(record);
                    }
                }
                let unchanged = if matches!(record.method.as_str(), "fund" | "withdraw" | "close") {
                    false
                } else if record.method == "deploy" {
                    state.is_none()
                } else {
                    state.as_ref().is_some_and(|s| {
                        if record.method == "execute" {
                            Some(&s.nonce) == record.nonce.as_ref()
                        } else {
                            Some(&s.revision) == record.revision.as_ref()
                        }
                    })
                };
                if unchanged {
                    record.status = "failed".into();
                    record
                        .extra
                        .insert("decisionCode".into(), json!("EXPIRED_UNEXECUTED"));
                    let mut absence = json!({"kind":format!("expired-{}",record.method),"height":height,"slot":slot});
                    if let Some(s) = state {
                        absence["nonce"] = json!(s.nonce);
                        absence["revision"] = json!(s.revision);
                    }
                    record.extra.insert("absence".into(), absence);
                    return Ok(record);
                }
                if !matches!(record.method.as_str(), "fund" | "withdraw" | "close") {
                    record.extra.insert("blockhashExpired".into(), json!(true));
                }
            }
        }
    }
    if result["status"] == "settled" {
        let receipt=sdk.client().rpc.call("getTransaction",json!([record.signature,{"commitment":"finalized","maxSupportedTransactionVersion":0,"encoding":"base64"}]))?;
        if receipt.is_null() {
            record.status = "uncertain".into();
            return Ok(record);
        }
        verify_receipt(&receipt, &proof, &record, sdk.client(), policy, owner)?;
    }
    record.update(result);
    Ok(record)
}

pub struct PolicyLifecycle<'a> {
    pub sdk: &'a dyn NativeOperations,
    pub journal: &'a FileJournal,
}
impl<'a> PolicyLifecycle<'a> {
    pub fn new(sdk: &'a dyn NativeOperations, journal: &'a FileJournal) -> Self {
        Self { sdk, journal }
    }
    pub fn reconcile(&self, record: Record, policy: &Policy, owner: Key) -> Result<Record> {
        reconcile_record(self.sdk, record, policy, owner)
    }
    fn reconcile_saved(&self, record: Record, policy: &Policy, owner: Key) -> Result<Record> {
        reconcile_saved_record(self.sdk, record, policy, owner, true)
    }
    pub fn submit(
        &self,
        policy: &Policy,
        owner: Key,
        method: &str,
        options: &Options,
        request_id: Option<&str>,
        mut sign: impl FnMut(&Transaction, &str) -> Result<[u8; 64]>,
    ) -> Result<Record> {
        policy.validate()?;
        let canonical = intent_for(self.sdk.client(), policy, owner, method, options)?;
        let id = request_id
            .map(str::to_owned)
            .unwrap_or_else(|| digest(canonical.as_bytes()));
        valid_id(&id)?;
        self.journal.locked(|| {
            let name=format!("request-{id}");
            let mut superseded = BTreeMap::<String, Record>::new();
            if let Some(prior)=self.journal.read::<Record>(&name)? {
                if prior.id!=id||prior.intent!=canonical{return Err(Error::config("Request ID conflict; recover the original request"));}
                let mut result=self.reconcile_saved(prior,policy,owner)?;self.journal.write(&name,&result)?;
                if result.final_status(){if self.journal.read::<Value>("execute-slot")?.is_some_and(|s|s["id"]==id){self.journal.clear("execute-slot")?;}}
                else if self.block_height()?<=result.last_valid_block_height{let _=self.broadcast(&result);}
                result.extra.insert("replayed".into(),json!(true));return Ok(result);
            }
            if method=="execute" {
                if let Some(slot)=self.journal.read::<Value>("execute-slot")? {
                    let previous=slot["id"].as_str().ok_or_else(||Error::config("Execution journal inconsistency"))?;valid_id(previous)?;
                    let old=self.journal.read::<Record>(&format!("request-{previous}"))?.ok_or_else(||Error::config("Execution journal inconsistency"))?;
                    if old.id!=previous||old.method!="execute" {return Err(Error::config("Execution journal inconsistency"));}
                    let reconciled=self.reconcile_saved(old,policy,owner)?;self.journal.write(&format!("request-{previous}"),&reconciled)?;
                    if !reconciled.final_status(){return Err(Error::config(format!("Execution {previous} is uncertain; recover it before a new spend")));}
                    self.journal.clear("execute-slot")?;
                }
            }
            if matches!(method,"fund"|"withdraw"|"close") {
                if let Some(slot)=self.journal.read::<Value>(&format!("owner-slot-{method}"))? {
                    let previous=slot["id"].as_str().ok_or_else(||Error::config("Owner journal inconsistency"))?;valid_id(previous)?;
                    let old=self.journal.read::<Record>(&format!("request-{previous}"))?.ok_or_else(||Error::config("Owner journal inconsistency"))?;
                    if old.id!=previous||old.method!=method{return Err(Error::config("Owner journal inconsistency"));}
                    if !self.superseded_owner(&old,policy,owner)? {
                        let reconciled=self.reconcile_saved(old,policy,owner)?;self.journal.write(&format!("request-{previous}"),&reconciled)?;
                        if !(reconciled.final_status()||reconciled.expired()&&options.additional_owner_operation){return Err(Error::config(format!("Earlier {method} is uncertain; recover it first. After verified expiry, explicitly authorize an additional owner operation while retaining the old proof.")));}
                        if !reconciled.final_status(){superseded.insert(previous.into(),reconciled);}
                    }
                }
            }
            if matches!(method,"fund"|"withdraw"|"close") {
                // Request persistence precedes the slot write. Orphaned signed
                // proofs from that crash window also block owner operations.
                for old in self.journal.entries::<Record>()? {
                    if old.method==method&&!old.final_status()&&!self.superseded_owner(&old,policy,owner)? {
                        let previous=old.id.clone();let reconciled=self.reconcile_saved(old,policy,owner)?;
                        self.journal.write(&format!("request-{previous}"),&reconciled)?;
                        if !(reconciled.final_status()||reconciled.expired()&&options.additional_owner_operation){return Err(Error::config(format!("Earlier {method} is uncertain; recover it first. After verified expiry, explicitly authorize an additional owner operation while retaining the old proof.")));}
                        if !reconciled.final_status(){superseded.insert(previous,reconciled);}
                    }
                }
            }
            let prepared=self.sdk.prepare(policy,owner,method,options)?;
            let binding=self.sdk.client().public_binding(policy,owner)?;
            let mut supplied=Vec::new();
            for signer in &prepared.transaction.signers {
                let role=if *signer==binding.owner{"owner"}else if *signer==binding.executor{"executor"}else if *signer==binding.authority{"authority"}else{return Err(Error::config("Unexpected native transaction signer"));};
                supplied.push((*signer,sign(&prepared.transaction,role)?));
            }
            let raw=prepared.transaction.signed_by(&supplied)?;
            let signatures:Vec<_>=supplied.iter().map(|(_,signature)|bs58::encode(signature).into_string()).collect();
            let signature=signatures.first().cloned().ok_or_else(||Error::config("Missing native transaction payer signature"))?;
            let mut record=Record{id:id.clone(),intent:canonical,method:method.into(),status:"uncertain".into(),transaction_url:self.sdk.client().transaction_url(&signature)?,signature,signatures,signed_bytes:base64::engine::general_purpose::STANDARD.encode(raw),blockhash:prepared.blockhash,last_valid_block_height:prepared.last_valid_block_height,nonce:prepared.nonce,revision:prepared.revision,expires_at:options.expires_at,commitment:options.commitment.clone(),instance_slot:options.instance_slot.map(|slot|slot.to_string()),extra:BTreeMap::new()};
            validate_record(self.sdk.client(),policy,owner,&record)?;
            self.journal.write(&name,&record)?;
            // Only a durable, validated successor proof can supersede an old
            // expired owner operation. Signing/write failure leaves its guard.
            for (previous,mut old) in superseded {
                old.extra.insert("supersededBy".into(),json!(id));
                self.journal.write(&format!("request-{previous}"),&old)?;
            }
            if matches!(method,"fund"|"withdraw"|"close"){self.journal.write(&format!("owner-slot-{method}"),&json!({"id":id}))?;}
            if method=="execute"{self.journal.write("execute-slot",&json!({"id":id}))?;}
            self.journal.write("last",&json!({"id":id}))?;
            if self.broadcast(&record).is_ok(){record.status="submitted".into();self.journal.write(&name,&record)?;}
            Ok(record)
        })
    }
    /// Complete a server-authorized execution without accepting caller-supplied
    /// transaction instructions. The authorization callback is lazy: a retry
    /// with an existing durable request reconciles and rebroadcasts the original
    /// proof without asking the server for another decision or signature.
    pub fn submit_authorized(
        &self,
        policy: &Policy,
        owner: Key,
        identity: &ExecutionRequestIdentity,
        mut authorize: impl FnMut() -> Result<AuthorizedExecution>,
        mut sign_executor: impl FnMut(&Transaction) -> Result<[u8; 64]>,
    ) -> Result<Record> {
        policy.validate()?;
        let id = identity.operation_id.clone();
        valid_id(&id)?;
        let input_digest = identity.digest()?;
        if identity.vault_policy_id != policy.id {
            return Err(Error::config("Execution request policy changed"));
        }
        self.journal.locked(|| {
            let name = format!("request-{id}");
            if let Some(prior) = self.journal.read::<Record>(&name)? {
                if prior.id != id
                    || prior.method != "execute"
                    || prior
                        .extra
                        .get("executionRequestDigest")
                        .and_then(Value::as_str)
                        != Some(input_digest.as_str())
                {
                    return Err(Error::config(
                        "Request ID conflict; recover the original request",
                    ));
                }
                let mut result = self.reconcile(prior, policy, owner)?;
                self.journal.write(&name, &result)?;
                if result.final_status()
                    && self
                        .journal
                        .read::<Value>("execute-slot")?
                        .is_some_and(|slot| slot["id"] == id)
                {
                    self.journal.clear("execute-slot")?;
                } else if !result.final_status()
                    && self.block_height()? <= result.last_valid_block_height
                {
                    let _ = self.broadcast(&result);
                }
                result.extra.insert("replayed".into(), json!(true));
                return Ok(result);
            }
            if let Some(slot) = self.journal.read::<Value>("execute-slot")? {
                let previous = slot["id"]
                    .as_str()
                    .ok_or_else(|| Error::config("Execution journal inconsistency"))?;
                valid_id(previous)?;
                let old = self
                    .journal
                    .read::<Record>(&format!("request-{previous}"))?
                    .ok_or_else(|| Error::config("Execution journal inconsistency"))?;
                if old.id != previous || old.method != "execute" {
                    return Err(Error::config("Execution journal inconsistency"));
                }
                let reconciled = self.reconcile(old, policy, owner)?;
                self.journal
                    .write(&format!("request-{previous}"), &reconciled)?;
                if !reconciled.final_status() {
                    return Err(Error::config(format!(
                        "Execution {previous} is uncertain; recover it before a new spend"
                    )));
                }
                self.journal.clear("execute-slot")?;
            }
            // A crash between writing a proof and reserving execute-slot must
            // not permit a second payment after restart.
            for old in self.journal.entries::<Record>()? {
                if old.method == "execute" && !old.final_status() {
                    let previous = old.id.clone();
                    let reconciled = self.reconcile(old, policy, owner)?;
                    self.journal
                        .write(&format!("request-{previous}"), &reconciled)?;
                    if !reconciled.final_status() {
                        return Err(Error::config(format!(
                            "Execution {previous} is uncertain; recover it before a new spend"
                        )));
                    }
                }
            }

            let authorized = authorize()?;
            let binding = self.sdk.client().public_binding(policy, owner)?;
            let amount_units = units(&identity.amount)?;
            if authorized.binding != binding
                || authorized.request.operation_id != id
                || authorized.request.input_digest != input_digest
                || authorized.request.vault_policy_id != policy.id
                || authorized.request.execution_policy_digest != policy.execution_policy_digest
                || authorized.request.execution_requirements_digest
                    != policy.execution_requirements_digest
                || authorized.request.recipient != identity.recipient
                || authorized.request.amount_units != amount_units
                || authorized.request.action != identity.action
                || authorized.request.merchant != identity.merchant
                || authorized.request.context_hash != identity.context_hash
                || authorized.request.digest()? != authorized.approval.request_digest
                || authorized.approval.assessment_digest.as_deref()
                    != policy
                        .semantic_required
                        .then_some(authorized.request.evidence_digest.as_str())
            {
                return Err(Error::config(
                    "Server approval differs from the execution request",
                ));
            }
            let state = self
                .sdk
                .state(policy, owner, false, None)?
                .ok_or_else(|| Error::config("Deploy the native policy first"))?;
            let expected_approval = ApprovalCommitment::new(
                policy,
                &state,
                &id,
                identity.recipient,
                &identity.amount,
                authorized.approval.expires_at,
                &authorized.approval.request_digest,
                authorized.approval.assessment_digest.as_deref(),
            )?;
            if authorized.approval != expected_approval
                || authorized.nonce != state.nonce
                || authorized.revision != state.revision
            {
                return Err(Error::config("Server approval or vault state changed"));
            }
            let options = authorized.approval.options()?;
            let intent = intent_for(self.sdk.client(), policy, owner, "execute", &options)?;
            if authorized.intent != intent {
                return Err(Error::config("Server execution intent changed"));
            }
            let transaction = Transaction::new(
                binding.executor,
                authorized.blockhash,
                self.sdk.client().expected_instructions(
                    policy,
                    &binding,
                    "execute",
                    &options,
                    Some(&authorized.nonce),
                    Some(&authorized.revision),
                )?,
            )?;
            if transaction.signers != [binding.executor, binding.authority]
                || authorized.message != transaction.message
                || authorized.simulation.units_consumed == 0
                || authorized.simulation.transaction_bytes != authorized.partial_transaction.len()
            {
                return Err(Error::config("Server prepared transaction changed"));
            }
            let partial = Signed::parse_partial(&authorized.partial_transaction)?;
            partial.matches(&transaction)?;
            if partial.signature(binding.authority).is_none()
                || partial.signature(binding.executor).is_some()
            {
                return Err(Error::config(
                    "Server response must contain only its authority signature",
                ));
            }
            let raw = transaction.add_signature(
                &authorized.partial_transaction,
                binding.executor,
                sign_executor(&transaction)?,
            )?;
            let proof = Signed::parse(&raw)?;
            proof.matches(&transaction)?;
            let signatures: Vec<_> = proof
                .signatures
                .iter()
                .map(|signature| bs58::encode(signature).into_string())
                .collect();
            let signature = bs58::encode(proof.primary_signature()?).into_string();
            let mut extra = BTreeMap::new();
            extra.insert("executionRequestDigest".into(), json!(input_digest));
            extra.insert("approvalRequest".into(), json!(authorized.request));
            extra.insert("approval".into(), json!(authorized.approval));
            extra.insert("simulation".into(), json!(authorized.simulation));
            let mut record = Record {
                id: id.clone(),
                intent,
                method: "execute".into(),
                status: "uncertain".into(),
                transaction_url: self.sdk.client().transaction_url(&signature)?,
                signature,
                signatures,
                signed_bytes: base64::engine::general_purpose::STANDARD.encode(raw),
                blockhash: authorized.blockhash,
                last_valid_block_height: authorized.last_valid_block_height,
                nonce: Some(authorized.nonce),
                revision: Some(authorized.revision),
                expires_at: options.expires_at,
                commitment: options.commitment.clone(),
                instance_slot: options.instance_slot.map(|slot| slot.to_string()),
                extra,
            };
            validate_record(self.sdk.client(), policy, owner, &record)?;
            self.journal.write(&name, &record)?;
            self.journal.write("execute-slot", &json!({"id":id}))?;
            self.journal.write("last", &json!({"id":id}))?;
            if self.broadcast(&record).is_ok() {
                record.status = "submitted".into();
                self.journal.write(&name, &record)?;
            }
            Ok(record)
        })
    }
    fn superseded_owner(&self, old: &Record, policy: &Policy, owner: Key) -> Result<bool> {
        if !old.expired() {
            return Ok(false);
        }
        let Some(id) = old.extra.get("supersededBy").and_then(Value::as_str) else {
            return Ok(false);
        };
        valid_id(id)?;
        if id == old.id {
            return Err(Error::config("Owner journal supersession inconsistency"));
        }
        let Some(next) = self.journal.read::<Record>(&format!("request-{id}"))? else {
            return Ok(false);
        };
        if next.id != id || next.method != old.method {
            return Err(Error::config("Owner journal supersession inconsistency"));
        }
        validate_record(self.sdk.client(), policy, owner, &next)?;
        Ok(true)
    }
    pub fn recover(&self, id: &str, policy: &Policy, owner: Key) -> Result<Record> {
        valid_id(id)?;
        policy.validate()?;
        self.journal.locked(|| {
            let name = format!("request-{id}");
            let prior = self
                .journal
                .read::<Record>(&name)?
                .ok_or_else(|| Error::config("Unknown request ID"))?;
            if prior.id != id {
                return Err(Error::config("Operation journal ID mismatch"));
            }
            let result = self.reconcile_saved(prior, policy, owner)?;
            self.journal.write(&name, &result)?;
            Ok(result)
        })
    }
    fn block_height(&self) -> Result<u64> {
        safe_height(
            &self
                .sdk
                .client()
                .rpc
                .call("getBlockHeight", json!([{"commitment":"finalized"}]))?,
        )
    }
    fn broadcast(&self, record: &Record) -> Result<()> {
        let result=self.sdk.client().rpc.call("sendTransaction",json!([record.signed_bytes,{"encoding":"base64","skipPreflight":false,"maxRetries":0,"preflightCommitment":"finalized"}]))?;
        if result != record.signature {
            return Err(Error::uncertain("RPC returned a different signature"));
        }
        Ok(())
    }
}
fn valid_id(id: &str) -> Result<()> {
    if !(8..=100).contains(&id.len())
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
    {
        return Err(Error::config(
            "Request ID must be 8–100 ASCII identifier characters",
        ));
    }
    Ok(())
}
fn verify_receipt(
    receipt: &Value,
    proof: &Signed,
    record: &Record,
    sdk: &NativeClient,
    policy: &Policy,
    owner: Key,
) -> Result<()> {
    let raw = receipt["transaction"][0]
        .as_str()
        .filter(|_| receipt["transaction"][1] == "base64")
        .ok_or_else(|| Error::config("Chain receipt does not match saved native transaction"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| Error::config("Invalid transaction receipt"))?;
    let chain = Signed::parse(&raw)?;
    if receipt["meta"].is_null()
        || !receipt["meta"]["err"].is_null()
        || chain.message != proof.message
        || chain.signatures != proof.signatures
    {
        return Err(Error::config(
            "Chain receipt does not match saved native transaction",
        ));
    }
    if record.method == "execute" {
        let b = sdk.public_binding(policy, owner)?;
        let mut programs = Vec::new();
        if let Some(groups) = receipt["meta"]["innerInstructions"].as_array() {
            for g in groups {
                if let Some(instructions) = g["instructions"].as_array() {
                    for i in instructions {
                        if let Some(index) = i["programIdIndex"]
                            .as_u64()
                            .and_then(|i| usize::try_from(i).ok())
                        {
                            if let Some(key) = chain.keys.get(index) {
                                programs.push(key.key);
                            }
                        }
                    }
                }
            }
        }
        if !programs.contains(&b.policy) || !programs.contains(&Key::parse(TOKEN_PROGRAM)?) {
            return Err(Error::config("Native policy or SPL CPI is missing"));
        }
        let intent: Intent = serde_json::from_str(&record.intent)
            .map_err(|_| Error::config("Invalid operation intent"))?;
        let amount = units(
            intent
                .amount
                .as_deref()
                .ok_or_else(|| Error::config("Missing transfer amount"))?,
        )?;
        let source = chain
            .keys
            .iter()
            .position(|k| k.key == b.token_account)
            .ok_or_else(|| Error::config("Missing token balance proof"))?;
        let destination = chain
            .keys
            .iter()
            .position(|k| Some(k.key) == intent.recipient)
            .ok_or_else(|| Error::config("Missing token balance proof"))?;
        let balance = |kind: &str, index: usize| -> Result<u64> {
            let entry = receipt["meta"][kind]
                .as_array()
                .and_then(|xs| xs.iter().find(|x| x["accountIndex"] == index))
                .ok_or_else(|| Error::config("Missing token balance proof"))?;
            if entry["mint"] != b.mint.to_string() {
                return Err(Error::config("Missing token balance proof"));
            }
            crate::native::number(
                entry["uiTokenAmount"]["amount"]
                    .as_str()
                    .ok_or_else(|| Error::config("Missing token balance proof"))?,
            )
        };
        if balance("preTokenBalances", source)?.checked_sub(balance("postTokenBalances", source)?)
            != Some(amount)
            || balance("postTokenBalances", destination)?
                .checked_sub(balance("preTokenBalances", destination)?)
                != Some(amount)
        {
            return Err(Error::config("Native transfer balance deltas differ"));
        }
    }
    Ok(())
}
