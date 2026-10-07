use crate::{
    client::{ATA_PROGRAM, Binding, NativeClient, TOKEN_PROGRAM, associated_token_address, hex32},
    crypto::Key,
    error::{Error, Result},
    policy::{MAX_DAILY_UNITS, Policy, decimal, digest, units},
    release, rpc,
    transaction::{Instruction, Meta, Transaction},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
pub const MAX_APPROVAL_SECONDS: u64 = 300;
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Key>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_slot: Option<u64>,
    #[serde(default)]
    pub additional_owner_operation: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    #[serde(flatten)]
    pub binding: Binding,
    pub abi: u8,
    pub source_bundle: String,
    pub policy_artifact: String,
    pub vault_id: String,
    pub daily_limit: String,
    pub action_limit: String,
    pub spent: String,
    pub spent_day: String,
    pub nonce: String,
    pub revision: String,
    pub instance_slot: String,
    pub approved: bool,
    pub balance: String,
}
/// Caller-controlled fields that define one logical execution request. The
/// digest is stable across authorization retries and excludes server decisions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRequestIdentity {
    pub version: u8,
    pub operation_id: String,
    pub vault_policy_id: String,
    pub amount: String,
    pub recipient: Key,
    pub action: String,
    pub merchant: String,
    pub context_hash: String,
}
impl ExecutionRequestIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: &Policy,
        operation_id: &str,
        amount: &str,
        recipient: Key,
        action: &str,
        merchant: &str,
        context: &Value,
    ) -> Result<Self> {
        let amount = decimal(units(amount)?);
        let encoded = serde_json::to_string(context)
            .map_err(|_| Error::config("Invalid execution context"))?;
        if !context.is_object() || encoded.len() > 16_384 {
            return Err(Error::config("Execution context must be a JSON object"));
        }
        let context_hash = digest(go_compact_json(&encoded));
        let identity = Self {
            version: 1,
            operation_id: operation_id.into(),
            vault_policy_id: policy.id.clone(),
            amount,
            recipient,
            action: action.into(),
            merchant: merchant.into(),
            context_hash,
        };
        identity.validate()?;
        Ok(identity)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(digest(serde_json::to_vec(self).map_err(|_| {
            Error::config("Invalid execution request identity")
        })?))
    }
    fn validate(&self) -> Result<()> {
        let amount = units(&self.amount)?;
        if self.version != 1
            || !(8..=100).contains(&self.operation_id.len())
            || !self
                .operation_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
            || hex32(&self.vault_policy_id)? == [0; 32]
            || amount == 0
            || decimal(amount) != self.amount
            || self.action.trim() != self.action
            || self.action.is_empty()
            || self.action.len() > 100
            || self.action.chars().any(char::is_control)
            || self.merchant.trim() != self.merchant
            || self.merchant.len() > 200
            || self.merchant.chars().any(char::is_control)
            || hex32(&self.context_hash)? == [0; 32]
        {
            return Err(Error::config("Invalid execution request identity"));
        }
        Ok(())
    }
}
/// Server decision inputs whose digest is committed into the transfer. This
/// exposes policy/evidence identity without placing those documents on chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    pub version: u8,
    pub operation_id: String,
    pub input_digest: String,
    pub vault_policy_id: String,
    pub execution_policy_id: String,
    pub execution_policy_digest: String,
    pub execution_requirements_digest: String,
    pub execution_policy_revision: i64,
    pub recipient: Key,
    pub amount_units: u64,
    pub action: String,
    pub merchant: String,
    pub context_hash: String,
    pub decision_code: String,
    pub evidence_digest: String,
}
impl ApprovalRequest {
    pub fn digest(&self) -> Result<String> {
        if self.version != 1
            || !(8..=100).contains(&self.operation_id.len())
            || !self
                .operation_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
            || self.execution_policy_id.is_empty()
            || self.execution_policy_revision < 0
            || self.amount_units == 0
            || self.action.trim() != self.action
            || self.action.is_empty()
            || self.action.len() > 100
            || self.action.chars().any(char::is_control)
            || self.merchant.trim() != self.merchant
            || self.merchant.len() > 200
            || self.merchant.chars().any(char::is_control)
            || self.decision_code != "PASS"
        {
            return Err(Error::config("Invalid approval request"));
        }
        for value in [
            self.input_digest.as_str(),
            self.vault_policy_id.as_str(),
            self.execution_policy_digest.as_str(),
            self.execution_requirements_digest.as_str(),
            self.context_hash.as_str(),
            self.evidence_digest.as_str(),
        ] {
            if hex32(value)? == [0; 32] {
                return Err(Error::config("Invalid approval request"));
            }
        }
        Ok(digest(
            serde_json::to_vec(self).map_err(|_| Error::config("Invalid approval request"))?,
        ))
    }
}
/// Canonical trusted-server authorization envelope. Its digest is embedded in
/// the transfer instruction and therefore signed by both executor and authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalCommitment {
    pub version: u32,
    pub operation_id: String,
    pub operation: String,
    pub policy_id: String,
    pub policy_revision: String,
    pub instance_slot: String,
    pub network: String,
    pub custody_program: Key,
    pub vault: Key,
    pub mint: Key,
    pub recipient: Key,
    pub executor: Key,
    pub authority: Key,
    pub amount_units: String,
    pub nonce: String,
    pub expires_at: u64,
    pub execution_policy_digest: String,
    pub execution_requirements_digest: String,
    pub semantic_required: bool,
    pub request_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment_digest: Option<String>,
    pub decision: String,
}
impl ApprovalCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: &Policy,
        state: &State,
        operation_id: &str,
        recipient: Key,
        amount: &str,
        expires_at: u64,
        request_digest: &str,
        assessment_digest: Option<&str>,
    ) -> Result<Self> {
        if !(8..=100).contains(&operation_id.len())
            || !operation_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
        {
            return Err(Error::config("Invalid approval operation ID"));
        }
        let validate_digest = |value: &str| -> Result<String> {
            let bytes = hex32(value)?;
            if bytes == [0; 32] {
                return Err(Error::config("Approval digest must be nonzero"));
            }
            Ok(value.to_owned())
        };
        let request_digest = validate_digest(request_digest)?;
        let assessment_digest = assessment_digest.map(validate_digest).transpose()?;
        if policy.semantic_required != assessment_digest.is_some() {
            return Err(Error::config(
                "Semantic assessment presence differs from policy requirements",
            ));
        }
        if state.vault_id != policy.id
            || state.source_bundle != policy.source_bundle
            || state.policy_artifact != policy.policy_artifact
        {
            return Err(Error::config("Approval policy or vault binding changed"));
        }
        Ok(Self {
            version: 1,
            operation_id: operation_id.into(),
            operation: "transfer".into(),
            policy_id: policy.id.clone(),
            policy_revision: state.revision.clone(),
            instance_slot: state.instance_slot.clone(),
            network: policy.network.clone(),
            custody_program: state.binding.custody,
            vault: state.binding.vault,
            mint: state.binding.mint,
            recipient,
            executor: state.binding.executor,
            authority: state.binding.authority,
            amount_units: units(amount)?.to_string(),
            nonce: state.nonce.clone(),
            expires_at,
            execution_policy_digest: policy.execution_policy_digest.clone(),
            execution_requirements_digest: policy.execution_requirements_digest.clone(),
            semantic_required: policy.semantic_required,
            request_digest,
            assessment_digest,
            decision: "allow".into(),
        })
    }
    pub fn digest(&self) -> Result<String> {
        if self.version != 1
            || self.operation != "transfer"
            || self.decision != "allow"
            || self.semantic_required != self.assessment_digest.is_some()
            || !(8..=100).contains(&self.operation_id.len())
            || !self
                .operation_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
        {
            return Err(Error::config("Invalid approval commitment"));
        }
        for value in [
            self.policy_id.as_str(),
            self.execution_policy_digest.as_str(),
            self.execution_requirements_digest.as_str(),
            self.request_digest.as_str(),
        ]
        .into_iter()
        .chain(self.assessment_digest.as_deref())
        {
            if hex32(value)? == [0; 32] {
                return Err(Error::config("Approval digest must be nonzero"));
            }
        }
        for value in [
            &self.policy_revision,
            &self.instance_slot,
            &self.amount_units,
            &self.nonce,
        ] {
            number(value)?;
        }
        Ok(digest(serde_json::to_vec(self).map_err(|_| {
            Error::config("Invalid approval commitment")
        })?))
    }
    pub fn options(&self) -> Result<Options> {
        Ok(Options {
            amount: Some(decimal(number(&self.amount_units)?)),
            recipient: Some(self.recipient),
            expires_at: Some(self.expires_at),
            commitment: Some(self.digest()?),
            instance_slot: Some(number(&self.instance_slot)?),
            additional_owner_operation: false,
        })
    }
}

// Match the server's encoding/json compaction for a raw context carried in an
// HTTP request. serde_json has already validated the string and escape syntax.
fn go_compact_json(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in raw.chars() {
        if in_string {
            match c {
                '<' => result.push_str("\\u003c"),
                '>' => result.push_str("\\u003e"),
                '&' => result.push_str("\\u0026"),
                '\u{2028}' => result.push_str("\\u2028"),
                '\u{2029}' => result.push_str("\\u2029"),
                _ => result.push(c),
            }
            if c == '"' && !escaped {
                in_string = false;
            }
            escaped = c == '\\' && !escaped;
        } else if c == '"' {
            in_string = true;
            result.push(c);
        } else if !c.is_ascii_whitespace() {
            result.push(c);
        }
    }
    result
}
pub struct Prepared {
    pub transaction: Transaction,
    pub simulation: Simulation,
    pub nonce: Option<String>,
    pub revision: Option<String>,
    pub last_valid_block_height: u64,
    pub blockhash: Key,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Simulation {
    pub context_slot: u64,
    pub units_consumed: u64,
    pub transaction_bytes: usize,
}
impl NativeClient {
    pub fn state(
        &self,
        policy: &Policy,
        owner: Key,
        recovery: bool,
        min_context_slot: Option<u64>,
    ) -> Result<Option<State>> {
        let b = self.binding(policy, owner, recovery)?;
        let Some(info) = rpc::account(self.rpc.as_ref(), b.vault, min_context_slot)? else {
            return Ok(None);
        };
        if info.owner != b.custody {
            return Err(Error::config("Wrong vault account owner"));
        }
        let expected_authority = b.authority;
        let s = decode_state(&info.data, b)?;
        if s.vault_id != policy.id
            || s.source_bundle != policy.source_bundle
            || s.policy_artifact != policy.policy_artifact
            || number(&s.daily_limit)? > MAX_DAILY_UNITS
            || number(&s.action_limit)? > MAX_DAILY_UNITS
            || s.binding.authority != expected_authority
        {
            return Err(Error::config("Vault identity/limits mismatch"));
        }
        let tokens = self.token(s.binding.token_account)?;
        if tokens.owner != s.binding.vault
            || tokens.mint != s.binding.mint
            || tokens.delegate
            || tokens.close_authority
        {
            return Err(Error::config("Unsafe custody token account"));
        }
        Ok(Some(State {
            balance: tokens.amount.to_string(),
            ..s
        }))
    }
    pub fn prepare(
        &self,
        policy: &Policy,
        owner: Key,
        method: &str,
        options: &Options,
    ) -> Result<Prepared> {
        let recovery = matches!(method, "revoke" | "withdraw" | "close");
        let b = self.binding(policy, owner, recovery)?;
        let s = self.state(policy, owner, recovery, None)?;
        let amount = options.amount.as_deref().map(units).transpose()?;
        if matches!(
            method,
            "deploy" | "fund" | "execute" | "withdraw" | "tune" | "tune_action"
        ) && amount.is_none()
        {
            return Err(Error::config("Specify the amount"));
        }
        if amount == Some(0) && !matches!(method, "tune" | "tune_action") {
            return Err(Error::denied("Amount must be positive"));
        }
        let nonce = s.as_ref().map(|s| s.nonce.clone());
        let revision = s.as_ref().map(|s| s.revision.clone());
        if method == "deploy" {
            if s.is_some() {
                return Err(Error::config(
                    "Vault already exists; recover its status instead of redeploying",
                ));
            }
            let source = associated_token_address(b.mint, owner, false)?;
            let a = self.token(source)?;
            if a.owner != owner || a.amount < amount.unwrap() {
                return Err(Error::denied("Insufficient owner test-token balance"));
            }
        } else {
            let state = s
                .as_ref()
                .ok_or_else(|| Error::config("Deploy the native policy first"))?;
            match method {
                "fund" => {
                    let source = associated_token_address(b.mint, owner, false)?;
                    let a = self.token(source)?;
                    if a.owner != owner || a.amount < amount.unwrap() {
                        return Err(Error::denied("Insufficient owner test-token balance"));
                    }
                }
                "execute" => {
                    if !state.approved {
                        return Err(Error::denied("Standing approval is withdrawn"));
                    }
                    let day = self.chain_time()? / 86400;
                    let spent = if day == number(&state.spent_day)? {
                        number(&state.spent)?
                    } else {
                        0
                    };
                    if amount.unwrap() > number(&state.daily_limit)?.saturating_sub(spent) {
                        return Err(Error::denied("Daily limit exceeded"));
                    }
                    if amount.unwrap() > number(&state.action_limit)? {
                        return Err(Error::denied("Per-action limit exceeded"));
                    }
                    if amount.unwrap() > number(&state.balance)? {
                        return Err(Error::denied("Insufficient vault balance"));
                    }
                    let a = self.token(
                        options
                            .recipient
                            .ok_or_else(|| Error::config("Specify the recipient"))?,
                    )?;
                    if a.mint != b.mint || a.owner == b.vault {
                        return Err(Error::config("Invalid destination token account"));
                    }
                    let now = self.chain_time()?;
                    let expires_at = options
                        .expires_at
                        .ok_or_else(|| Error::config("Specify the approval expiry"))?;
                    if expires_at < now || expires_at > now.saturating_add(MAX_APPROVAL_SECONDS) {
                        return Err(Error::denied("Execution approval has invalid expiry"));
                    }
                    let commitment = options
                        .commitment
                        .as_deref()
                        .ok_or_else(|| Error::config("Specify the approval commitment"))?;
                    if hex32(commitment)? == [0; 32] {
                        return Err(Error::config("Approval commitment must be nonzero"));
                    }
                    if options.instance_slot != Some(number(&state.instance_slot)?) {
                        return Err(Error::config("Vault instance identity changed"));
                    }
                }
                "tune" | "tune_action" if amount.unwrap() > MAX_DAILY_UNITS => {
                    return Err(Error::denied("Daily limit exceeds compiled ceiling"));
                }
                "close" if options.instance_slot != Some(number(&state.instance_slot)?) => {
                    return Err(Error::config("Vault instance identity changed"));
                }
                "tune" | "tune_action" | "revoke" | "withdraw" | "close" => (),
                _ => return Err(Error::config("Unsupported policy command")),
            }
        }
        let instructions = self.expected_instructions(
            policy,
            &b,
            method,
            options,
            nonce.as_deref(),
            revision.as_deref(),
        )?;
        let latest = self
            .rpc
            .call("getLatestBlockhash", json!([{"commitment":"finalized"}]))?;
        let blockhash = Key::parse(
            latest["value"]["blockhash"]
                .as_str()
                .ok_or_else(|| Error::config("Invalid latest blockhash"))?,
        )?;
        let last_valid_block_height = safe_height(&latest["value"]["lastValidBlockHeight"])?;
        let transaction = Transaction::new(
            if method == "execute" {
                b.executor
            } else {
                b.owner
            },
            blockhash,
            instructions,
        )?;
        let simulation = self.simulate(&transaction)?;
        Ok(Prepared {
            transaction,
            simulation,
            nonce,
            revision,
            last_valid_block_height,
            blockhash,
        })
    }
    pub fn simulate(&self, transaction: &Transaction) -> Result<Simulation> {
        let raw = transaction.partially_signed(&[])?;
        let response = self.rpc.call(
            "simulateTransaction",
            json!([
                base64::engine::general_purpose::STANDARD.encode(&raw),
                {
                    "encoding":"base64",
                    "sigVerify":false,
                    "replaceRecentBlockhash":false,
                    "commitment":"finalized"
                }
            ]),
        )?;
        let value = response["value"]
            .as_object()
            .ok_or_else(|| Error::config("Invalid native transaction simulation"))?;
        if value.get("err") != Some(&Value::Null) {
            return Err(Error::denied("Native transaction simulation failed"));
        }
        let units_consumed = value
            .get("unitsConsumed")
            .and_then(Value::as_u64)
            .filter(|units| *units > 0)
            .ok_or_else(|| Error::config("Native simulation omitted compute units"))?;
        Ok(Simulation {
            context_slot: safe_height(&response["context"]["slot"])?,
            units_consumed,
            transaction_bytes: raw.len(),
        })
    }
    pub fn expected_instructions(
        &self,
        policy: &Policy,
        b: &Binding,
        method: &str,
        options: &Options,
        nonce: Option<&str>,
        revision: Option<&str>,
    ) -> Result<Vec<Instruction>> {
        let amount = options.amount.as_deref().map(units).transpose()?;
        let required = || amount.ok_or_else(|| Error::config("Specify the amount"));
        let revision = || {
            revision
                .ok_or_else(|| Error::config("Invalid operation revision"))
                .and_then(number)
        };
        let instruction = |tag: u8, tail: Vec<u8>, accounts: Vec<Meta>| {
            let mut data = vec![tag];
            data.extend(tail);
            Instruction {
                program: b.custody,
                accounts,
                data,
            }
        };
        let meta = |key, writable, signer| Meta {
            key,
            writable,
            signer,
        };
        let ro = |key| meta(key, false, false);
        let w = |key| meta(key, true, false);
        let s = |key| meta(key, false, true);
        let owner_ata = || associated_token_address(b.mint, b.owner, false);
        let mut operation = match method {
            "deploy" => {
                let mut fields = hex32(&policy.id)?.to_vec();
                fields.extend(hex32(&release().source_bundle)?);
                fields.extend(hex32(&release().artifacts[0].sha256)?);
                fields.extend(units(&policy.daily_limit)?.to_le_bytes());
                fields.extend(units(&policy.action_limit)?.to_le_bytes());
                let funding = required()?;
                let source = owner_ata()?;
                let approve = {
                    let mut data = vec![1];
                    data.extend(0u64.to_le_bytes());
                    data
                };
                vec![
                    ata(b.owner, b.token_account, b.vault, b.mint)?,
                    instruction(
                        0,
                        fields,
                        vec![
                            w(b.vault),
                            meta(b.owner, true, true),
                            ro(b.mint),
                            ro(b.token_account),
                            ro(b.policy),
                            ro(b.executor),
                            ro(Key::parse(SYSTEM_PROGRAM)?),
                            ro(b.policy_data),
                            ro(b.authority),
                        ],
                    ),
                    instruction(
                        1,
                        funding.to_le_bytes().to_vec(),
                        vec![
                            w(b.vault),
                            s(b.owner),
                            w(source),
                            w(b.token_account),
                            ro(b.mint),
                            ro(Key::parse(TOKEN_PROGRAM)?),
                        ],
                    ),
                    instruction(
                        2,
                        approve,
                        vec![w(b.vault), s(b.owner), ro(b.policy), ro(b.policy_data)],
                    ),
                ]
            }
            "fund" => vec![instruction(
                1,
                required()?.to_le_bytes().to_vec(),
                vec![
                    w(b.vault),
                    s(b.owner),
                    w(owner_ata()?),
                    w(b.token_account),
                    ro(b.mint),
                    ro(Key::parse(TOKEN_PROGRAM)?),
                ],
            )],
            "execute" => {
                let mut data = required()?.to_le_bytes().to_vec();
                data.extend(
                    nonce
                        .ok_or_else(|| Error::config("Invalid operation nonce"))
                        .and_then(number)?
                        .to_le_bytes(),
                );
                data.extend(revision()?.to_le_bytes());
                data.extend(
                    options
                        .expires_at
                        .ok_or_else(|| Error::config("Specify the approval expiry"))?
                        .to_le_bytes(),
                );
                data.extend(hex32(
                    options
                        .commitment
                        .as_deref()
                        .ok_or_else(|| Error::config("Specify the approval commitment"))?,
                )?);
                data.extend(
                    options
                        .instance_slot
                        .ok_or_else(|| Error::config("Specify the vault instance slot"))?
                        .to_le_bytes(),
                );
                vec![instruction(
                    4,
                    data,
                    vec![
                        w(b.vault),
                        s(b.executor),
                        w(b.token_account),
                        w(options
                            .recipient
                            .ok_or_else(|| Error::config("Specify the recipient"))?),
                        ro(b.mint),
                        ro(Key::parse(TOKEN_PROGRAM)?),
                        ro(b.policy),
                        ro(b.policy_data),
                        s(b.authority),
                    ],
                )]
            }
            "revoke" => {
                let mut data = vec![0];
                data.extend(revision()?.to_le_bytes());
                vec![instruction(
                    2,
                    data,
                    vec![w(b.vault), s(b.owner), ro(b.policy)],
                )]
            }
            "tune" => {
                let mut data = required()?.to_le_bytes().to_vec();
                data.extend(revision()?.to_le_bytes());
                vec![instruction(
                    3,
                    data,
                    vec![w(b.vault), s(b.owner), ro(b.policy), ro(b.policy_data)],
                )]
            }
            "tune_action" => {
                let mut data = required()?.to_le_bytes().to_vec();
                data.extend(revision()?.to_le_bytes());
                vec![instruction(8, data, vec![w(b.vault), s(b.owner)])]
            }
            "withdraw" => {
                let destination = owner_ata()?;
                vec![
                    ata(b.owner, destination, b.owner, b.mint)?,
                    instruction(
                        5,
                        required()?.to_le_bytes().to_vec(),
                        vec![
                            w(b.vault),
                            s(b.owner),
                            w(b.token_account),
                            w(destination),
                            ro(b.mint),
                            ro(Key::parse(TOKEN_PROGRAM)?),
                        ],
                    ),
                ]
            }
            "close" => {
                let destination = owner_ata()?;
                let mut data = revision()?.to_le_bytes().to_vec();
                data.extend(
                    options
                        .instance_slot
                        .ok_or_else(|| Error::config("Specify the vault instance slot"))?
                        .to_le_bytes(),
                );
                vec![
                    ata(b.owner, destination, b.owner, b.mint)?,
                    instruction(
                        9,
                        data,
                        vec![
                            w(b.vault),
                            meta(b.owner, true, true),
                            w(b.token_account),
                            w(destination),
                            ro(b.mint),
                            ro(Key::parse(TOKEN_PROGRAM)?),
                        ],
                    ),
                ]
            }
            _ => return Err(Error::config("Unsupported persisted operation")),
        };
        let mut instructions = compute_budget(method)?;
        instructions.append(&mut operation);
        Ok(instructions)
    }
    pub fn chain_time(&self) -> Result<u64> {
        let slot = self
            .rpc
            .call("getSlot", json!([{"commitment":"finalized"}]))?;
        let slot = safe_height(&slot)?;
        let time = self.rpc.call("getBlockTime", json!([slot]))?;
        safe_height(&time).map_err(|_| Error::config("Chain time is unavailable"))
    }
    pub fn status(&self, signature: &str) -> Result<Value> {
        self.check_network()?;
        let result = self.rpc.call(
            "getSignatureStatuses",
            json!([[signature],{"searchTransactionHistory":true}]),
        )?;
        let v = &result["value"][0];
        let mut out = json!({"status":"uncertain","signature":signature,"transactionUrl":self.transaction_url(signature)?});
        if !v.is_null() {
            let finalized = v["confirmationStatus"] == "finalized";
            if !v["err"].is_null() {
                out["status"] = json!(if finalized { "failed" } else { "uncertain" });
                out["error"] = v["err"].clone();
            } else {
                out["status"] = json!(if finalized { "settled" } else { "submitted" });
            }
        }
        Ok(out)
    }
    pub fn transaction_url(&self, signature: &str) -> Result<String> {
        if !(80..=90).contains(&signature.len())
            || bs58::decode(signature)
                .into_vec()
                .map_or(true, |b| b.len() != 64)
        {
            return Err(Error::config("Invalid transaction signature"));
        }
        Ok(format!(
            "https://explorer.solana.com/tx/{signature}?cluster={}",
            self.config.network.split(':').nth(1).unwrap()
        ))
    }
    pub fn bundle(&self, policy: &Policy, owner: Key) -> Result<Value> {
        policy.validate()?;
        let b = self.public_binding(policy, owner)?;
        Ok(
            json!({"version":2,"policy":policy,"context":{"policyId":policy.id,"owner":owner,"network":policy.network,"mint":b.mint,"executor":b.executor,"authority":b.authority,"deployment":self.config.deployment}}),
        )
    }
    pub fn skill(&self, policy: &Policy, state: &State) -> Result<String> {
        if !state.approved
            || state.source_bundle != policy.source_bundle
            || state.policy_artifact != policy.policy_artifact
        {
            return Err(Error::config(
                "Finalize deployment and standing approval before issuing a skill",
            ));
        }
        let b = &state.binding;
        let mut text = format!(
            "---\nname: allowit-policy-{}\ndescription: Execute transfers governed by this AllowIt native Solana policy.\n---\n\nPolicy {}; {}; mint {}.\nOwner {}; executor {}; trusted authority {}; vault {}; custody {}.\nOn chain: standing approval, up to {} test tokens per action, and up to {} per UTC day.\nTask: {}. Server gate digest {}; requirements digest {}; semantic checks required: {}. The server must evaluate the bound policy before cosigning; the native artifact itself enforces only the stated numeric and signer rules.\n\nImport the issued executor.json with `allowit policy import executor.json` on the executor device. Configure only the designated ALLOWIT_EXECUTOR_KEYPAIR there; never provide the owner or authority secret key. Run `allowit policy status` before acting. For each new operation, choose one ALLOWIT_REQUEST_ID and run `allowit policy execute RECIPIENT_TOKEN_ACCOUNT AMOUNT`. Keep that ID and exact intent for retries. Exit 6 means replay of the earlier receipt, not another payment. The executor and trusted server authority sign the exact transaction; this skill contains no keys. After an uncertain result, recover the saved operation with `allowit policy status`; never submit a replacement. A settled transfer does not prove delivery of a purchased service.",
            &policy.id[..16],
            policy.id,
            policy.network,
            b.mint,
            b.owner,
            b.executor,
            b.authority,
            b.vault,
            b.custody,
            decimal(number(&state.action_limit)?),
            decimal(number(&state.daily_limit)?),
            serde_json::to_string(&policy.prompt).unwrap(),
            policy.execution_policy_digest,
            policy.execution_requirements_digest,
            policy.semantic_required,
        );
        if policy.pay_discovery {
            text.push_str("\n\nFor paid APIs, discover providers through PaySH: https://pay.sh/docs/using-pay/skills. Payment execution through PaySH is unavailable in this profile. Do not pay using another wallet or Pay payment tools as a fallback. Report unsupported payment execution.");
        }
        text.push('\n');
        Ok(text)
    }
}
fn compute_budget(method: &str) -> Result<Vec<Instruction>> {
    let program = Key::parse(COMPUTE_BUDGET_PROGRAM)?;
    let limit = match method {
        "deploy" => 400_000u32,
        "execute" => 300_000u32,
        _ => 200_000u32,
    };
    let mut units = vec![2];
    units.extend(limit.to_le_bytes());
    let mut price = vec![3];
    price.extend(1u64.to_le_bytes());
    Ok(vec![
        Instruction {
            program,
            accounts: Vec::new(),
            data: units,
        },
        Instruction {
            program,
            accounts: Vec::new(),
            data: price,
        },
    ])
}
fn ata(payer: Key, address: Key, owner: Key, mint: Key) -> Result<Instruction> {
    let meta = |key, writable, signer| Meta {
        key,
        writable,
        signer,
    };
    Ok(Instruction {
        program: Key::parse(ATA_PROGRAM)?,
        accounts: vec![
            meta(payer, true, true),
            meta(address, true, false),
            meta(owner, false, false),
            meta(mint, false, false),
            meta(Key::parse(SYSTEM_PROGRAM)?, false, false),
            meta(Key::parse(TOKEN_PROGRAM)?, false, false),
        ],
        data: vec![1],
    })
}
pub fn number(value: &str) -> Result<u64> {
    if value.is_empty()
        || !value.bytes().all(|c| c.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(Error::config("Invalid unsigned integer"));
    }
    value
        .parse()
        .map_err(|_| Error::config("Invalid unsigned integer"))
}
pub fn safe_height(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .filter(|h| *h <= 9_007_199_254_740_991)
        .ok_or_else(|| Error::config("Invalid finalized height or slot"))
}
fn decode_state(d: &[u8], b: Binding) -> Result<State> {
    if d.len() != 352 || d[0] != 2 || d[298] > 1 || d[347..].iter().any(|n| *n != 0) {
        return Err(Error::config("Invalid native vault state"));
    }
    for (i, (name, k)) in [
        ("owner", b.owner),
        ("executor", b.executor),
        ("mint", b.mint),
        ("tokenAccount", b.token_account),
        ("policy", b.policy),
    ]
    .iter()
    .enumerate()
    {
        if d[2 + i * 32..34 + i * 32] != k.0 {
            return Err(Error::config(format!("Vault {name} mismatch")));
        }
    }
    if d[1] != b.bump {
        return Err(Error::config("Vault bump mismatch"));
    }
    if d[299..331] != b.authority.0 {
        return Err(Error::config("Vault authority mismatch"));
    }
    let hex = |offset| {
        d[offset..offset + 32]
            .iter()
            .map(|c| format!("{c:02x}"))
            .collect::<String>()
    };
    let u = |offset| u64::from_le_bytes(d[offset..offset + 8].try_into().unwrap()).to_string();
    Ok(State {
        binding: b,
        abi: 2,
        source_bundle: hex(162),
        policy_artifact: hex(194),
        vault_id: hex(226),
        daily_limit: u(258),
        action_limit: u(331),
        spent: u(266),
        spent_day: u(274),
        nonce: u(282),
        revision: u(290),
        instance_slot: u(339),
        approved: d[298] == 1,
        balance: "0".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::{Config, Deployment},
        crypto::LocalSigner,
        policy::ExecutionBinding,
        rpc::Rpc,
        transaction::Signed,
    };
    use std::sync::Arc;

    struct Offline;
    impl Rpc for Offline {
        fn call(&self, _: &str, _: Value) -> Result<Value> {
            panic!("instruction composition is offline")
        }
    }
    struct SimulationRpc(Value);
    impl Rpc for SimulationRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            assert_eq!(method, "simulateTransaction");
            assert_eq!(params[1]["encoding"], "base64");
            assert_eq!(params[1]["sigVerify"], false);
            assert_eq!(params[1]["replaceRecentBlockhash"], false);
            assert_eq!(params[1]["commitment"], "finalized");
            let raw = base64::engine::general_purpose::STANDARD
                .decode(params[0].as_str().unwrap())
                .unwrap();
            Signed::parse_partial(&raw).unwrap();
            Ok(self.0.clone())
        }
    }
    fn signer(n: u8) -> LocalSigner {
        LocalSigner::from_secret(
            &ed25519_dalek::SigningKey::from_bytes(&[n; 32]).to_keypair_bytes(),
        )
        .unwrap()
    }
    fn fixture() -> (NativeClient, Policy, State) {
        let owner = signer(1).public_key();
        let executor = signer(2).public_key();
        let authority = signer(3).public_key();
        let policy =
            Policy::generate("solana:testnet", "Spend up to 5 test tokens per day").unwrap();
        let binding = Binding {
            owner,
            executor,
            authority,
            mint: Key([4; 32]),
            vault: Key([5; 32]),
            token_account: Key([6; 32]),
            policy: Key([7; 32]),
            policy_data: Key([8; 32]),
            custody: Key([9; 32]),
            bump: 254,
        };
        let client = NativeClient::new(
            Config {
                network: policy.network.clone(),
                mint: Some(binding.mint),
                executor: Some(executor),
                authority: Some(authority),
                deployment: Some(Deployment {
                    network: policy.network.clone(),
                    source_bundle: policy.source_bundle.clone(),
                    policy: binding.policy,
                    policy_data: binding.policy_data,
                    custody: binding.custody,
                }),
            },
            Arc::new(Offline),
        )
        .unwrap();
        let state = State {
            binding,
            abi: 2,
            source_bundle: policy.source_bundle.clone(),
            policy_artifact: policy.policy_artifact.clone(),
            vault_id: policy.id.clone(),
            daily_limit: "5000000".into(),
            action_limit: "1000000".into(),
            spent: "0".into(),
            spent_day: "0".into(),
            nonce: "4".into(),
            revision: "7".into(),
            instance_slot: "19".into(),
            approved: true,
            balance: "5000000".into(),
        };
        (client, policy, state)
    }

    #[test]
    fn atomic_setup_and_cosigned_execution_are_packet_sized() {
        let (client, policy, state) = fixture();
        let setup = client
            .expected_instructions(
                &policy,
                &state.binding,
                "deploy",
                &Options {
                    amount: Some("0.1".into()),
                    ..Options::default()
                },
                None,
                None,
            )
            .unwrap();
        assert_eq!(setup.len(), 6);
        assert_eq!(setup[3].data[0], 0);
        assert_eq!(setup[4].data[0], 1);
        assert_eq!(setup[5].data[0], 2);
        let setup_tx = Transaction::new(state.binding.owner, Key([10; 32]), setup).unwrap();
        assert_eq!(setup_tx.signers, vec![state.binding.owner]);
        assert!(setup_tx.message.len() + 65 <= 1232);

        let commitment = ApprovalCommitment::new(
            &policy,
            &state,
            "payment-0001",
            Key([11; 32]),
            "0.5",
            100,
            &"12".repeat(32),
            None,
        )
        .unwrap();
        let execute = client
            .expected_instructions(
                &policy,
                &state.binding,
                "execute",
                &commitment.options().unwrap(),
                Some(&state.nonce),
                Some(&state.revision),
            )
            .unwrap();
        let tx = Transaction::new(state.binding.executor, Key([10; 32]), execute).unwrap();
        assert_eq!(
            tx.signers,
            vec![state.binding.executor, state.binding.authority]
        );
        assert!(tx.message.len() + 129 <= 1232);
    }

    #[test]
    fn commitment_binds_semantic_assessment_and_exact_payment() {
        let (_, policy, state) = fixture();
        let numeric = ApprovalCommitment::new(
            &policy,
            &state,
            "payment-0001",
            Key([11; 32]),
            "0.5",
            100,
            &"12".repeat(32),
            None,
        )
        .unwrap();
        let mut altered = numeric.clone();
        altered.amount_units = "500001".into();
        assert_ne!(numeric.digest().unwrap(), altered.digest().unwrap());
        let semantic = policy
            .clone()
            .with_execution_binding(ExecutionBinding {
                policy_digest: "21".repeat(32),
                requirements_digest: "22".repeat(32),
                semantic_required: true,
            })
            .unwrap();
        let mut semantic_state = state.clone();
        semantic_state.vault_id = semantic.id.clone();
        assert!(
            ApprovalCommitment::new(
                &semantic,
                &semantic_state,
                "payment-0002",
                Key([11; 32]),
                "0.5",
                100,
                &"12".repeat(32),
                None,
            )
            .is_err()
        );
        assert!(
            ApprovalCommitment::new(
                &semantic,
                &semantic_state,
                "payment-0002",
                Key([11; 32]),
                "0.5",
                100,
                &"12".repeat(32),
                Some(&"23".repeat(32)),
            )
            .is_ok()
        );
    }

    #[test]
    fn state_json_has_one_authority_and_round_trips() {
        let (_, _, state) = fixture();
        let value = serde_json::to_value(&state).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .filter(|key| *key == "authority")
                .count(),
            1
        );
        let decoded: State = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.binding.authority, state.binding.authority);
        assert_eq!(decoded.instance_slot, state.instance_slot);
        assert_eq!(decoded.action_limit, state.action_limit);
    }

    #[test]
    fn simulation_uses_the_exact_unsigned_transaction_and_fails_closed() {
        let (client, _, state) = fixture();
        let transaction = Transaction::new(
            state.binding.owner,
            Key([10; 32]),
            compute_budget("deploy").unwrap(),
        )
        .unwrap();
        let expected_bytes = transaction.partially_signed(&[]).unwrap().len();
        let simulator = NativeClient::new(
            client.config.clone(),
            Arc::new(SimulationRpc(json!({
                "context":{"slot":44},
                "value":{"err":null,"unitsConsumed":1234}
            }))),
        )
        .unwrap();
        let simulation = simulator.simulate(&transaction).unwrap();
        assert_eq!(simulation.context_slot, 44);
        assert_eq!(simulation.units_consumed, 1234);
        assert_eq!(simulation.transaction_bytes, expected_bytes);

        let rejected = NativeClient::new(
            client.config,
            Arc::new(SimulationRpc(json!({
                "context":{"slot":44},
                "value":{"err":{"InstructionError":[2,"Custom"]},"unitsConsumed":1234}
            }))),
        )
        .unwrap();
        assert!(rejected.simulate(&transaction).is_err());
    }
}
