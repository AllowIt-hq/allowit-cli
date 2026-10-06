use crate::{
    client::{ATA_PROGRAM, Binding, NativeClient, TOKEN_PROGRAM, associated_token_address, hex32},
    crypto::Key,
    error::{Error, Result},
    policy::{MAX_DAILY_UNITS, Policy, decimal, units},
    release, rpc,
    transaction::{Instruction, Meta, Transaction},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Key>,
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
    pub spent: String,
    pub spent_day: String,
    pub nonce: String,
    pub revision: String,
    pub approved: bool,
    pub balance: String,
}
pub struct Prepared {
    pub transaction: Transaction,
    pub nonce: Option<String>,
    pub revision: Option<String>,
    pub last_valid_block_height: u64,
    pub blockhash: Key,
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
        let s = decode_state(&info.data, b)?;
        if s.vault_id != policy.id
            || s.source_bundle != policy.source_bundle
            || s.policy_artifact != policy.policy_artifact
            || number(&s.daily_limit)? > MAX_DAILY_UNITS
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
        let recovery = matches!(method, "revoke" | "withdraw");
        let b = self.binding(policy, owner, recovery)?;
        let s = self.state(policy, owner, recovery, None)?;
        let amount = options.amount.as_deref().map(units).transpose()?;
        if matches!(method, "fund" | "execute" | "withdraw" | "tune") && amount.is_none() {
            return Err(Error::config("Specify the amount"));
        }
        if amount == Some(0) && method != "tune" {
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
                }
                "tune" if amount.unwrap() > MAX_DAILY_UNITS => {
                    return Err(Error::denied("Daily limit exceeds compiled ceiling"));
                }
                "tune" | "revoke" | "withdraw" => (),
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
        Ok(Prepared {
            transaction,
            nonce,
            revision,
            last_valid_block_height,
            blockhash,
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
        Ok(match method {
            "deploy" => {
                let mut fields = hex32(&policy.id)?.to_vec();
                fields.extend(hex32(&release().source_bundle)?);
                fields.extend(hex32(&release().artifacts[0].sha256)?);
                fields.extend(units(&policy.daily_limit)?.to_le_bytes());
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
            _ => return Err(Error::config("Unsupported persisted operation")),
        })
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
            json!({"version":1,"policy":policy,"context":{"policyId":policy.id,"owner":owner,"network":policy.network,"mint":b.mint,"executor":b.executor,"deployment":self.config.deployment}}),
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
            "---\nname: allowit-policy-{}\ndescription: Execute transfers governed by this AllowIt native Solana policy.\n---\n\nPolicy {}; {}; mint {}.\nOwner {}; executor {}; vault {}; custody {}.\nEnforced: standing approval and up to {} test tokens per UTC day.\nTask: {}. Purpose and recipient restrictions are not enforced by this native artifact.\n\nImport the issued executor.json with `allowit policy import executor.json` on the executor device. Configure only the designated ALLOWIT_EXECUTOR_KEYPAIR there; never provide the owner secret key. Run `allowit policy status` before acting. For each new operation, choose one ALLOWIT_REQUEST_ID and run `allowit policy execute RECIPIENT_TOKEN_ACCOUNT AMOUNT`. Keep that ID and exact intent for retries. Exit 6 means replay of the earlier receipt, not another payment. The configured executor signs; this skill contains no keys. After an uncertain result, recover the saved operation with `allowit policy status`; never submit a replacement. A settled transfer does not prove delivery of a purchased service.",
            &policy.id[..16],
            policy.id,
            policy.network,
            b.mint,
            b.owner,
            b.executor,
            b.vault,
            b.custody,
            decimal(number(&state.daily_limit)?),
            serde_json::to_string(&policy.prompt).unwrap()
        );
        if policy.pay_discovery {
            text.push_str("\n\nFor paid APIs, discover providers through PaySH: https://pay.sh/docs/using-pay/skills. Payment execution through PaySH is unavailable in this profile. Do not pay using another wallet or Pay payment tools as a fallback. Report unsupported payment execution.");
        }
        text.push('\n');
        Ok(text)
    }
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
    if d.len() != 320 || d[0] != 1 || d[298] > 1 || d[299..].iter().any(|n| *n != 0) {
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
    let hex = |offset| {
        d[offset..offset + 32]
            .iter()
            .map(|c| format!("{c:02x}"))
            .collect::<String>()
    };
    let u = |offset| u64::from_le_bytes(d[offset..offset + 8].try_into().unwrap()).to_string();
    Ok(State {
        binding: b,
        abi: 1,
        source_bundle: hex(162),
        policy_artifact: hex(194),
        vault_id: hex(226),
        daily_limit: u(258),
        spent: u(266),
        spent_day: u(274),
        nonce: u(282),
        revision: u(290),
        approved: d[298] == 1,
        balance: "0".into(),
    })
}
