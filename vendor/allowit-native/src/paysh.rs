//! Sponsored native payment transport. Provider HTTP and semantic authority
//! remain in the trusted host; this client only signs the installed profile.
use crate::{
    crypto::{Key, LocalSigner, verify},
    error::{Error, Result},
    rpc::{Account, Rpc, account},
    transaction::{Instruction, Meta, Transaction},
};
pub use allowit_paysh_interface as interface;
use base64::{Engine, engine::general_purpose::STANDARD};
use borsh::BorshDeserialize;
use interface::{Action, BUDGET_SEED, Budget, Policy, RECEIPT_SEED, Receipt, Request};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SYSTEM: &str = "11111111111111111111111111111111";
const INSTRUCTIONS: &str = "Sysvar1nstructions1111111111111111111111111";
const ED25519: &str = "Ed25519SigVerify111111111111111111111111111";
const LOOKUP: &str = "AddressLookupTab1e1111111111111111111111111";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Deployment {
    pub program: Key,
    pub genesis: Key,
    pub module_digest: [u8; 32],
    pub program_artifact: [u8; 32],
    pub upgrade_authority: Option<Key>,
    pub pool_program: Key,
    pub pool_program_artifact: [u8; 32],
    pub pool_upgrade_authority: Option<Key>,
    pub lookup_table: Option<Key>,
    pub compute_limit: u32,
}

/// Public signed proof, suitable for a durable journal. Contains no keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedExecution {
    pub signature: String,
    pub signed_bytes: String,
    pub request_bytes: String,
    pub request_hash: [u8; 32],
    pub receipt: Key,
    pub policy: Key,
    pub payer: Key,
    pub expires_slot: u64,
    pub expires_timestamp: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSetup {
    pub owner: Key,
    pub policy: Key,
    pub sol_vault: Key,
    pub config_bytes: String,
    pub allocation_lamports: u64,
    pub message: String,
    pub unsigned_transaction: String,
    #[serde(default)]
    pub blockhash_context_slot: Option<u64>,
    #[serde(default)]
    pub last_valid_block_height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settlement {
    pub signature: String,
    pub finalized_slot: u64,
    pub invocation_index: u16,
}
#[derive(Clone, Debug, PartialEq)]
pub enum ExecutionStatus {
    Pending,
    Finalized(Settlement),
    /// Both expiry clocks passed at finalized commitment and nonce is absent.
    ProvenAbsent,
    /// Nonce receipt proves execution, but finalized transaction metadata is unavailable.
    ConsumedUnlocated,
}

pub struct PayShClient {
    pub deployment: Deployment,
    rpc: Arc<dyn Rpc>,
}
impl PayShClient {
    pub fn new(deployment: Deployment, rpc: Arc<dyn Rpc>) -> Result<Self> {
        if !(50_000..=1_400_000).contains(&deployment.compute_limit) {
            return Err(Error::config("Invalid sponsored compute limit"));
        }
        Ok(Self { deployment, rpc })
    }

    /// Pin the current deployed bytes and retained upgrade authority. An
    /// upgrade requires a newly verified release; it cannot silently change it.
    pub fn verify_deployment(&self) -> Result<()> {
        let actual = self.rpc.call("getGenesisHash", json!([]))?;
        if actual.as_str() != Some(&self.deployment.genesis.to_string()) {
            return Err(Error::config(
                "PaySH RPC network differs from the approved deployment",
            ));
        }
        self.verify_program(
            self.deployment.program,
            self.deployment.program_artifact,
            self.deployment.upgrade_authority,
        )?;
        self.verify_program(
            self.deployment.pool_program,
            self.deployment.pool_program_artifact,
            self.deployment.pool_upgrade_authority,
        )
    }

    fn verify_program(
        &self,
        program: Key,
        artifact: [u8; 32],
        expected_authority: Option<Key>,
    ) -> Result<()> {
        let loader = Key::parse("BPFLoaderUpgradeab1e11111111111111111111111")?;
        let p = account(&*self.rpc, program, None)?
            .ok_or_else(|| Error::config("PaySH program is not deployed"))?;
        if !p.executable
            || p.owner != loader
            || p.data.len() != 36
            || p.data[..4] != 2u32.to_le_bytes()
        {
            return Err(Error::config("Invalid PaySH program account"));
        }
        let linked = Key(p.data[4..36].try_into().unwrap());
        let canonical = Key::find_program_address(&[&program.0], loader)?.0;
        if linked != canonical {
            return Err(Error::config("Invalid PaySH program data binding"));
        }
        let data = account(&*self.rpc, linked, None)?
            .ok_or_else(|| Error::config("Missing PaySH program data"))?;
        if data.owner != loader
            || data.executable
            || data.data.len() < 45
            || data.data[..4] != 3u32.to_le_bytes()
        {
            return Err(Error::config("Invalid PaySH program data"));
        }
        let authority = match data.data[12] {
            0 => None,
            1 => Some(Key(data.data[13..45].try_into().unwrap())),
            _ => return Err(Error::config("Invalid program upgrade authority")),
        };
        if authority != expected_authority
            || <[u8; 32]>::from(Sha256::digest(&data.data[45..])) != artifact
        {
            return Err(Error::config(
                "Approved executable or upgrade authority changed",
            ));
        }
        Ok(())
    }

    pub fn clock(&self) -> Result<(u64, i64)> {
        let a = account(
            &*self.rpc,
            Key::parse("SysvarC1ock11111111111111111111111111111111")?,
            None,
        )?
        .ok_or_else(|| Error::config("Missing native Clock"))?;
        if a.owner != Key::parse("Sysvar1111111111111111111111111111111111111")?
            || a.data.len() != 40
        {
            return Err(Error::config("Invalid native Clock"));
        }
        Ok((
            u64::from_le_bytes(a.data[..8].try_into().unwrap()),
            i64::from_le_bytes(a.data[32..40].try_into().unwrap()),
        ))
    }

    /// Public, verified address snapshot for owner-side v0 intent decoding.
    /// Addresses contain no signing material and cannot confer authority.
    pub fn lookup_snapshot(&self) -> Result<Option<LookupTable>> {
        self.verify_deployment()?;
        let (slot, _) = self.clock()?;
        self.lookup(slot)
    }

    pub fn token_balance(&self, address: Key) -> Result<u64> {
        let a = account(&*self.rpc, address, None)?
            .ok_or_else(|| Error::config("Missing policy token account"))?;
        if a.owner != Key::parse(TOKEN)? || a.executable || a.data.len() != 165 || a.data[108] != 1
        {
            return Err(Error::config(
                "Expected an initialized classic SPL token account",
            ));
        }
        Ok(u64::from_le_bytes(a.data[64..72].try_into().unwrap()))
    }

    /// Use Orca's exact integer quote implementation. Only fixed-fee, classic
    /// SPL SOL/USDC pools and three authenticated fixed tick arrays are admitted.
    pub fn quote_swap_for_usdc(
        &self,
        policy: Key,
        needed: u64,
        max_lamports: u64,
        slippage_bps: u16,
    ) -> Result<Action> {
        use orca_whirlpools_core::{TickArrayFacade, WhirlpoolFacade, WhirlpoolRewardInfoFacade};
        if needed == 0 || slippage_bps > 100 {
            return Err(Error::config(
                "Swap needs positive output and slippage at most one percent",
            ));
        }
        self.verify_deployment()?;
        let p = self.policy(policy)?;
        let c = &p.config;
        let pool = &c.pool;
        let a = account(&*self.rpc, Key(pool.state), None)?
            .ok_or_else(|| Error::config("Missing approved Whirlpool"))?;
        let d = &a.data;
        if a.owner != Key(pool.program)
            || a.executable
            || d.len() != 653
            || d[..8] != Sha256::digest(b"account:Whirlpool")[..8]
            || d[101..133] != Key::parse("So11111111111111111111111111111111111111112")?.0
            || d[181..213] != c.usdc_mint
            || d[133..165] != pool.wsol
            || d[213..245] != pool.usdc
        {
            return Err(Error::config(
                "Whirlpool accounts or token order differ from the approved profile",
            ));
        }
        let u16_at = |i| u16::from_le_bytes(d[i..i + 2].try_into().unwrap());
        let u128_at = |i| u128::from_le_bytes(d[i..i + 16].try_into().unwrap());
        let spacing = u16_at(41);
        let fee = u16_at(45);
        if spacing == 0
            || d[43..45] != spacing.to_le_bytes()
            || u64::from(fee)
                > c.max_pool_fee_bps
                    .checked_mul(100)
                    .ok_or_else(|| Error::config("Invalid fee cap"))?
        {
            return Err(Error::denied(
                "Adaptive or excessive pool fees are not approved",
            ));
        }
        let spacing_seed = spacing.to_le_bytes();
        let expected = Key::find_program_address(
            &[
                b"whirlpool",
                &d[8..40],
                &d[101..133],
                &d[181..213],
                &spacing_seed,
            ],
            Key(pool.program),
        )?
        .0;
        if expected.0 != pool.state
            || Key::find_program_address(&[b"oracle", &pool.state], Key(pool.program))?
                .0
                .0
                != pool.oracle
        {
            return Err(Error::config("Invalid canonical pool or oracle address"));
        }
        let whirlpool = WhirlpoolFacade {
            tick_spacing: spacing,
            fee_rate: fee,
            protocol_fee_rate: u16_at(47),
            liquidity: u128_at(49),
            sqrt_price: u128_at(65),
            tick_current_index: i32::from_le_bytes(d[81..85].try_into().unwrap()),
            fee_growth_global_a: u128_at(165),
            fee_growth_global_b: u128_at(245),
            reward_last_updated_timestamp: u64::from_le_bytes(d[261..269].try_into().unwrap()),
            reward_infos: std::array::from_fn(|i| WhirlpoolRewardInfoFacade {
                emissions_per_second_x64: u128_at(269 + i * 128 + 96),
                growth_global_x64: u128_at(269 + i * 128 + 112),
            }),
        };
        let span = i32::from(spacing) * 88;
        let start = whirlpool.tick_current_index.div_euclid(span) * span;
        let mut keys = [[0; 32]; 3];
        let mut arrays = Vec::new();
        for (i, key) in keys.iter_mut().enumerate() {
            let tick = start
                .checked_sub((i as i32) * span)
                .ok_or_else(|| Error::config("Tick overflow"))?;
            let text = tick.to_string();
            let address = Key::find_program_address(
                &[b"tick_array", &pool.state, text.as_bytes()],
                Key(pool.program),
            )?
            .0;
            *key = address.0;
            let a = account(&*self.rpc, address, None)?
                .ok_or_else(|| Error::config("Required pool tick array is unavailable"))?;
            arrays.push(decode_tick_array(&a, Key(pool.program), pool.state, tick)?);
        }
        let arrays: [TickArrayFacade; 3] = arrays
            .try_into()
            .map_err(|_| Error::config("Missing tick arrays"))?;
        let sqrt_price_limit = admitted_swap_boundary(whirlpool, &arrays)?;
        let quote = |amount| bounded_whirlpool_quote(amount, slippage_bps, whirlpool, arrays);
        let max = max_lamports
            .min(c.max_swap_lamports_per_call)
            .min(
                c.max_total_swap_lamports
                    .saturating_sub(p.total_swap_lamports),
            )
            .min(
                c.allocation_lamports
                    .saturating_sub(p.total_sol_debits)
                    .saturating_sub(c.service_fee_lamports),
            );
        let (low, q) = minimum_swap_input(max, needed, quote)?;
        if q.token_in > low
            || u128::from(q.token_min_out) * 1_000_000_000
                < u128::from(low) * u128::from(c.min_usdc_per_sol)
        {
            return Err(Error::denied(
                "Quoted swap is below the approved price floor",
            ));
        }
        Ok(Action::SwapSolToUsdc {
            amount_in_lamports: low,
            min_out_usdc: q.token_min_out,
            sqrt_price_limit,
            tick_arrays: keys,
        })
    }

    pub fn policy(&self, address: Key) -> Result<Policy> {
        let a = account(&*self.rpc, address, None)?
            .ok_or_else(|| Error::config("PaySH policy is not initialized"))?;
        if a.owner != self.deployment.program
            || a.executable
            || a.data.len() != interface::POLICY_BYTES
        {
            return Err(Error::config("Invalid PaySH policy account"));
        }
        let mut bytes = a.data.as_slice();
        let p = Policy::deserialize(&mut bytes)
            .map_err(|_| Error::config("Invalid PaySH policy encoding"))?;
        let expected = Key::find_program_address(
            &[interface::POLICY_SEED, &p.owner, &p.config.instance_id],
            self.deployment.program,
        )?;
        if !matches!(p.version, 1 | 2)
            || p.bump != expected.1
            || expected.0 != address
            || p.config.network != self.deployment.genesis.0
            || p.config.module_digest != self.deployment.module_digest
            || p.config.pool.program != self.deployment.pool_program.0
        {
            return Err(Error::config(
                "PaySH policy differs from its approved binding",
            ));
        }
        Ok(p)
    }

    /// The owner reviews these fixed installation terms before signing. The
    /// host must persist this preparation and signed bytes before broadcast.
    pub fn prepare_setup(
        &self,
        owner: Key,
        config: &interface::Config,
        allocation_lamports: u64,
    ) -> Result<PreparedSetup> {
        self.verify_deployment()?;
        if !owner.on_curve()
            || config.network != self.deployment.genesis.0
            || config.module_digest != self.deployment.module_digest
            || config.pool.program != self.deployment.pool_program.0
            || allocation_lamports == 0
            || allocation_lamports > config.allocation_lamports
            || config.period_seconds == 0
        {
            return Err(Error::config("Invalid owner-approved PaySH installation"));
        }
        let program = self.deployment.program;
        let policy = Key::find_program_address(
            &[interface::POLICY_SEED, &owner.0, &config.instance_id],
            program,
        )?
        .0;
        let sol_vault = Key::find_program_address(&[interface::SOL_SEED, &policy.0], program)?.0;
        let instructions = setup_instructions(
            owner,
            config,
            allocation_lamports,
            program,
            policy,
            sol_vault,
            self.deployment.compute_limit,
        )?;
        let (slot, _) = self.clock()?;
        let lookup = self.lookup(slot)?;
        let block = self
            .rpc
            .call("getLatestBlockhash", json!([{"commitment":"finalized"}]))?;
        let blockhash = Key::parse(
            block["value"]["blockhash"]
                .as_str()
                .ok_or_else(|| Error::config("Invalid blockhash"))?,
        )?;
        let message = transaction_message(owner, blockhash, &instructions, lookup.as_ref())?;
        let mut unsigned = vec![1];
        unsigned.extend([0; 64]);
        unsigned.extend(&message);
        Ok(PreparedSetup {
            owner,
            policy,
            sol_vault,
            config_bytes: STANDARD.encode(
                borsh::to_vec(config).map_err(|_| Error::config("Invalid installation config"))?,
            ),
            allocation_lamports,
            message: STANDARD.encode(message),
            unsigned_transaction: STANDARD.encode(unsigned),
            blockhash_context_slot: Some(
                block["context"]["slot"]
                    .as_u64()
                    .ok_or_else(|| Error::config("Missing blockhash context"))?,
            ),
            last_valid_block_height: Some(
                block["value"]["lastValidBlockHeight"]
                    .as_u64()
                    .ok_or_else(|| Error::config("Missing blockhash expiry height"))?,
            ),
        })
    }

    pub fn verify_setup_signature(prepared: &PreparedSetup, signed_bytes: &str) -> Result<String> {
        let raw = STANDARD
            .decode(signed_bytes)
            .map_err(|_| Error::config("Invalid signed owner setup"))?;
        let expected = STANDARD
            .decode(&prepared.message)
            .map_err(|_| Error::config("Invalid setup preparation"))?;
        if raw.len() < 65 || raw.len() > 1232 || raw[0] != 1 || raw[65..] != expected {
            return Err(Error::config(
                "Owner setup differs from the reviewed exact installation",
            ));
        }
        verify(prepared.owner, &raw[65..], &raw[1..65])?;
        Ok(bs58::encode(&raw[1..65]).into_string())
    }

    pub fn broadcast_setup(&self, prepared: &PreparedSetup, signed_bytes: &str) -> Result<String> {
        let signature = Self::verify_setup_signature(prepared, signed_bytes)?;
        self.check_setup_packet(prepared, signed_bytes, None)
            .map_err(|_| {
                Error::uncertain("Cannot revalidate saved installation; retain its signed proof")
            })?;
        let result=self.rpc.call("sendTransaction",json!([signed_bytes,{"encoding":"base64","skipPreflight":false,"preflightCommitment":"finalized","maxRetries":0}])).map_err(|_| Error::uncertain("Setup broadcast RPC failed after receiving signed bytes; retain its proof"))?;
        if result.as_str() != Some(&signature) {
            return Err(Error::uncertain(
                "Setup submission is unresolved; preserve its original signed bytes",
            ));
        }
        Ok(signature)
    }

    pub fn finalized_setup(&self, prepared: &PreparedSetup, signed_bytes: &str) -> Result<bool> {
        let signature = Self::verify_setup_signature(prepared, signed_bytes)?;
        let tx=self.rpc.call("getTransaction",json!([signature,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}]))?;
        if tx.is_null() {
            return Ok(false);
        }
        if tx["transaction"][1] != "base64" || tx["transaction"][0] != signed_bytes {
            return Err(Error::config(
                "Finalized setup differs from its saved signed bytes",
            ));
        }
        if tx["meta"].get("err").is_none() {
            return Err(Error::config("Missing finalized setup outcome"));
        }
        if !tx["meta"]["err"].is_null() {
            return Ok(false);
        }
        self.check_setup_packet(prepared, signed_bytes, Some(&tx["meta"]))?;
        let policy = self.policy(prepared.policy)?;
        let expected = STANDARD
            .decode(&prepared.config_bytes)
            .map_err(|_| Error::config("Invalid setup config"))?;
        if policy.owner != prepared.owner.0
            || borsh::to_vec(&policy.config).map_err(|_| Error::config("Invalid setup state"))?
                != expected
        {
            return Err(Error::config(
                "Installed policy differs from the owner's reviewed terms",
            ));
        }
        // Exact transaction verification proves its bounded funding instruction;
        // current balance can legitimately change after subsequent executions.
        Ok(true)
    }

    pub fn draft(
        &self,
        policy: Key,
        action: Action,
        operation_id: [u8; 32],
        nonce: [u8; 32],
        challenge_hash: [u8; 32],
        evidence_hash: [u8; 32],
    ) -> Result<Request> {
        self.verify_deployment()?;
        let p = self.policy(policy)?;
        let (slot, timestamp) = self.clock()?;
        if p.paused || timestamp >= p.config.policy_expires_timestamp {
            return Err(Error::denied("PaySH policy is paused or expired"));
        }
        let seconds = p.config.max_age_seconds.min(60);
        Ok(Request {
            network: p.config.network,
            program: self.deployment.program.0,
            policy: policy.0,
            owner: p.owner,
            module_digest: p.config.module_digest,
            operation_id,
            nonce,
            challenge_hash,
            evidence_hash,
            signing_slot: slot,
            signing_timestamp: timestamp,
            expires_slot: slot
                .checked_add(p.config.max_age_slots)
                .ok_or_else(|| Error::config("Clock overflow"))?,
            expires_timestamp: timestamp
                .checked_add(
                    seconds
                        .try_into()
                        .map_err(|_| Error::config("Clock overflow"))?,
                )
                .ok_or_else(|| Error::config("Clock overflow"))?
                .min(p.config.policy_expires_timestamp),
            service_fee_lamports: p.config.service_fee_lamports,
            action,
        })
    }

    pub fn prepare_execute(
        &self,
        request: &Request,
        evaluator: &LocalSigner,
        sponsor: &LocalSigner,
    ) -> Result<PreparedExecution> {
        self.verify_deployment()?;
        let policy = Key(request.policy);
        let p = self.policy(policy)?;
        if evaluator.public_key().0 != p.config.evaluator
            || request.network != p.config.network
            || request.program != self.deployment.program.0
            || request.owner != p.owner
            || request.module_digest != p.config.module_digest
            || request.service_fee_lamports != p.config.service_fee_lamports
            || p.config.owner_only && sponsor.public_key().0 != p.owner
        {
            return Err(Error::denied(
                "Request is outside the installed PaySH signing scope",
            ));
        }
        let (slot, time) = self.clock()?;
        if p.paused
            || request.signing_timestamp < 0
            || request.signing_slot > slot
            || time < request.signing_timestamp
            || slot > request.expires_slot
            || time > request.expires_timestamp
            || time > p.config.policy_expires_timestamp
            || request.expires_slot < request.signing_slot
            || request.expires_slot - request.signing_slot > p.config.max_age_slots
            || request.expires_timestamp < request.signing_timestamp
            || request.expires_timestamp - request.signing_timestamp
                > p.config.max_age_seconds as i64
        {
            return Err(Error::denied("Request is stale or the policy is inactive"));
        }
        let period = (request.signing_timestamp as u64)
            .checked_div(p.config.period_seconds)
            .ok_or_else(|| Error::config("Invalid budget period"))?;
        let receipt = Key::find_program_address(
            &[RECEIPT_SEED, &policy.0, &request.nonce],
            self.deployment.program,
        )?
        .0;
        let budget = Key::find_program_address(
            &[BUDGET_SEED, &policy.0, &period.to_le_bytes()],
            self.deployment.program,
        )?
        .0;
        if account(&*self.rpc, receipt, None)?.is_some_and(|a| !unallocated(&a)) {
            return Err(Error::denied("Request nonce was already consumed"));
        }
        let spent = if let Some(a) = account(&*self.rpc, budget, None)? {
            if a.owner != self.deployment.program || a.data.len() != interface::BUDGET_BYTES {
                return Err(Error::config("Invalid budget account"));
            }
            let b = Budget::try_from_slice(&a.data)
                .map_err(|_| Error::config("Invalid budget encoding"))?;
            if b.period != period {
                return Err(Error::config("Invalid budget binding"));
            }
            b
        } else {
            Budget {
                period,
                usdc: 0,
                swap_lamports: 0,
                fee_lamports: 0,
                sol_debits: 0,
            }
        };
        bounded_sum(
            spent.fee_lamports,
            request.service_fee_lamports,
            p.config.max_fee_lamports_per_period,
        )?;
        let action_sol = match request.action {
            Action::PayUsdc { .. } => 0,
            Action::SwapSolToUsdc {
                amount_in_lamports, ..
            } => amount_in_lamports,
        };
        let total_debit = action_sol
            .checked_add(request.service_fee_lamports)
            .ok_or_else(|| Error::denied("SOL debit overflow"))?;
        bounded_sum(
            p.total_sol_debits,
            total_debit,
            p.config.allocation_lamports,
        )?;
        bounded_sum(
            spent.sol_debits,
            total_debit,
            p.config.max_sol_debits_per_period,
        )?;
        match request.action {
            Action::PayUsdc { amount } => {
                bounded_sum(spent.usdc, amount, p.config.max_usdc_per_period)?
            }
            Action::SwapSolToUsdc {
                amount_in_lamports,
                min_out_usdc,
                ..
            } => {
                if amount_in_lamports == 0
                    || amount_in_lamports > p.config.max_swap_lamports_per_call
                    || u128::from(min_out_usdc) * 1_000_000_000
                        < u128::from(amount_in_lamports) * u128::from(p.config.min_usdc_per_sol)
                {
                    return Err(Error::denied(
                        "Swap violates the approved amount or price floor",
                    ));
                }
                bounded_sum(
                    spent.swap_lamports,
                    amount_in_lamports,
                    p.config.max_swap_lamports_per_period,
                )?;
                bounded_sum(
                    p.total_swap_lamports,
                    amount_in_lamports,
                    p.config.max_total_swap_lamports,
                )?;
            }
        }
        let message = request.signed_message();
        let attestation =
            ed25519_instruction(evaluator.public_key(), &message, evaluator.sign(&message))?;
        let accounts = execute_accounts(
            &p,
            self.deployment.program,
            policy,
            sponsor.public_key(),
            receipt,
            budget,
            &request.action,
        )?;
        let execute = Instruction {
            program: self.deployment.program,
            accounts,
            data: borsh::to_vec(&interface::Instruction::Execute(request.clone()))
                .map_err(|_| Error::config("Invalid PaySH request"))?,
        };
        let mut compute_data = vec![2];
        compute_data.extend(self.deployment.compute_limit.to_le_bytes());
        let compute = Instruction {
            program: Key::parse("ComputeBudget111111111111111111111111111111")?,
            accounts: vec![],
            data: compute_data,
        };
        let block = self
            .rpc
            .call("getLatestBlockhash", json!([{"commitment":"finalized"}]))?;
        let blockhash = Key::parse(
            block["value"]["blockhash"]
                .as_str()
                .ok_or_else(|| Error::config("Invalid blockhash"))?,
        )?;
        let instructions = vec![compute, attestation, execute];
        let lookup = self.lookup(slot)?;
        let tx_message = transaction_message(
            sponsor.public_key(),
            blockhash,
            &instructions,
            lookup.as_ref(),
        )?;
        let signature = sponsor.sign(&tx_message);
        let mut raw = vec![1];
        raw.extend(signature);
        raw.extend(tx_message);
        if raw.len() > 1232 {
            return Err(Error::config(
                "PaySH transaction exceeds packet size; configure an active lookup table",
            ));
        }
        let encoded = STANDARD.encode(&raw);
        Ok(PreparedExecution {
            signature: bs58::encode(signature).into_string(),
            signed_bytes: encoded,
            request_bytes: STANDARD
                .encode(borsh::to_vec(request).map_err(|_| Error::config("Invalid request"))?),
            request_hash: Sha256::digest(message).into(),
            receipt,
            policy,
            payer: sponsor.public_key(),
            expires_slot: request.expires_slot,
            expires_timestamp: request.expires_timestamp,
        })
    }

    fn check_execution_packet(
        &self,
        prepared: &PreparedExecution,
        historical: Option<&serde_json::Value>,
    ) -> Result<()> {
        let raw = STANDARD
            .decode(&prepared.signed_bytes)
            .map_err(|_| Error::config("Invalid saved packet"))?;
        let decoded = packet_message(&raw[65..])?;
        let request: Request = borsh::from_slice(
            &STANDARD
                .decode(&prepared.request_bytes)
                .map_err(|_| Error::config("Invalid saved request"))?,
        )
        .map_err(|_| Error::config("Invalid saved request"))?;
        if historical.is_none() {
            self.verify_deployment()?;
        }
        let policy = self.policy(Key(request.policy))?;
        if request.program != self.deployment.program.0
            || request.network != self.deployment.genesis.0
            || request.owner != policy.owner
            || request.module_digest != policy.config.module_digest
            || request.service_fee_lamports != policy.config.service_fee_lamports
            || request.signing_timestamp < 0
        {
            return Err(Error::config(
                "Saved request differs from its installed scope",
            ));
        }
        let approval = &decoded.instructions[1].1;
        if approval.len() < 112 || approval[16..48] != policy.config.evaluator {
            return Err(Error::config("Saved approval uses a different evaluator"));
        }
        let signature: [u8; 64] = approval[48..112].try_into().unwrap();
        let message = request.signed_message();
        verify(Key(policy.config.evaluator), &message, &signature)?;
        let attestation = ed25519_instruction(Key(policy.config.evaluator), &message, signature)?;
        let period = (request.signing_timestamp as u64)
            .checked_div(policy.config.period_seconds)
            .ok_or_else(|| Error::config("Invalid saved budget period"))?;
        let budget = Key::find_program_address(
            &[BUDGET_SEED, &request.policy, &period.to_le_bytes()],
            self.deployment.program,
        )?
        .0;
        let receipt = Key::find_program_address(
            &[RECEIPT_SEED, &request.policy, &request.nonce],
            self.deployment.program,
        )?
        .0;
        if receipt != prepared.receipt {
            return Err(Error::config("Saved receipt PDA changed"));
        }
        let execute = Instruction {
            program: self.deployment.program,
            accounts: execute_accounts(
                &policy,
                self.deployment.program,
                Key(request.policy),
                prepared.payer,
                receipt,
                budget,
                &request.action,
            )?,
            data: borsh::to_vec(&interface::Instruction::Execute(request))
                .map_err(|_| Error::config("Invalid saved request"))?,
        };
        let mut limit = vec![2];
        limit.extend(self.deployment.compute_limit.to_le_bytes());
        let compute = Instruction {
            program: Key::parse("ComputeBudget111111111111111111111111111111")?,
            accounts: vec![],
            data: limit,
        };
        let lookup = self.proof_lookup(&decoded, historical)?;
        let expected = transaction_message(
            prepared.payer,
            decoded.blockhash,
            &[compute, attestation, execute],
            lookup.as_ref(),
        )?;
        if raw[65..] != expected {
            return Err(Error::config(
                "Saved transaction accounts or instructions differ from the exact request",
            ));
        }
        Ok(())
    }

    fn check_setup_packet(
        &self,
        prepared: &PreparedSetup,
        signed_bytes: &str,
        historical: Option<&serde_json::Value>,
    ) -> Result<()> {
        if historical.is_none() {
            self.verify_deployment()?;
        }
        let raw = STANDARD
            .decode(signed_bytes)
            .map_err(|_| Error::config("Invalid setup packet"))?;
        let decoded = packet_message(&raw[65..])?;
        let config: interface::Config = borsh::from_slice(
            &STANDARD
                .decode(&prepared.config_bytes)
                .map_err(|_| Error::config("Invalid setup config"))?,
        )
        .map_err(|_| Error::config("Invalid setup config"))?;
        let policy = Key::find_program_address(
            &[
                interface::POLICY_SEED,
                &prepared.owner.0,
                &config.instance_id,
            ],
            self.deployment.program,
        )?
        .0;
        let sol_vault =
            Key::find_program_address(&[interface::SOL_SEED, &policy.0], self.deployment.program)?
                .0;
        if prepared.policy != policy
            || prepared.sol_vault != sol_vault
            || config.network != self.deployment.genesis.0
            || config.module_digest != self.deployment.module_digest
            || config.pool.program != self.deployment.pool_program.0
            || prepared.allocation_lamports == 0
            || prepared.allocation_lamports > config.allocation_lamports
        {
            return Err(Error::config(
                "Setup metadata differs from the owner-approved installation",
            ));
        }
        let instructions = setup_instructions(
            prepared.owner,
            &config,
            prepared.allocation_lamports,
            self.deployment.program,
            policy,
            sol_vault,
            self.deployment.compute_limit,
        )?;
        let lookup = self.proof_lookup(&decoded, historical)?;
        let expected = transaction_message(
            prepared.owner,
            decoded.blockhash,
            &instructions,
            lookup.as_ref(),
        )?;
        if raw[65..] != expected {
            return Err(Error::config(
                "Setup packet changes reviewed configuration, funding or account privileges",
            ));
        }
        Ok(())
    }

    fn proof_lookup(
        &self,
        decoded: &DecodedMessage,
        historical: Option<&serde_json::Value>,
    ) -> Result<Option<LookupTable>> {
        let Some(lookup) = &decoded.lookup else {
            return Ok(None);
        };
        if Some(lookup.key) != self.deployment.lookup_table {
            return Err(Error::config("Saved packet uses a different lookup table"));
        }
        if let Some(meta) = historical {
            historical_lookup(lookup, &meta["loadedAddresses"]).map(Some)
        } else {
            let (slot, _) = self.clock()?;
            let table = self
                .lookup(slot)?
                .ok_or_else(|| Error::config("Missing configured lookup table"))?;
            let resolve = |indices: &[u8]| -> Result<Vec<String>> {
                indices
                    .iter()
                    .map(|i| {
                        table
                            .addresses
                            .get(*i as usize)
                            .map(ToString::to_string)
                            .ok_or_else(|| Error::config("Saved lookup index is absent"))
                    })
                    .collect()
            };
            // Appending unrelated entries may not alter the signed packet's
            // original choice between static and loaded accounts.
            historical_lookup(lookup, &json!({"writable":resolve(&lookup.writable)?, "readonly":resolve(&lookup.readonly)?})).map(Some)
        }
    }

    fn lookup(&self, current_slot: u64) -> Result<Option<LookupTable>> {
        let Some(key) = self.deployment.lookup_table else {
            return Ok(None);
        };
        let a =
            account(&*self.rpc, key, None)?.ok_or_else(|| Error::config("Missing lookup table"))?;
        if a.owner != Key::parse(LOOKUP)?
            || a.executable
            || a.data.len() < 56
            || (a.data.len() - 56) % 32 != 0
            || a.data[..4] != 1u32.to_le_bytes()
            || u64::from_le_bytes(a.data[4..12].try_into().unwrap()) != u64::MAX
            || u64::from_le_bytes(a.data[12..20].try_into().unwrap()) >= current_slot
        {
            return Err(Error::config(
                "Lookup table is invalid, deactivated or not yet active",
            ));
        }
        let addresses: Vec<_> = a.data[56..]
            .chunks_exact(32)
            .map(|x| Key(x.try_into().unwrap()))
            .collect();
        if addresses.len() > 256
            || addresses
                .iter()
                .enumerate()
                .any(|(i, k)| addresses[..i].contains(k))
        {
            return Err(Error::config("Invalid lookup table addresses"));
        }
        Ok(Some(LookupTable { key, addresses }))
    }

    /// Call only after the caller durably saved this exact signed packet.
    pub fn broadcast(&self, prepared: &PreparedExecution) -> Result<()> {
        verify_packet(prepared)?;
        self.check_execution_packet(prepared, None).map_err(|_| {
            Error::uncertain(
                "Cannot revalidate saved execution; retain its proof and reconcile its nonce",
            )
        })?;
        let simulation = self.rpc.call("simulateTransaction", json!([prepared.signed_bytes,{"encoding":"base64","sigVerify":true,"commitment":"finalized"}])).map_err(|_| Error::uncertain("Simulation RPC failed after receiving the saved approval; reconcile its nonce"))?;
        if simulation.get("value").is_none() || !simulation["value"]["err"].is_null() {
            return Err(Error::uncertain(
                "Native simulation rejected the saved approval. Reconcile its nonce before any replacement.",
            ));
        }
        let result = self.rpc.call("sendTransaction", json!([prepared.signed_bytes,{"encoding":"base64","skipPreflight":false,"preflightCommitment":"finalized","maxRetries":0}])).map_err(|_| Error::uncertain("Broadcast RPC failed after receiving the saved approval; reconcile its nonce"))?;
        if result.as_str() != Some(&prepared.signature) {
            return Err(Error::uncertain(
                "RPC returned a different signature; reconcile the saved packet",
            ));
        }
        Ok(())
    }
    /// Reconcile the authorization's nonce, not just the sponsor signature.
    /// Another permitted relayer may have finalized the same request first.
    pub fn settlement(&self, prepared: &PreparedExecution) -> Result<ExecutionStatus> {
        verify_packet(prepared)?;
        let request: Request = borsh::from_slice(
            &STANDARD
                .decode(&prepared.request_bytes)
                .map_err(|_| Error::config("Invalid saved request"))?,
        )
        .map_err(|_| Error::config("Invalid saved request"))?;
        let policy = self.policy(Key(request.policy))?;
        let raw = STANDARD
            .decode(&prepared.signed_bytes)
            .map_err(|_| Error::config("Invalid saved packet"))?;
        let decoded = packet_message(&raw[65..])?;
        if request.program != self.deployment.program.0
            || request.owner != policy.owner
            || request.network != self.deployment.genesis.0
            || request.module_digest != policy.config.module_digest
            || request.service_fee_lamports != policy.config.service_fee_lamports
            || decoded.instructions[1].1[16..48] != policy.config.evaluator
        {
            return Err(Error::config(
                "Saved approval differs from the installed scope",
            ));
        }
        let genesis = self.rpc.call("getGenesisHash", json!([]))?;
        if genesis.as_str() != Some(&self.deployment.genesis.to_string()) {
            return Err(Error::config("Recovery RPC network differs"));
        }
        let (slot, timestamp) = self.clock()?;
        let Some(a) =
            account(&*self.rpc, prepared.receipt, Some(slot))?.filter(|a| !unallocated(a))
        else {
            return Ok(
                if slot > request.expires_slot && timestamp > request.expires_timestamp {
                    ExecutionStatus::ProvenAbsent
                } else {
                    ExecutionStatus::Pending
                },
            );
        };
        let receipt = Receipt::try_from_slice(&a.data)
            .map_err(|_| Error::config("Invalid execution receipt"))?;
        if a.owner != self.deployment.program
            || a.executable
            || receipt.version != 1
            || receipt.request_hash != prepared.request_hash
            || receipt.operation_id != request.operation_id
            || receipt.signing_timestamp != request.signing_timestamp
        {
            return Err(Error::config(
                "Receipt does not bind the saved authorization",
            ));
        }
        let expected = borsh::to_vec(&interface::Instruction::Execute(request))
            .map_err(|_| Error::config("Invalid saved request"))?;
        // First check the original sponsor packet. If it lost a permissionless
        // race, use finalized address history to locate the successful relayer.
        let mut candidates = vec![prepared.signature.clone()];
        let mut before: Option<String> = None;
        for page in 0..=4 {
            for signature in candidates.drain(..) {
                let tx = self.rpc.call("getTransaction", json!([signature,{"encoding":"json","commitment":"finalized","maxSupportedTransactionVersion":0}]))?;
                if tx.is_null() || tx["meta"].get("err").is_none() || !tx["meta"]["err"].is_null() {
                    continue;
                }
                if let Some(settled) =
                    settlement_transaction(&tx, &signature, self.deployment.program, &expected)?
                {
                    return Ok(ExecutionStatus::Finalized(settled));
                }
            }
            if page == 4 {
                break;
            }
            let mut options = json!({"limit":100,"commitment":"finalized","minContextSlot":slot});
            if let Some(before) = &before {
                options["before"] = json!(before);
            }
            let history = self.rpc.call(
                "getSignaturesForAddress",
                json!([prepared.receipt, options]),
            )?;
            let history = history
                .as_array()
                .ok_or_else(|| Error::config("Invalid receipt address history"))?;
            if history.is_empty() {
                break;
            }
            before = history
                .last()
                .and_then(|v| v["signature"].as_str())
                .map(str::to_owned);
            for entry in history {
                if entry.get("err").is_some() && entry["err"].is_null() {
                    candidates.push(
                        entry["signature"]
                            .as_str()
                            .ok_or_else(|| Error::config("Invalid settlement signature"))?
                            .to_owned(),
                    );
                }
            }
        }
        Ok(ExecutionStatus::ConsumedUnlocated)
    }

    pub fn finalized(&self, prepared: &PreparedExecution) -> Result<bool> {
        match self.settlement(prepared)? {
            ExecutionStatus::Finalized(_) => Ok(true),
            ExecutionStatus::Pending => Ok(false),
            ExecutionStatus::ConsumedUnlocated => Err(Error::uncertain(
                "Authorization consumed; finalized transaction unavailable. Do not create another payment",
            )),
            ExecutionStatus::ProvenAbsent => Err(Error::denied(
                "Authorization expired without a finalized receipt",
            )),
        }
    }

    /// Refresh only an unsigned installation after its old blockhash has
    /// positively expired. Signed owner proofs remain separately durable.
    pub fn setup_expired(&self, prepared: &PreparedSetup) -> Result<bool> {
        let raw = STANDARD
            .decode(&prepared.unsigned_transaction)
            .map_err(|_| Error::config("Invalid setup packet"))?;
        if raw.len() < 65
            || raw.len() > 1232
            || raw[0] != 1
            || raw[1..65] != [0; 64]
            || STANDARD.encode(&raw[65..]) != prepared.message
        {
            return Err(Error::config("Invalid unsigned setup proof"));
        }
        self.check_setup_packet(prepared, &prepared.unsigned_transaction, None)?;
        let decoded = packet_message(&raw[65..])?;
        self.setup_blockhash_expired(prepared, decoded.blockhash)
    }

    fn setup_blockhash_expired(&self, prepared: &PreparedSetup, blockhash: Key) -> Result<bool> {
        Ok(self.setup_expiry_context(prepared, blockhash)?.is_some())
    }

    fn setup_expiry_context(
        &self,
        prepared: &PreparedSetup,
        blockhash: Key,
    ) -> Result<Option<u64>> {
        let (Some(context_slot), Some(last_valid_height)) = (
            prepared.blockhash_context_slot,
            prepared.last_valid_block_height,
        ) else {
            return Ok(None); // Legacy journals cannot prove coherent expiry.
        };
        let options = json!({"commitment":"finalized", "minContextSlot":context_slot});
        let height = self
            .rpc
            .call("getBlockHeight", json!([options.clone()]))?
            .as_u64()
            .ok_or_else(|| Error::config("Invalid finalized block height"))?;
        if height <= last_valid_height {
            return Ok(None);
        }
        let valid = self
            .rpc
            .call("isBlockhashValid", json!([blockhash, options]))?;
        if valid["context"]["slot"]
            .as_u64()
            .is_none_or(|slot| slot < context_slot)
        {
            return Err(Error::config("Lagging finalized blockhash context"));
        }
        let active = valid["value"]
            .as_bool()
            .ok_or_else(|| Error::config("Invalid finalized blockhash status"))?;
        Ok((!active).then(|| valid["context"]["slot"].as_u64().unwrap()))
    }

    /// A signed owner installation can be abandoned only after finalized
    /// blockhash expiry and finalized absence of its permanent policy account.
    pub fn setup_proven_absent(&self, prepared: &PreparedSetup, signed: &str) -> Result<bool> {
        Self::verify_setup_signature(prepared, signed)?;
        self.check_setup_packet(prepared, signed, None)?;
        let raw = STANDARD
            .decode(signed)
            .map_err(|_| Error::config("Invalid setup packet"))?;
        let decoded = packet_message(&raw[65..])?;
        let Some(expiry_slot) = self.setup_expiry_context(prepared, decoded.blockhash)? else {
            return Ok(false);
        };
        self.setup_account_absent(prepared, expiry_slot)
    }

    fn setup_account_absent(&self, prepared: &PreparedSetup, expiry_slot: u64) -> Result<bool> {
        Ok(
            account(&*self.rpc, prepared.policy, Some(expiry_slot))?
                .is_none_or(|a| unallocated(&a)),
        )
    }
}

/// Native account creation accepts a donated, empty System account as unused.
fn unallocated(account: &Account) -> bool {
    !account.executable && account.owner == Key([0; 32]) && account.data.is_empty()
}

fn settlement_transaction(
    tx: &serde_json::Value,
    signature: &str,
    program: Key,
    expected: &[u8],
) -> Result<Option<Settlement>> {
    if tx["meta"].get("err").is_none() || !tx["meta"]["err"].is_null() {
        return Ok(None);
    }
    if tx["transaction"]["signatures"][0] != signature {
        return Err(Error::config("Settlement signature differs"));
    }
    let message = &tx["transaction"]["message"];
    let mut keys = Vec::new();
    for list in [
        &message["accountKeys"],
        &tx["meta"]["loadedAddresses"]["writable"],
        &tx["meta"]["loadedAddresses"]["readonly"],
    ] {
        if list.is_null() {
            continue;
        }
        for value in list
            .as_array()
            .ok_or_else(|| Error::config("Invalid settlement accounts"))?
        {
            keys.push(Key::parse(
                value
                    .as_str()
                    .ok_or_else(|| Error::config("Invalid settlement account"))?,
            )?);
        }
    }
    let mut found = None;
    for (index, instruction) in message["instructions"]
        .as_array()
        .ok_or_else(|| Error::config("Invalid settlement instructions"))?
        .iter()
        .enumerate()
    {
        let program_index: usize = instruction["programIdIndex"]
            .as_u64()
            .ok_or_else(|| Error::config("Invalid settlement program index"))?
            .try_into()
            .map_err(|_| Error::config("Invalid settlement program index"))?;
        if keys.get(program_index) != Some(&program) {
            continue;
        }
        let bytes = bs58::decode(
            instruction["data"]
                .as_str()
                .ok_or_else(|| Error::config("Invalid settlement instruction"))?,
        )
        .into_vec()
        .map_err(|_| Error::config("Invalid settlement instruction"))?;
        if bytes == expected {
            if found.is_some() {
                return Err(Error::config("Repeated settlement execution"));
            }
            found = Some(Settlement {
                signature: signature.into(),
                finalized_slot: tx["slot"]
                    .as_u64()
                    .ok_or_else(|| Error::config("Missing finalized settlement slot"))?,
                invocation_index: index
                    .try_into()
                    .map_err(|_| Error::config("Invalid settlement invocation index"))?,
            });
        }
    }
    Ok(found)
}

fn setup_instructions(
    owner: Key,
    config: &interface::Config,
    allocation_lamports: u64,
    program: Key,
    policy: Key,
    sol_vault: Key,
    compute_limit: u32,
) -> Result<Vec<Instruction>> {
    let ata = Key::parse("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?;
    let token = Key::parse(TOKEN)?;
    let system = Key::parse(SYSTEM)?;
    let wsol = Key::parse("So11111111111111111111111111111111111111112")?;
    let associated =
        |mint: Key| Key::find_program_address(&[&policy.0, &token.0, &mint.0], ata).map(|x| x.0);
    if associated(Key(config.usdc_mint))?.0 != config.vault_usdc
        || associated(wsol)?.0 != config.vault_wsol
    {
        return Err(Error::config(
            "Policy vault token accounts are not its canonical associated accounts",
        ));
    }
    let r = |key| Meta {
        key,
        writable: false,
        signer: false,
    };
    let w = |key| Meta {
        key,
        writable: true,
        signer: false,
    };
    let signer = Meta {
        key: owner,
        writable: true,
        signer: true,
    };
    let create_ata = |mint, address| Instruction {
        program: ata,
        accounts: vec![
            signer.clone(),
            w(address),
            r(policy),
            r(mint),
            r(system),
            r(token),
        ],
        data: vec![1],
    };
    let pool = &config.pool;
    let accounts = vec![
        w(policy),
        signer.clone(),
        r(Key(config.vault_usdc)),
        r(Key(config.vault_wsol)),
        r(Key(config.usdc_mint)),
        r(Key(config.vendor_usdc)),
        r(Key(config.treasury)),
        r(system),
        w(sol_vault),
        r(Key(pool.program)),
        r(Key(pool.state)),
        r(Key(pool.wsol)),
        r(Key(pool.usdc)),
        r(Key(pool.oracle)),
    ];
    let init = Instruction {
        program,
        accounts,
        data: borsh::to_vec(&interface::Instruction::Initialize(config.clone()))
            .map_err(|_| Error::config("Invalid installation config"))?,
    };
    let mut transfer = 2u32.to_le_bytes().to_vec();
    transfer.extend(allocation_lamports.to_le_bytes());
    let fund = Instruction {
        program: system,
        accounts: vec![signer.clone(), w(sol_vault)],
        data: transfer,
    };
    let mut limit = vec![2];
    limit.extend(compute_limit.to_le_bytes());
    let compute = Instruction {
        program: Key::parse("ComputeBudget111111111111111111111111111111")?,
        accounts: vec![],
        data: limit,
    };
    let instructions = vec![
        compute,
        create_ata(Key(config.usdc_mint), Key(config.vault_usdc)),
        create_ata(wsol, Key(config.vault_wsol)),
        init,
        fund,
    ];
    Ok(instructions)
}

fn bounded_sum(spent: u64, amount: u64, cap: u64) -> Result<()> {
    if spent.checked_add(amount).is_none_or(|n| n > cap) {
        return Err(Error::denied("Approved PaySH budget would be exceeded"));
    }
    Ok(())
}
fn decode_tick_array(
    a: &crate::rpc::Account,
    program: Key,
    pool: [u8; 32],
    start: i32,
) -> Result<orca_whirlpools_core::TickArrayFacade> {
    use orca_whirlpools_core::{TickArrayFacade, TickFacade};
    let d = &a.data;
    if a.owner != program
        || a.executable
        || d.len() != 9988
        || d[..8] != Sha256::digest(b"account:TickArray")[..8]
        || d[9956..9988] != pool
        || i32::from_le_bytes(d[8..12].try_into().unwrap()) != start
    {
        return Err(Error::config(
            "Tick array differs from the approved pool and address",
        ));
    }
    if (0..88).any(|i| d[12 + i * 113] > 1) {
        return Err(Error::config("Invalid tick initialization flag"));
    }
    let ticks = std::array::from_fn(|i| {
        let t = &d[12 + i * 113..12 + (i + 1) * 113];
        let u = |o| u128::from_le_bytes(t[o..o + 16].try_into().unwrap());
        TickFacade {
            initialized: t[0] == 1,
            liquidity_net: i128::from_le_bytes(t[1..17].try_into().unwrap()),
            liquidity_gross: u(17),
            fee_growth_outside_a: u(33),
            fee_growth_outside_b: u(49),
            reward_growths_outside: [u(65), u(81), u(97)],
        }
    });
    Ok(TickArrayFacade {
        start_tick_index: start,
        ticks,
    })
}
pub fn ed25519_instruction(key: Key, message: &[u8], signature: [u8; 64]) -> Result<Instruction> {
    let size: u16 = message
        .len()
        .try_into()
        .map_err(|_| Error::config("Approval message is too large"))?;
    let mut data = vec![1, 0];
    for n in [48, u16::MAX, 16, u16::MAX, 112, size, u16::MAX] {
        data.extend(n.to_le_bytes());
    }
    data.extend(key.0);
    data.extend(signature);
    data.extend(message);
    Ok(Instruction {
        program: Key::parse(ED25519)?,
        accounts: vec![],
        data,
    })
}
fn execute_accounts(
    p: &Policy,
    program: Key,
    policy: Key,
    payer: Key,
    receipt: Key,
    budget: Key,
    action: &Action,
) -> Result<Vec<Meta>> {
    let w = |key| Meta {
        key: Key(key),
        writable: true,
        signer: false,
    };
    let r = |key| Meta {
        key: Key(key),
        writable: false,
        signer: false,
    };
    let c = &p.config;
    let mut a = vec![
        w(policy.0),
        Meta {
            key: payer,
            writable: true,
            signer: true,
        },
        w(receipt.0),
        w(budget.0),
        w(c.treasury),
        w(c.vault_usdc),
        w(c.vault_wsol),
        w(c.vendor_usdc),
        r(c.usdc_mint),
        r(Key::parse(TOKEN)?.0),
        r(Key::parse(SYSTEM)?.0),
        r(Key::parse(INSTRUCTIONS)?.0),
        w(
            Key::find_program_address(&[interface::SOL_SEED, &policy.0], program)?
                .0
                .0,
        ),
    ];
    if let Action::SwapSolToUsdc { .. } = action {
        // The admitted pool profile defines the exact additional account roles.
        a.extend(pool_accounts(&c.pool, action)?);
    }
    Ok(a)
}
fn pool_accounts(pool: &interface::Pool, action: &Action) -> Result<Vec<Meta>> {
    let r = |k| Meta {
        key: Key(k),
        writable: false,
        signer: false,
    };
    let w = |k| Meta {
        key: Key(k),
        writable: true,
        signer: false,
    };
    let Action::SwapSolToUsdc { tick_arrays, .. } = action else {
        return Err(Error::config("Invalid swap action"));
    };
    let mut accounts = vec![
        r(pool.program),
        w(pool.state),
        w(pool.wsol),
        w(pool.usdc),
        r(pool.oracle),
    ];
    accounts.extend(tick_arrays.iter().map(|key| w(*key)));
    Ok(accounts)
}
fn verify_packet(p: &PreparedExecution) -> Result<()> {
    let raw = STANDARD
        .decode(&p.signed_bytes)
        .map_err(|_| Error::config("Invalid saved signed packet"))?;
    if raw.len() < 69 || raw.len() > 1232 || raw[0] != 1 {
        return Err(Error::config("Invalid saved signed packet"));
    }
    let sig: &[u8] = &raw[1..65];
    if bs58::encode(sig).into_string() != p.signature {
        return Err(Error::config("Saved signature differs from its packet"));
    }
    verify(p.payer, &raw[65..], sig)?;
    let decoded = packet_message(&raw[65..])?;
    let req: Request = borsh::from_slice(
        &STANDARD
            .decode(&p.request_bytes)
            .map_err(|_| Error::config("Invalid saved request"))?,
    )
    .map_err(|_| Error::config("Invalid saved request"))?;
    if <[u8; 32]>::from(Sha256::digest(req.signed_message())) != p.request_hash
        || req.policy != p.policy.0
        || req.expires_slot != p.expires_slot
        || req.expires_timestamp != p.expires_timestamp
    {
        return Err(Error::config("Saved request binding changed"));
    }
    let expected = borsh::to_vec(&interface::Instruction::Execute(req.clone()))
        .map_err(|_| Error::config("Invalid saved request"))?;
    let receipt =
        Key::find_program_address(&[RECEIPT_SEED, &req.policy, &req.nonce], Key(req.program))?.0;
    if decoded.payer != p.payer
        || decoded.instructions.len() != 3
        || decoded.instructions[0].0 != Key::parse("ComputeBudget111111111111111111111111111111")?
        || decoded.instructions[1].0 != Key::parse(ED25519)?
        || decoded.instructions[2].0 != Key(req.program)
        || decoded.instructions[2].1 != expected
        || receipt != p.receipt
    {
        return Err(Error::config(
            "Saved signed packet does not execute its canonical request",
        ));
    }
    let ed = &decoded.instructions[1].1;
    if ed.len() < 112 {
        return Err(Error::config("Invalid saved approval"));
    }
    let key = Key(ed[16..48].try_into().unwrap());
    let signature: [u8; 64] = ed[48..112].try_into().unwrap();
    let exact = ed25519_instruction(key, &req.signed_message(), signature)?;
    if exact.data != *ed {
        return Err(Error::config(
            "Approval instruction differs from the canonical request",
        ));
    }
    verify(key, &req.signed_message(), &signature)?;
    Ok(())
}

struct DecodedMessage {
    payer: Key,
    blockhash: Key,
    instructions: Vec<(Key, Vec<u8>)>,
    lookup: Option<ParsedLookup>,
}
struct ParsedLookup {
    key: Key,
    writable: Vec<u8>,
    readonly: Vec<u8>,
}
fn packet_message(data: &[u8]) -> Result<DecodedMessage> {
    struct Reader<'a> {
        data: &'a [u8],
        offset: usize,
    }
    impl<'a> Reader<'a> {
        fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
            let end = self
                .offset
                .checked_add(n)
                .ok_or_else(|| Error::config("Packet overflow"))?;
            let b = self
                .data
                .get(self.offset..end)
                .ok_or_else(|| Error::config("Truncated packet"))?;
            self.offset = end;
            Ok(b)
        }
        fn byte(&mut self) -> Result<u8> {
            Ok(self.bytes(1)?[0])
        }
        fn compact(&mut self) -> Result<usize> {
            let mut n = 0;
            for i in 0..3 {
                let b = self.byte()?;
                if i == 2 && b > 3 {
                    return Err(Error::config("Invalid compact packet length"));
                }
                n |= ((b & 127) as usize) << (7 * i);
                if b & 128 == 0 {
                    if i > 0 && b == 0 {
                        return Err(Error::config("Noncanonical packet length"));
                    }
                    return Ok(n);
                }
            }
            Err(Error::config("Invalid compact packet length"))
        }
    }
    let mut r = Reader { data, offset: 0 };
    let first = r.byte()?;
    let v0 = first == 0x80;
    let required = if v0 { r.byte()? } else { first };
    let readonly_signers = r.byte()?;
    let readonly = r.byte()?;
    let count = r.compact()?;
    if required != 1
        || readonly_signers != 0
        || count == 0
        || count > 256
        || readonly as usize >= count
    {
        return Err(Error::config("Invalid sponsored packet header"));
    }
    let mut keys = Vec::new();
    for _ in 0..count {
        let k = Key(r.bytes(32)?.try_into().unwrap());
        if keys.contains(&k) {
            return Err(Error::config("Duplicate static packet account"));
        }
        keys.push(k);
    }
    let blockhash = Key(r.bytes(32)?.try_into().unwrap());
    let n = r.compact()?;
    if n > 16 {
        return Err(Error::config("Invalid packet instruction count"));
    }
    let mut instructions = Vec::new();
    for _ in 0..n {
        let index = r.byte()? as usize;
        let program = *keys
            .get(index)
            .ok_or_else(|| Error::config("Instruction program must be a static account"))?;
        let accounts = r.compact()?;
        r.bytes(accounts)?;
        let len = r.compact()?;
        instructions.push((program, r.bytes(len)?.to_vec()));
    }
    let mut lookup = None;
    if v0 {
        let n = r.compact()?;
        if n > 1 {
            return Err(Error::config(
                "Only the configured lookup table is admitted",
            ));
        }
        for _ in 0..n {
            let key = Key(r.bytes(32)?.try_into().unwrap());
            let n = r.compact()?;
            let writable = r.bytes(n)?.to_vec();
            let n = r.compact()?;
            let readonly = r.bytes(n)?.to_vec();
            lookup = Some(ParsedLookup {
                key,
                writable,
                readonly,
            });
        }
    }
    if r.offset != data.len() {
        return Err(Error::config("Trailing packet data"));
    }
    Ok(DecodedMessage {
        payer: keys[0],
        blockhash,
        instructions,
        lookup,
    })
}

/// Recover exactly the addresses the finalized transaction used. Current table
/// availability and later appends cannot change a historical payment proof.
fn historical_lookup(lookup: &ParsedLookup, loaded: &serde_json::Value) -> Result<LookupTable> {
    let writable = loaded["writable"]
        .as_array()
        .ok_or_else(|| Error::config("Missing finalized lookup addresses"))?;
    let readonly = loaded["readonly"]
        .as_array()
        .ok_or_else(|| Error::config("Missing finalized lookup addresses"))?;
    if writable.len() != lookup.writable.len() || readonly.len() != lookup.readonly.len() {
        return Err(Error::config("Finalized lookup address count differs"));
    }
    let mut addresses: Vec<Key> = (0u16..256)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"unused-paysh-lookup-slot");
            h.update(i.to_le_bytes());
            Key(h.finalize().into())
        })
        .collect();
    let mut seen = Vec::new();
    for (index, value) in lookup
        .writable
        .iter()
        .zip(writable)
        .chain(lookup.readonly.iter().zip(readonly))
    {
        if seen.contains(index) {
            return Err(Error::config("Duplicate finalized lookup index"));
        }
        seen.push(*index);
        addresses[*index as usize] = Key::parse(
            value
                .as_str()
                .ok_or_else(|| Error::config("Invalid finalized lookup address"))?,
        )?;
    }
    Ok(LookupTable {
        key: lookup.key,
        addresses,
    })
}

#[derive(Clone, Debug)]
pub struct LookupTable {
    pub key: Key,
    pub addresses: Vec<Key>,
}
pub fn transaction_message(
    payer: Key,
    blockhash: Key,
    instructions: &[Instruction],
    lookup: Option<&LookupTable>,
) -> Result<Vec<u8>> {
    if let Ok(tx) = Transaction::new(payer, blockhash, instructions.to_vec()) {
        return Ok(tx.message);
    }
    let Some(table) = lookup else {
        return Err(Error::config("Transaction requires an active lookup table"));
    };
    let mut roles: BTreeMap<Key, (bool, bool)> = BTreeMap::from([(payer, (true, true))]);
    let programs: Vec<_> = instructions.iter().map(|i| i.program).collect();
    for i in instructions {
        roles.entry(i.program).or_default();
        for a in &i.accounts {
            let role = roles.entry(a.key).or_default();
            role.0 |= a.signer;
            role.1 |= a.writable;
        }
    }
    if roles.iter().any(|(k, (s, _))| *s && *k != payer) {
        return Err(Error::config(
            "Sponsored execution requires its one fixed fee payer",
        ));
    }
    let mut writable = vec![];
    let mut readonly = vec![];
    let mut static_keys = vec![];
    for (k, (_, w)) in &roles {
        if *k != payer && !programs.contains(k) && table.addresses.contains(k) {
            let index = table.addresses.iter().position(|x| x == k).unwrap();
            if index > 255 {
                return Err(Error::config("Invalid lookup address index"));
            }
            if *w {
                writable.push((index as u8, *k));
            } else {
                readonly.push((index as u8, *k));
            }
        } else {
            static_keys.push(*k);
        }
    }
    static_keys.sort_by_key(|k| (*k != payer, !roles[k].0, !roles[k].1, *k));
    let ro = static_keys
        .iter()
        .filter(|k| !roles[k].0 && !roles[k].1)
        .count();
    let mut all = static_keys.clone();
    all.extend(writable.iter().map(|x| x.1));
    all.extend(readonly.iter().map(|x| x.1));
    if all.len() > 256 {
        return Err(Error::config("Too many transaction accounts"));
    }
    let mut out = vec![0x80, 1, 0, ro as u8];
    compact(&mut out, static_keys.len());
    for k in &static_keys {
        out.extend(k.0);
    }
    out.extend(blockhash.0);
    compact(&mut out, instructions.len());
    for i in instructions {
        out.push(all.iter().position(|k| *k == i.program).unwrap() as u8);
        compact(&mut out, i.accounts.len());
        for a in &i.accounts {
            out.push(all.iter().position(|k| *k == a.key).unwrap() as u8);
        }
        compact(&mut out, i.data.len());
        out.extend(&i.data);
    }
    out.push(1);
    out.extend(table.key.0);
    compact(&mut out, writable.len());
    out.extend(writable.iter().map(|x| x.0));
    compact(&mut out, readonly.len());
    out.extend(readonly.iter().map(|x| x.0));
    if out.len() + 65 > 1232 {
        return Err(Error::config(
            "PaySH versioned transaction exceeds packet size",
        ));
    }
    Ok(out)
}
fn compact(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut b = (n & 127) as u8;
        n >>= 7;
        if n > 0 {
            b |= 128;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

// The Apache core's unrestricted quote can revisit the last array indefinitely.
// Stop at the authenticated third array's lower boundary instead. This same limit
// is signed into the CPI action, so execution cannot traverse beyond quoted data.
fn admitted_swap_boundary(
    pool: orca_whirlpools_core::WhirlpoolFacade,
    arrays: &[orca_whirlpools_core::TickArrayFacade; 3],
) -> Result<u128> {
    use orca_whirlpools_core::{
        MAX_SQRT_PRICE, MAX_TICK_INDEX, MIN_TICK_INDEX, tick_index_to_sqrt_price,
    };
    if pool.tick_spacing == 0
        || !(MIN_TICK_INDEX..=MAX_TICK_INDEX).contains(&pool.tick_current_index)
    {
        return Err(Error::config("Invalid tick spacing"));
    }
    let span = i32::from(pool.tick_spacing) * 88;
    let start = pool.tick_current_index.div_euclid(span) * span;
    for (i, array) in arrays.iter().enumerate() {
        if Some(array.start_tick_index) != start.checked_sub(i as i32 * span) {
            return Err(Error::config("Quote arrays differ from the admitted order"));
        }
    }
    let limit = tick_index_to_sqrt_price(arrays[2].start_tick_index.max(MIN_TICK_INDEX));
    if pool.sqrt_price <= limit || pool.sqrt_price > MAX_SQRT_PRICE {
        return Err(Error::denied(
            "Pool price is outside the admitted swap range",
        ));
    }
    Ok(limit)
}

fn bounded_whirlpool_quote(
    amount: u64,
    slippage_bps: u16,
    pool: orca_whirlpools_core::WhirlpoolFacade,
    arrays: [orca_whirlpools_core::TickArrayFacade; 3],
) -> Result<orca_whirlpools_core::ExactInSwapQuote> {
    use orca_whirlpools_core::{
        ExactInSwapQuote, TickArraySequence, compute_swap,
        try_get_min_amount_with_slippage_tolerance,
    };
    if amount == 0 || slippage_bps > 100 {
        return Err(Error::denied("Invalid bounded swap amount or slippage"));
    }
    let limit = admitted_swap_boundary(pool, &arrays)?;
    let sequence = TickArraySequence::new(
        [
            Some(arrays[0]),
            Some(arrays[1]),
            Some(arrays[2]),
            None,
            None,
        ],
        pool.tick_spacing,
    )
    .map_err(|_| Error::denied("Invalid bounded tick sequence"))?;
    let swap = compute_swap(amount, limit, pool, sequence, true, true, 0)
        .map_err(|_| Error::denied("Approved pool liquidity cannot satisfy this swap"))?;
    if swap.token_a != amount {
        return Err(Error::denied("Swap exceeds the admitted tick array range"));
    }
    Ok(ExactInSwapQuote {
        token_in: swap.token_a,
        token_est_out: swap.token_b,
        token_min_out: try_get_min_amount_with_slippage_tolerance(swap.token_b, slippage_bps)
            .map_err(|_| Error::denied("Invalid integer swap slippage"))?,
        trade_fee: swap.trade_fee,
    })
}

fn minimum_swap_input(
    max: u64,
    needed: u64,
    quote: impl Fn(u64) -> Result<orca_whirlpools_core::ExactInSwapQuote>,
) -> Result<(u64, orca_whirlpools_core::ExactInSwapQuote)> {
    // Deliberately deny an out-of-range cap instead of searching beyond the
    // three approved arrays or silently selecting a different pool profile.
    if max == 0 || needed == 0 || quote(max)?.token_min_out < needed {
        return Err(Error::denied(
            "Required USDC exceeds the approved swap or available liquidity",
        ));
    }
    let (mut low, mut high) = (1, max);
    while low < high {
        let mid = low + (high - low) / 2;
        let enough = quote(mid).is_ok_and(|q| q.token_min_out >= needed);
        if enough { high = mid } else { low = mid + 1 }
    }
    Ok((low, quote(low)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixed_quote_fixture() -> (
        orca_whirlpools_core::WhirlpoolFacade,
        [orca_whirlpools_core::TickArrayFacade; 3],
    ) {
        use orca_whirlpools_core::{TickArrayFacade, TickFacade, WhirlpoolFacade};
        // Public Testnet snapshot used by the real direct swap proof. Only
        // quote-relevant state is reproduced; these are not private keys.
        let pool = WhirlpoolFacade {
            tick_spacing: 64,
            fee_rate: 400,
            liquidity: 100_000_000,
            sqrt_price: 1_844_674_407_370_955_161,
            tick_current_index: -46055,
            ..Default::default()
        };
        let mut arrays = [-50688, -56320, -61952].map(|start_tick_index| TickArrayFacade {
            start_tick_index,
            ticks: [TickFacade::default(); 88],
        });
        arrays[1].ticks[80] = TickFacade {
            initialized: true,
            liquidity_net: 100_000_000,
            liquidity_gross: 100_000_000,
            ..Default::default()
        };
        (pool, arrays)
    }

    #[test]
    fn bounded_quote_matches_actual_testnet_swap_and_integer_slippage() {
        let (pool, arrays) = fixed_quote_fixture();
        let q = bounded_whirlpool_quote(1_000_000, 50, pool, arrays).unwrap();
        assert_eq!(
            (q.token_in, q.token_est_out, q.token_min_out, q.trade_fee),
            (1_000_000, 9986, 9936, 400)
        );
        assert_eq!(
            bounded_whirlpool_quote(1_000_000, 0, pool, arrays)
                .unwrap()
                .token_min_out,
            9986
        );
        assert!(bounded_whirlpool_quote(0, 50, pool, arrays).is_err());
        assert!(bounded_whirlpool_quote(1, 101, pool, arrays).is_err());
    }

    #[test]
    fn bounded_quote_matches_independent_core_2_1_1_fixed_fee_vectors() {
        let (pool, arrays) = fixed_quote_fixture();
        // Independently computed against the preserved 2.1.1 quote binary.
        // Both releases agree on input/output/minOut/fee within the range.
        for (amount, output, min_out, fee) in [
            (1, 0, 0, 1),
            (99, 0, 0, 1),
            (1000, 9, 8, 1),
            (10_000, 99, 98, 4),
            (100_000, 999, 994, 40),
            (1_000_000, 9986, 9936, 400),
            (2_000_000, 19952, 19852, 800),
            (10_000_000, 98970, 98475, 4000),
            (50_000_000, 476009, 473628, 20_000),
            (100_000_000, 908760, 904216, 40_000),
            (250_000_000, 1999359, 1989362, 100_000),
        ] {
            let q = bounded_whirlpool_quote(amount, 50, pool, arrays).unwrap();
            assert_eq!(
                (q.token_in, q.token_est_out, q.token_min_out, q.trade_fee),
                (amount, output, min_out, fee)
            );
        }
    }

    #[test]
    fn bounded_quote_stops_at_third_array_for_oversized_and_sparse_inputs() {
        let (mut pool, mut arrays) = fixed_quote_fixture();
        for amount in [1_000_000_000, u64::MAX] {
            assert!(bounded_whirlpool_quote(amount, 50, pool, arrays).is_err());
        }
        arrays[1].ticks[80] = Default::default();
        assert!(bounded_whirlpool_quote(u64::MAX, 50, pool, arrays).is_err());
        pool.liquidity = 0;
        assert!(bounded_whirlpool_quote(1, 50, pool, arrays).is_err());
        let (pool, mut arrays) = fixed_quote_fixture();
        // Force all 264 initialized ticks to be visited, including the exact
        // lower boundary. Exhausting them must still end without revisiting it.
        for array in &mut arrays {
            for tick in &mut array.ticks {
                *tick = orca_whirlpools_core::TickFacade {
                    initialized: true,
                    liquidity_gross: 1,
                    ..Default::default()
                };
            }
        }
        assert!(bounded_whirlpool_quote(u64::MAX, 50, pool, arrays).is_err());
    }

    #[test]
    fn bounded_quote_denies_equal_price_limit_and_unordered_arrays() {
        let (mut pool, mut arrays) = fixed_quote_fixture();
        let boundary = admitted_swap_boundary(pool, &arrays).unwrap();
        pool.sqrt_price = boundary;
        assert!(bounded_whirlpool_quote(1, 50, pool, arrays).is_err());
        let (pool, _) = fixed_quote_fixture();
        arrays.swap(0, 1);
        assert!(bounded_whirlpool_quote(1, 50, pool, arrays).is_err());
        let (mut pool, arrays) = fixed_quote_fixture();
        pool.tick_current_index = i32::MIN;
        assert!(bounded_whirlpool_quote(1, 50, pool, arrays).is_err());
        pool.tick_spacing = 0;
        assert!(bounded_whirlpool_quote(1, 50, pool, arrays).is_err());
    }

    #[test]
    fn bounded_quote_clamps_near_min_tick_and_rejects_partial_input() {
        use orca_whirlpools_core::{
            MIN_SQRT_PRICE, MIN_TICK_INDEX, TickArrayFacade, TickFacade, tick_index_to_sqrt_price,
        };
        let (mut pool, _) = fixed_quote_fixture();
        pool.tick_current_index = MIN_TICK_INDEX + 1;
        pool.sqrt_price = tick_index_to_sqrt_price(pool.tick_current_index);
        let span = i32::from(pool.tick_spacing) * 88;
        let start = pool.tick_current_index.div_euclid(span) * span;
        let arrays = std::array::from_fn(|i| TickArrayFacade {
            start_tick_index: start - i as i32 * span,
            ticks: [TickFacade::default(); 88],
        });
        assert_eq!(
            admitted_swap_boundary(pool, &arrays).unwrap(),
            MIN_SQRT_PRICE
        );
        assert!(bounded_whirlpool_quote(u64::MAX, 50, pool, arrays).is_err());
        pool.sqrt_price = MIN_SQRT_PRICE;
        assert!(bounded_whirlpool_quote(1, 50, pool, arrays).is_err());
    }

    #[test]
    fn bounded_minimum_search_preserves_exact_min_out_and_cap() {
        let (pool, arrays) = fixed_quote_fixture();
        let quote = |amount| bounded_whirlpool_quote(amount, 50, pool, arrays);
        let (amount, q) = minimum_swap_input(1_000_000, 1000, quote).unwrap();
        assert!(q.token_min_out >= 1000);
        assert!(quote(amount - 1).unwrap().token_min_out < 1000);
        assert_eq!(minimum_swap_input(amount, 1000, quote).unwrap().0, amount);
        assert!(minimum_swap_input(amount - 1, 1000, quote).is_err());
        assert!(minimum_swap_input(0, 1000, quote).is_err());
        assert!(minimum_swap_input(1_000_000, 0, quote).is_err());
        // Conservatively deny the entire request when its cap needs more than
        // the authenticated arrays, even if a smaller quote would suffice.
        assert!(minimum_swap_input(u64::MAX, 1000, quote).is_err());
    }

    #[test]
    fn approval_uses_self_contained_offsets_and_exact_signature() {
        let secret = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let s = LocalSigner::from_secret(&secret.to_keypair_bytes()).unwrap();
        let message = b"exact approval";
        let ix = ed25519_instruction(s.public_key(), message, s.sign(message)).unwrap();
        assert_eq!(&ix.data[2..4], &48u16.to_le_bytes());
        assert_eq!(&ix.data[6..8], &16u16.to_le_bytes());
        assert_eq!(&ix.data[10..12], &112u16.to_le_bytes());
        for offset in [4, 8, 14] {
            assert_eq!(&ix.data[offset..offset + 2], &u16::MAX.to_le_bytes());
        }
        verify(s.public_key(), &ix.data[112..], &ix.data[48..112]).unwrap();
        assert!(verify(s.public_key(), b"changed", &ix.data[48..112]).is_err());
    }
    #[test]
    fn lookup_compresses_large_exact_message_and_keeps_program_static() {
        let payer = Key([1; 32]);
        let program = Key([2; 32]);
        let addresses: Vec<_> = (3..28).map(|i| Key([i; 32])).collect();
        let ix = Instruction {
            program,
            accounts: addresses
                .iter()
                .map(|k| Meta {
                    key: *k,
                    writable: true,
                    signer: false,
                })
                .collect(),
            data: vec![1; 550],
        };
        assert!(transaction_message(payer, Key([9; 32]), std::slice::from_ref(&ix), None).is_err());
        let message = transaction_message(
            payer,
            Key([9; 32]),
            &[ix],
            Some(&LookupTable {
                key: Key([29; 32]),
                addresses,
            }),
        )
        .unwrap();
        assert_eq!(message[0], 0x80);
        assert_eq!(message[4], 2);
        assert_eq!(&message[5..37], &payer.0);
        assert_eq!(&message[37..69], &program.0);
        assert!(message.len() + 65 < 1232);
    }
    #[test]
    fn saved_request_metadata_cannot_replace_a_different_signed_execution() {
        let signer = |n| {
            LocalSigner::from_secret(
                &ed25519_dalek::SigningKey::from_bytes(&[n; 32]).to_keypair_bytes(),
            )
            .unwrap()
        };
        let sponsor = signer(7);
        let evaluator = signer(8);
        let request = Request {
            network: [1; 32],
            program: [2; 32],
            policy: [3; 32],
            owner: [4; 32],
            module_digest: [5; 32],
            operation_id: [6; 32],
            nonce: [9; 32],
            challenge_hash: [10; 32],
            evidence_hash: [11; 32],
            signing_slot: 1000,
            signing_timestamp: 3601,
            expires_slot: 1180,
            expires_timestamp: 3661,
            service_fee_lamports: 1000,
            action: Action::PayUsdc { amount: 1000 },
        };
        let receipt = Key::find_program_address(
            &[RECEIPT_SEED, &request.policy, &request.nonce],
            Key(request.program),
        )
        .unwrap()
        .0;
        let instructions = [
            Instruction {
                program: Key::parse("ComputeBudget111111111111111111111111111111").unwrap(),
                accounts: vec![],
                data: vec![2, 64, 66, 15, 0],
            },
            ed25519_instruction(
                evaluator.public_key(),
                &request.signed_message(),
                evaluator.sign(&request.signed_message()),
            )
            .unwrap(),
            Instruction {
                program: Key(request.program),
                accounts: vec![],
                data: borsh::to_vec(&interface::Instruction::Execute(request.clone())).unwrap(),
            },
        ];
        let message =
            transaction_message(sponsor.public_key(), Key([12; 32]), &instructions, None).unwrap();
        let signature = sponsor.sign(&message);
        let mut raw = vec![1];
        raw.extend(signature);
        raw.extend(message);
        let mut proof = PreparedExecution {
            signature: bs58::encode(signature).into_string(),
            signed_bytes: STANDARD.encode(raw),
            request_bytes: STANDARD.encode(borsh::to_vec(&request).unwrap()),
            request_hash: Sha256::digest(request.signed_message()).into(),
            receipt,
            policy: Key(request.policy),
            payer: sponsor.public_key(),
            expires_slot: request.expires_slot,
            expires_timestamp: request.expires_timestamp,
        };
        verify_packet(&proof).unwrap();
        let mut replacement = request;
        replacement.action = Action::PayUsdc { amount: 999_999 };
        replacement.challenge_hash = [13; 32];
        proof.request_bytes = STANDARD.encode(borsh::to_vec(&replacement).unwrap());
        proof.request_hash = Sha256::digest(replacement.signed_message()).into();
        assert!(verify_packet(&proof).is_err());
    }

    #[test]
    fn finalized_lookup_preserves_original_placement_after_table_append_or_close() {
        let payer = Key([1; 32]);
        let program = Key([2; 32]);
        let addresses: Vec<_> = (3..28).map(|i| Key([i; 32])).collect();
        let static_account = Key([30; 32]);
        let ix = Instruction {
            program,
            accounts: addresses
                .iter()
                .chain(std::iter::once(&static_account))
                .map(|key| Meta {
                    key: *key,
                    writable: true,
                    signer: false,
                })
                .collect(),
            data: vec![1; 550],
        };
        let table = LookupTable {
            key: Key([29; 32]),
            addresses,
        };
        let original = transaction_message(
            payer,
            Key([31; 32]),
            std::slice::from_ref(&ix),
            Some(&table),
        )
        .unwrap();
        let parsed = packet_message(&original).unwrap();
        let lookup = parsed.lookup.unwrap();
        let meta = json!({"writable":lookup.writable.iter().map(|i|table.addresses[*i as usize].to_string()).collect::<Vec<_>>(),"readonly":[]});
        let recovered = historical_lookup(&lookup, &meta).unwrap();
        assert_eq!(
            original,
            transaction_message(
                payer,
                Key([31; 32]),
                std::slice::from_ref(&ix),
                Some(&recovered)
            )
            .unwrap()
        );
        let mut extended = table;
        extended.addresses.push(static_account);
        assert_ne!(
            original,
            transaction_message(payer, Key([31; 32]), &[ix], Some(&extended)).unwrap()
        );
        let mut bad = meta;
        bad["writable"][0] = json!(Key([99; 32]).to_string());
        assert_ne!(
            recovered.addresses,
            historical_lookup(&lookup, &bad).unwrap().addresses
        );
        assert!(historical_lookup(&lookup, &json!({"writable":[],"readonly":[]})).is_err());
    }

    #[test]
    fn settlement_identifies_the_actual_relayer_and_loaded_program() {
        let program = Key([2; 32]);
        let data = vec![1, 2, 3];
        let tx = json!({"slot":42,"meta":{"err":null,"loadedAddresses":{"writable":[],"readonly":[program.to_string()]}},
            "transaction":{"signatures":["winning-relayer"],"message":{"accountKeys":[Key([1;32]).to_string()],
            "instructions":[{"programIdIndex":0,"data":""},{"programIdIndex":1,"data":bs58::encode(&data).into_string()}]}}});
        assert_eq!(
            settlement_transaction(&tx, "winning-relayer", program, &data).unwrap(),
            Some(Settlement {
                signature: "winning-relayer".into(),
                finalized_slot: 42,
                invocation_index: 1
            })
        );
        assert!(settlement_transaction(&tx, "original-sponsor", program, &data).is_err());
        assert_eq!(
            settlement_transaction(&tx, "winning-relayer", program, &[9]).unwrap(),
            None
        );
    }

    #[test]
    fn settlement_requires_success_metadata_and_one_exact_execution() {
        let program = Key([2; 32]);
        let ix = json!({"programIdIndex":0,"data":bs58::encode([1,2,3]).into_string()});
        let mut tx = json!({"slot":42,"meta":{"err":null},"transaction":{"signatures":["relayer"],
            "message":{"accountKeys":[program.to_string()],"instructions":[ix.clone()]}}});
        assert!(
            settlement_transaction(&tx, "relayer", program, &[1, 2, 3])
                .unwrap()
                .is_some()
        );
        tx["meta"] = json!({});
        assert_eq!(
            settlement_transaction(&tx, "relayer", program, &[1, 2, 3]).unwrap(),
            None
        );
        tx["meta"] = json!({"err":{"InstructionError":[0,"Custom"]}});
        assert_eq!(
            settlement_transaction(&tx, "relayer", program, &[1, 2, 3]).unwrap(),
            None
        );
        tx["meta"] = json!({"err":null});
        tx["transaction"]["message"]["instructions"] = json!([ix.clone(), ix]);
        assert!(settlement_transaction(&tx, "relayer", program, &[1, 2, 3]).is_err());
    }

    #[test]
    fn setup_expiry_requires_height_and_coherent_finalized_context() {
        struct ExpiryRpc {
            height: u64,
            slot: u64,
            valid: bool,
        }
        impl Rpc for ExpiryRpc {
            fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
                match method {
                    "getBlockHeight" => {
                        assert_eq!(params[0]["minContextSlot"], 100);
                        Ok(json!(self.height))
                    }
                    "isBlockhashValid" => {
                        assert_eq!(params[1]["minContextSlot"], 100);
                        Ok(json!({"context":{"slot":self.slot},"value":self.valid}))
                    }
                    "getAccountInfo" => {
                        assert_eq!(params[1]["minContextSlot"], self.slot);
                        Ok(json!({"context":{"slot":self.slot-1},"value":null}))
                    }
                    _ => panic!("unexpected RPC {method}"),
                }
            }
        }
        let proof = PreparedSetup {
            owner: Key([1; 32]),
            policy: Key([2; 32]),
            sol_vault: Key([3; 32]),
            config_bytes: String::new(),
            allocation_lamports: 1,
            message: String::new(),
            unsigned_transaction: String::new(),
            blockhash_context_slot: Some(100),
            last_valid_block_height: Some(200),
        };
        let client = |height, slot, valid| {
            PayShClient::new(
                Deployment {
                    program: Key([4; 32]),
                    genesis: Key([5; 32]),
                    module_digest: [6; 32],
                    program_artifact: [7; 32],
                    upgrade_authority: None,
                    pool_program: Key([8; 32]),
                    pool_program_artifact: [9; 32],
                    pool_upgrade_authority: None,
                    lookup_table: None,
                    compute_limit: 100_000,
                },
                Arc::new(ExpiryRpc {
                    height,
                    slot,
                    valid,
                }),
            )
            .unwrap()
        };
        let hash = Key([10; 32]);
        assert!(
            !client(200, 100, false)
                .setup_blockhash_expired(&proof, hash)
                .unwrap()
        );
        assert!(
            !client(201, 101, true)
                .setup_blockhash_expired(&proof, hash)
                .unwrap()
        );
        assert!(
            client(201, 99, false)
                .setup_blockhash_expired(&proof, hash)
                .is_err()
        );
        assert!(
            client(201, 101, false)
                .setup_blockhash_expired(&proof, hash)
                .unwrap()
        );
        let expired = client(201, 101, false);
        let expiry_slot = expired.setup_expiry_context(&proof, hash).unwrap().unwrap();
        assert_eq!(expiry_slot, 101);
        assert!(expired.setup_account_absent(&proof, expiry_slot).is_err());
        let mut legacy = proof;
        legacy.blockhash_context_slot = None;
        assert!(
            !client(201, 101, false)
                .setup_blockhash_expired(&legacy, hash)
                .unwrap()
        );
    }

    #[test]
    fn checked_budgets_cannot_wrap() {
        assert!(bounded_sum(u64::MAX, 1, u64::MAX).is_err());
        assert!(bounded_sum(7, 4, 10).is_err());
        assert!(bounded_sum(7, 3, 10).is_ok());
    }

    /// Public protocol fixture; the RPC transport never connects to a cluster
    /// or loads signing keys.
    struct RecoveryFixture {
        deployment: Deployment,
        policy: Policy,
        request: Request,
        original: PreparedExecution,
        alternative: PreparedExecution,
    }
    impl RecoveryFixture {
        fn new() -> Self {
            // Public packets captured from the finalized Testnet relayer-race
            // regression. No signing secrets or live RPC calls are required.
            let deployment: Deployment = serde_json::from_str(r#"{"computeLimit":900000,"genesis":"4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY","lookupTable":"H7YaW5WvJekYrQxMAxTvUQbi5ofp5Dx6Ffmm11RKNdJd","moduleDigest":[219,159,224,2,254,58,128,163,7,138,167,61,245,149,171,29,105,42,45,138,47,45,199,179,87,3,207,6,181,252,253,104],"poolProgram":"7vNu5JwjiDSvyDaVv5eykQvXjHeXh24iAFCSq21sBkg3","poolProgramArtifact":[31,74,161,0,195,208,39,191,181,112,186,113,238,146,238,246,215,190,210,16,176,147,180,120,88,57,201,228,238,68,206,104],"poolUpgradeAuthority":"5LRTaca6jgPzTSgG9vV5YonL7VmFpKBTbLBSBKUPRALX","program":"CLaqn7vJ2VQyaLBLWyj3YgynVo7jcG8eoy21mJT6nYe6","programArtifact":[165,108,123,214,82,41,144,230,78,250,115,218,5,187,99,194,224,2,187,31,60,67,73,250,29,128,131,189,190,67,90,199],"upgradeAuthority":"7a6zuZXTVaNcrY8BkoTeRasuqj7qmQkZWgd8xH7RYSg2"}"#).unwrap();
            let original: PreparedExecution = serde_json::from_str(r#"{"expiresSlot":449830346,"expiresTimestamp":1791419275,"payer":"DM34nWejgGkuj51F8jrfCvWAXJrsj9PiEY7uAMS4vuqG","policy":"Bbe81FrevbMKmo1Gbt2GQJwPTXCQbp8xGvRSu9MQZqHx","receipt":"6x6XGeY3DEmt9ZveDwRqDPHM3ACKKinWvD36vaahtDd3","requestBytes":"OhMuzhAwXsGDByVQL6K35+uBV+kSPUwfZUpxeHFh3CGodNsPP1aBN4E4wW0/veQVDHWdxYKOOh30pzQr9I2+m510luAFFvv2t7ONIAjr8NtltFepGC3TaW91QDNtclWHYaESFi79/A83XgaZth9TgCGW3+r/1RsEPmT+MqNmz/Pbn+AC/jqAoweKpz31lasdaSotii8tx7NXA88Gtfz9aCkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiorKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKywsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsFt3PGgAAAABP48ZqAAAAAMrdzxoAAAAAi+PGagAAAADoAwAAAAAAAAABAAAAAAAAAA==","requestHash":[5,91,229,250,237,182,1,200,66,94,76,101,162,82,31,126,81,169,212,186,77,32,97,130,221,147,39,149,146,219,140,157],"signature":"4PU2pk1yiXS4HhdgH2DspAcUHfG6YvK4mPtCCmsE4fWCEnP4AtNUx1MTghMuNtkcYXwGnymYJ1Pxg8hFmrh7zPsR","signedBytes":"AalsxGYx/wEdFr+n8qqXKk1mFXS4e6nBrG5YyAqcoXBYUvN5EtE9yCOB7BiG0n1ltjWbkm385yLwYxWs0EX0EQwBAAcQt24xyeLF6lGBQukDx40uMieiqLo5yER1yC435d49g9dAaHApQexteBeFXE3+ChFNrcdmHVk8JT+MmR0ZSfWoMFhnn2zdneA5RfauOjq32uKIsi18hlgKkHk38RJZE+uyYEzhuiuf93TQ5t7hC9cmxX1OaRKaLXEwISeSGTW8LTeAVDe/19PrSSevU7s9HTmyo8olE8SKViRuafZTr8OOm510luAFFvv2t7ONIAjr8NtltFepGC3TaW91QDNtclWHotZ35m/yVZpg3d226HMfI1fK7e3NAHqImdleJvp33PrTwXXGnvdBPirMkVSxtuee1gmnhSNg/Rk09k5Ocl3sBvAW37ZcQJp3ArNj5VdfkWHlf/RkFp+KZRp7Ch+v6C3TAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACodNsPP1aBN4E4wW0/veQVDHWdxYKOOh30pzQr9I2+mwMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAA31G1nyT+74S+UKPg41A/wVwdEkn9Ipk/MpwRIAAAADzKTpjc+b3MwD3QOwtEiVkzIDEpiH+2d1Puq93rd8NgQan1RcYe9FmNdrUBFX9wsDBJMaPIVZ1pdu6y18IAAAABt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKlCyLfq4SAAbbMxDitb98Lcl6KKJMDpUWkShUG30AojKwMLAAUCoLsNAAwAqAEBADAA//8QAP//cAA4AP//VYzzAmKP/48GOza+ZXe23DS7puEyRivupM4Vc7ojWdCXY0IZT86g2rfMDk1Uy3dwwzsdZhomJEa0t0Mpv3BldqI6l3w50+dWzk2sSCypEUoZmO56Lvm2vTUC9Tp1UAkJYWxsb3dpdC1wYXlzaC1yZXF1ZXN0LXYx8QfbFFc9skuC7qUGhJFm4j019453R1quJYLDPoAJFo0KDQUAAgcBCAYEDQ8JDgPSAgE6Ey7OEDBewYMHJVAvorfn64FX6RI9TB9lSnF4cWHcIah02w8/VoE3gTjBbT+95BUMdZ3Fgo46HfSnNCv0jb6bnXSW4AUW+/a3s40gCOvw22W0V6kYLdNpb3VAM21yVYdhoRIWLv38DzdeBpm2H1OAIZbf6v/VGwQ+ZP4yo2bP89uf4AL+OoCjB4qnPfWVqx1pKi2KLy3Hs1cDzwa1/P1oKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKisrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwW3c8aAAAAAE/jxmoAAAAAyt3PGgAAAACL48ZqAAAAAOgDAAAAAAAAAAEAAAAAAAAA"}"#).unwrap();
            let alternative: PreparedExecution = serde_json::from_str(r#"{"expiresSlot":449830346,"expiresTimestamp":1791419275,"payer":"7a6zuZXTVaNcrY8BkoTeRasuqj7qmQkZWgd8xH7RYSg2","policy":"Bbe81FrevbMKmo1Gbt2GQJwPTXCQbp8xGvRSu9MQZqHx","receipt":"6x6XGeY3DEmt9ZveDwRqDPHM3ACKKinWvD36vaahtDd3","requestBytes":"OhMuzhAwXsGDByVQL6K35+uBV+kSPUwfZUpxeHFh3CGodNsPP1aBN4E4wW0/veQVDHWdxYKOOh30pzQr9I2+m510luAFFvv2t7ONIAjr8NtltFepGC3TaW91QDNtclWHYaESFi79/A83XgaZth9TgCGW3+r/1RsEPmT+MqNmz/Pbn+AC/jqAoweKpz31lasdaSotii8tx7NXA88Gtfz9aCkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiorKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKywsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsFt3PGgAAAABP48ZqAAAAAMrdzxoAAAAAi+PGagAAAADoAwAAAAAAAAABAAAAAAAAAA==","requestHash":[5,91,229,250,237,182,1,200,66,94,76,101,162,82,31,126,81,169,212,186,77,32,97,130,221,147,39,149,146,219,140,157],"signature":"2NwsGigyduazGcCqMnfhfk6cYoCG9HViuobmqQ7xyEdbckg3F7RYL76STsWY9J9te9GGBsWSDHdx9NV447ECDWKh","signedBytes":"AUTxP57xrQVo4LwkjlKmJIVKlHhmOi3eltvyBHUNpD+ZGmTNqLK7eyQ6BsxTVTXE9HFAhNlrEDkYBftYlURUKAABAAcQYaESFi79/A83XgaZth9TgCGW3+r/1RsEPmT+MqNmz/NAaHApQexteBeFXE3+ChFNrcdmHVk8JT+MmR0ZSfWoMFhnn2zdneA5RfauOjq32uKIsi18hlgKkHk38RJZE+uyYEzhuiuf93TQ5t7hC9cmxX1OaRKaLXEwISeSGTW8LTeAVDe/19PrSSevU7s9HTmyo8olE8SKViRuafZTr8OOm510luAFFvv2t7ONIAjr8NtltFepGC3TaW91QDNtclWHotZ35m/yVZpg3d226HMfI1fK7e3NAHqImdleJvp33PrTwXXGnvdBPirMkVSxtuee1gmnhSNg/Rk09k5Ocl3sBvAW37ZcQJp3ArNj5VdfkWHlf/RkFp+KZRp7Ch+v6C3TAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACodNsPP1aBN4E4wW0/veQVDHWdxYKOOh30pzQr9I2+mwMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAA31G1nyT+74S+UKPg41A/wVwdEkn9Ipk/MpwRIAAAADzKTpjc+b3MwD3QOwtEiVkzIDEpiH+2d1Puq93rd8NgQan1RcYe9FmNdrUBFX9wsDBJMaPIVZ1pdu6y18IAAAABt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKnFkLmRhbKlzLBIjykmcWjW+Tr9ci1tjChTSyU20udRGQMLAAUCoLsNAAwAqAEBADAA//8QAP//cAA4AP//VYzzAmKP/48GOza+ZXe23DS7puEyRivupM4Vc7ojWdCXY0IZT86g2rfMDk1Uy3dwwzsdZhomJEa0t0Mpv3BldqI6l3w50+dWzk2sSCypEUoZmO56Lvm2vTUC9Tp1UAkJYWxsb3dpdC1wYXlzaC1yZXF1ZXN0LXYx8QfbFFc9skuC7qUGhJFm4j019453R1quJYLDPoAJFo0KDQUAAgcBCAYEDQ8JDgPSAgE6Ey7OEDBewYMHJVAvorfn64FX6RI9TB9lSnF4cWHcIah02w8/VoE3gTjBbT+95BUMdZ3Fgo46HfSnNCv0jb6bnXSW4AUW+/a3s40gCOvw22W0V6kYLdNpb3VAM21yVYdhoRIWLv38DzdeBpm2H1OAIZbf6v/VGwQ+ZP4yo2bP89uf4AL+OoCjB4qnPfWVqx1pKi2KLy3Hs1cDzwa1/P1oKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKisrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwW3c8aAAAAAE/jxmoAAAAAyt3PGgAAAACL48ZqAAAAAOgDAAAAAAAAAAEAAAAAAAAA"}"#).unwrap();
            let config: interface::Config = borsh::from_slice(&STANDARD.decode("PlQnvUCF43GQvMfeVVfeywMFy0ok0TBHAnRY9gz/RuE6Ey7OEDBewYMHJVAvorfn64FX6RI9TB9lSnF4cWHcIduf4AL+OoCjB4qnPfWVqx1pKi2KLy3Hs1cDzwa1/P1oVYzzAmKP/48GOza+ZXe23DS7puEyRivupM4Vc7ojWdBAaHApQexteBeFXE3+ChFNrcdmHVk8JT+MmR0ZSfWoMPMpOmNz5vczAPdA7C0SJWTMgMSmIf7Z3U+6r3et3w2B8BbftlxAmncCs2PlV1+RYeV/9GQWn4plGnsKH6/oLdOi1nfmb/JVmmDd3bbocx8jV8rt7c0AeoiZ2V4m+nfc+oBUN7/X0+tJJ69Tuz0dObKjyiUTxIpWJG5p9lOvw46bZtKqFfSwLvpOOqM2mHXq1G5fiqwhKPnpacjHCcwe9dSseu0XUCaTYTsV64+8wTL+raFAiQnL09VibW252Qi4tpdNgkpsKM6oMAxqxnPxYoJHcuHLziawRQwNzZp7mEcSsX/R5LYnljofiWMjIyiyNk7GZfN7jrQnLQf4JJTf0gb8fFKEc7HD+BI+2JGSOw/t35fSleX8EHKDRAWrKuN/TRAOAAAAAAAAUMMAAAAAAADAxi0AAAAAABAnAAAAAAAAQEtMAAAAAADAxi0AAAAAAMDGLQAAAAAAQEtMAAAAAADoAwAAAAAAAAASegAAAAAACgAAAAAAAAC0AAAAAAAAADwAAAAAAAAAGvHGagAAAAAA").unwrap()).unwrap();
            let request: Request =
                borsh::from_slice(&STANDARD.decode(&original.request_bytes).unwrap()).unwrap();
            let (policy_key, bump) = Key::find_program_address(
                &[interface::POLICY_SEED, &request.owner, &config.instance_id],
                deployment.program,
            )
            .unwrap();
            assert_eq!(policy_key, original.policy);
            let policy = Policy {
                version: 1,
                bump,
                owner: request.owner,
                paused: false,
                total_swap_lamports: 0,
                total_sol_debits: 0,
                config,
            };
            Self {
                deployment,
                policy,
                request,
                original,
                alternative,
            }
        }
        fn rpc(&self, receipt_present: bool, slot: u64, timestamp: i64) -> RecoveryRpc {
            let mut policy_bytes = borsh::to_vec(&self.policy).unwrap();
            policy_bytes.resize(interface::POLICY_BYTES, 0);
            let receipt = interface::Receipt {
                version: 1,
                request_hash: self.original.request_hash,
                operation_id: self.request.operation_id,
                signing_timestamp: self.request.signing_timestamp,
            };
            RecoveryRpc {
                deployment: self.deployment.clone(),
                policy_key: self.original.policy,
                policy_bytes,
                receipt_key: self.original.receipt,
                receipt_owner: self.deployment.program,
                receipt_bytes: receipt_present.then(|| borsh::to_vec(&receipt).unwrap()),
                slot,
                timestamp,
                receipt_context_slot: slot,
                original_signature: self.original.signature.clone(),
                // The original sponsor can fail after another relayer consumes the nonce.
                original_transaction: json!({"slot":self.request.signing_slot + 1,"meta":{"err":{"InstructionError":[2,{"Custom":203}]}}}),
                alternative_signature: self.alternative.signature.clone(),
                alternative_transaction: serde_json::Value::Null,
                history: json!([]),
                calls: std::sync::Mutex::new(vec![]),
            }
        }
        fn winning_transaction(&self) -> serde_json::Value {
            json!({"slot":self.request.signing_slot + 1,"meta":{"err":null},
                "transaction":{"signatures":[self.alternative.signature],"message":{
                    "accountKeys":[self.alternative.payer.to_string(),
                        "ComputeBudget111111111111111111111111111111",
                        ED25519,self.deployment.program.to_string()],
                    "instructions":[{"programIdIndex":1,"data":""},
                        {"programIdIndex":2,"data":""},
                        {"programIdIndex":3,"data":bs58::encode(
                            borsh::to_vec(&interface::Instruction::Execute(self.request.clone())).unwrap()
                        ).into_string()}]}}})
        }
    }
    struct RecoveryRpc {
        deployment: Deployment,
        policy_key: Key,
        policy_bytes: Vec<u8>,
        receipt_key: Key,
        receipt_owner: Key,
        receipt_bytes: Option<Vec<u8>>,
        slot: u64,
        timestamp: i64,
        receipt_context_slot: u64,
        original_signature: String,
        original_transaction: serde_json::Value,
        alternative_signature: String,
        alternative_transaction: serde_json::Value,
        history: serde_json::Value,
        calls: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
    }
    impl Rpc for RecoveryRpc {
        fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
            self.calls
                .lock()
                .unwrap()
                .push((method.into(), params.clone()));
            let value = |owner: Key, bytes: &[u8]| {
                json!({"owner":owner.to_string(),
                "executable":false,"data":[STANDARD.encode(bytes),"base64"]})
            };
            match method {
                "getGenesisHash" => Ok(json!(self.deployment.genesis.to_string())),
                "getAccountInfo" => {
                    assert_eq!(params[1]["commitment"], "finalized");
                    let key = Key::parse(params[0].as_str().unwrap()).unwrap();
                    if key == self.policy_key {
                        Ok(
                            json!({"context":{"slot":self.slot},"value":value(self.deployment.program,&self.policy_bytes)}),
                        )
                    } else if key
                        == Key::parse("SysvarC1ock11111111111111111111111111111111").unwrap()
                    {
                        let mut clock = vec![0; 40];
                        clock[..8].copy_from_slice(&self.slot.to_le_bytes());
                        clock[32..40].copy_from_slice(&self.timestamp.to_le_bytes());
                        Ok(
                            json!({"context":{"slot":self.slot},"value":value(Key::parse("Sysvar1111111111111111111111111111111111111").unwrap(),&clock)}),
                        )
                    } else {
                        assert_eq!(key, self.receipt_key);
                        assert_eq!(params[1]["minContextSlot"], self.slot);
                        Ok(json!({"context":{"slot":self.receipt_context_slot},
                            "value":self.receipt_bytes.as_ref().map(|bytes|value(self.receipt_owner,bytes))}))
                    }
                }
                "getTransaction" => {
                    assert_eq!(params[1]["commitment"], "finalized");
                    let signature = params[0].as_str().unwrap();
                    if signature == self.original_signature {
                        Ok(self.original_transaction.clone())
                    } else {
                        assert_eq!(signature, self.alternative_signature);
                        Ok(self.alternative_transaction.clone())
                    }
                }
                "getSignaturesForAddress" => {
                    assert_eq!(params[0], self.receipt_key.to_string());
                    assert_eq!(params[1]["commitment"], "finalized");
                    assert_eq!(params[1]["minContextSlot"], self.slot);
                    if params[1].get("before").is_some() {
                        Ok(json!([]))
                    } else {
                        Ok(self.history.clone())
                    }
                }
                _ => panic!("Unexpected recovery RPC {method}"),
            }
        }
    }
    #[test]
    fn failed_exact_owner_packet_is_unfinalized_not_positive_absence() {
        let fixture = RecoveryFixture::new();
        let raw = STANDARD.decode(&fixture.original.signed_bytes).unwrap();
        let mut unsigned = raw.clone();
        unsigned[1..65].fill(0);
        // Any exact failed owner packet is false, never an installation or absence proof.
        let proof = PreparedSetup {
            owner: fixture.original.payer,
            policy: fixture.original.policy,
            sol_vault: Key([1; 32]),
            config_bytes: String::new(),
            allocation_lamports: 1,
            message: STANDARD.encode(&raw[65..]),
            unsigned_transaction: STANDARD.encode(unsigned),
            blockhash_context_slot: Some(100),
            last_valid_block_height: Some(200),
        };
        let mut rpc = fixture.rpc(
            false,
            fixture.request.expires_slot,
            fixture.request.expires_timestamp,
        );
        rpc.original_transaction = json!({"meta":{"err":{"InstructionError":[2,"Custom"]}},
            "transaction":[fixture.original.signed_bytes,"base64"]});
        let client = PayShClient::new(fixture.deployment.clone(), Arc::new(rpc)).unwrap();
        assert!(
            !client
                .finalized_setup(&proof, &fixture.original.signed_bytes)
                .unwrap()
        );
        let mut rpc = fixture.rpc(
            false,
            fixture.request.expires_slot,
            fixture.request.expires_timestamp,
        );
        rpc.original_transaction = json!({"meta":{"err":{"InstructionError":[2,"Custom"]}},
            "transaction":["different-packet","base64"]});
        let client = PayShClient::new(fixture.deployment.clone(), Arc::new(rpc)).unwrap();
        assert!(
            client
                .finalized_setup(&proof, &fixture.original.signed_bytes)
                .is_err()
        );
    }

    #[test]
    fn donated_empty_receipt_is_unused_but_foreign_or_executable_accounts_are_not() {
        let fixture = RecoveryFixture::new();
        let mut rpc = fixture.rpc(
            false,
            fixture.request.expires_slot + 1,
            fixture.request.expires_timestamp + 1,
        );
        rpc.receipt_bytes = Some(vec![]);
        rpc.receipt_owner = Key([0; 32]);
        let client = PayShClient::new(fixture.deployment.clone(), Arc::new(rpc)).unwrap();
        assert_eq!(
            client.settlement(&fixture.original).unwrap(),
            ExecutionStatus::ProvenAbsent
        );
        let mut a = Account {
            owner: Key([0; 32]),
            executable: false,
            data: vec![],
        };
        assert!(unallocated(&a));
        a.executable = true;
        assert!(!unallocated(&a));
        a.executable = false;
        a.owner = Key([9; 32]);
        assert!(!unallocated(&a));
        a.owner = Key([0; 32]);
        a.data.push(1);
        assert!(!unallocated(&a));
    }

    #[test]
    fn settlement_retains_consumed_nonce_when_transaction_is_unlocated() {
        let fixture = RecoveryFixture::new();
        let rpc = Arc::new(fixture.rpc(
            true,
            fixture.request.expires_slot + 1,
            fixture.request.expires_timestamp + 1,
        ));
        let client = PayShClient::new(fixture.deployment.clone(), rpc.clone()).unwrap();
        assert_eq!(
            client.settlement(&fixture.original).unwrap(),
            ExecutionStatus::ConsumedUnlocated
        );
        // Expiry does not make a consumed authorization replaceable.
        assert_eq!(client.finalized(&fixture.original).unwrap_err().code, 5);
        let calls = rpc.calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(method, _)| method == "getSignaturesForAddress")
        );
        assert!(
            calls
                .iter()
                .any(|(method, params)| method == "getTransaction"
                    && params[0] == fixture.original.signature)
        );
    }
    #[test]
    fn settlement_proves_absence_only_after_both_coherent_finalized_clocks() {
        let fixture = RecoveryFixture::new();
        for (slot, timestamp, expected) in [
            (
                fixture.request.expires_slot,
                fixture.request.expires_timestamp,
                ExecutionStatus::Pending,
            ),
            (
                fixture.request.expires_slot + 1,
                fixture.request.expires_timestamp,
                ExecutionStatus::Pending,
            ),
            (
                fixture.request.expires_slot,
                fixture.request.expires_timestamp + 1,
                ExecutionStatus::Pending,
            ),
            (
                fixture.request.expires_slot + 1,
                fixture.request.expires_timestamp + 1,
                ExecutionStatus::ProvenAbsent,
            ),
        ] {
            let rpc = Arc::new(fixture.rpc(false, slot, timestamp));
            let client = PayShClient::new(fixture.deployment.clone(), rpc.clone()).unwrap();
            assert_eq!(client.settlement(&fixture.original).unwrap(), expected);
            assert!(!rpc.calls.lock().unwrap().iter().any(|(method, _)| method
                == "getTransaction"
                || method == "getSignaturesForAddress"));
        }
        let mut stale = fixture.rpc(
            false,
            fixture.request.expires_slot + 1,
            fixture.request.expires_timestamp + 1,
        );
        stale.receipt_context_slot = fixture.request.expires_slot;
        let client = PayShClient::new(fixture.deployment, Arc::new(stale)).unwrap();
        assert!(client.settlement(&fixture.original).is_err());
    }
    #[test]
    fn settlement_recovers_alternate_relayer_after_original_sponsor_failed() {
        let fixture = RecoveryFixture::new();
        assert_ne!(fixture.original.payer, fixture.alternative.payer);
        assert_ne!(fixture.original.signature, fixture.alternative.signature);
        assert_eq!(
            fixture.original.request_hash,
            fixture.alternative.request_hash
        );
        let mut rpc = fixture.rpc(
            true,
            fixture.request.expires_slot + 1,
            fixture.request.expires_timestamp + 1,
        );
        rpc.alternative_transaction = fixture.winning_transaction();
        rpc.history = json!([{"signature":"missing-success-metadata"},
            {"signature":fixture.original.signature,"err":{"InstructionError":[2,{"Custom":203}]}},
            {"signature":fixture.alternative.signature,"err":null}]);
        let rpc = Arc::new(rpc);
        let client = PayShClient::new(fixture.deployment, rpc.clone()).unwrap();
        assert_eq!(
            client.settlement(&fixture.original).unwrap(),
            ExecutionStatus::Finalized(Settlement {
                signature: fixture.alternative.signature.clone(),
                finalized_slot: fixture.request.signing_slot + 1,
                invocation_index: 2,
            })
        );
        let calls = rpc.calls.lock().unwrap();
        let queries: Vec<_> = calls
            .iter()
            .filter(|(method, _)| method == "getTransaction")
            .map(|(_, params)| params[0].as_str().unwrap())
            .collect();
        assert_eq!(
            queries,
            vec![
                fixture.original.signature.as_str(),
                fixture.alternative.signature.as_str()
            ]
        );
    }
}
