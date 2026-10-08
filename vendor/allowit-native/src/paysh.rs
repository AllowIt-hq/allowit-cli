//! Sponsored native payment transport. Provider HTTP and semantic authority
//! remain in the trusted host; this client only signs the installed profile.
use crate::{
    crypto::{Key, LocalSigner, verify},
    error::{Error, Result},
    rpc::{Rpc, account},
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
        let loader = Key::parse("BPFLoaderUpgradeab1e11111111111111111111111")?;
        let p = account(&*self.rpc, self.deployment.program, None)?
            .ok_or_else(|| Error::config("PaySH program is not deployed"))?;
        if !p.executable
            || p.owner != loader
            || p.data.len() != 36
            || p.data[..4] != 2u32.to_le_bytes()
        {
            return Err(Error::config("Invalid PaySH program account"));
        }
        let linked = Key(p.data[4..36].try_into().unwrap());
        let canonical = Key::find_program_address(&[&self.deployment.program.0], loader)?.0;
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
        if authority != self.deployment.upgrade_authority
            || <[u8; 32]>::from(Sha256::digest(&data.data[45..]))
                != self.deployment.program_artifact
        {
            return Err(Error::config(
                "PaySH executable or upgrade authority changed",
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
        use orca_whirlpools_core::{
            MIN_SQRT_PRICE, TickArrayFacade, WhirlpoolFacade, WhirlpoolRewardInfoFacade,
            swap_quote_by_input_token,
        };
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
            fee_tier_index_seed: d[43..45].try_into().unwrap(),
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
        let (_, timestamp) = self.clock()?;
        let quote = |amount| {
            swap_quote_by_input_token(
                amount,
                true,
                slippage_bps,
                whirlpool,
                None,
                arrays.into(),
                timestamp.max(0) as u64,
                None,
                None,
            )
        };
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
        let best = quote(max)
            .map_err(|_| Error::denied("Approved pool liquidity cannot satisfy this swap"))?;
        if max == 0 || best.token_min_out < needed {
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
        let q = quote(low).map_err(|_| Error::denied("No admissible swap quote"))?;
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
            sqrt_price_limit: MIN_SQRT_PRICE,
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
        if p.version != 1
            || p.bump != expected.1
            || expected.0 != address
            || p.config.network != self.deployment.genesis.0
            || p.config.module_digest != self.deployment.module_digest
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
        self.check_setup_packet(prepared, signed_bytes, None)?;
        let result=self.rpc.call("sendTransaction",json!([signed_bytes,{"encoding":"base64","skipPreflight":false,"preflightCommitment":"finalized","maxRetries":0}]))?;
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
        if !tx["meta"]["err"].is_null() {
            return Err(Error::denied("Policy installation finalized with an error"));
        }
        if tx["transaction"][1] != "base64" || tx["transaction"][0] != signed_bytes {
            return Err(Error::config(
                "Finalized setup differs from its saved signed bytes",
            ));
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
        if account(&*self.rpc, receipt, None)?.is_some() {
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
        let simulation = self.rpc.call(
            "simulateTransaction",
            json!([encoded,{"encoding":"base64","sigVerify":true,"commitment":"finalized"}]),
        )?;
        if !simulation["value"]["err"].is_null() || simulation.get("value").is_none() {
            return Err(Error::denied(
                "Native PaySH simulation rejected the exact transaction",
            ));
        }
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
        self.check_execution_packet(prepared, None)?;
        let result = self.rpc.call("sendTransaction", json!([prepared.signed_bytes,{"encoding":"base64","skipPreflight":false,"preflightCommitment":"finalized","maxRetries":0}]))?;
        if result.as_str() != Some(&prepared.signature) {
            return Err(Error::uncertain(
                "RPC returned a different signature; reconcile the saved packet",
            ));
        }
        Ok(())
    }
    pub fn finalized(&self, prepared: &PreparedExecution) -> Result<bool> {
        verify_packet(prepared)?;
        let statuses = self.rpc.call(
            "getSignatureStatuses",
            json!([[prepared.signature],{"searchTransactionHistory":true}]),
        )?;
        let s = &statuses["value"][0];
        if s.is_null() || s["confirmationStatus"] != "finalized" {
            return Ok(false);
        }
        if !s["err"].is_null() {
            return Err(Error::denied(
                "PaySH transaction finalized with an execution error",
            ));
        }
        let tx = self.rpc.call("getTransaction", json!([prepared.signature,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}]))?;
        if tx.is_null() {
            return Ok(false);
        }
        if !tx["meta"]["err"].is_null()
            || tx["transaction"][1] != "base64"
            || tx["transaction"][0] != prepared.signed_bytes
        {
            return Err(Error::config(
                "Finalized PaySH transaction differs from the saved exact packet",
            ));
        }
        self.check_execution_packet(prepared, Some(&tx["meta"]))?;
        let a = account(&*self.rpc, prepared.receipt, s["slot"].as_u64())?
            .ok_or_else(|| Error::config("Finalized execution has no receipt"))?;
        let r = Receipt::try_from_slice(&a.data)
            .map_err(|_| Error::config("Invalid execution receipt"))?;
        let request: Request = borsh::from_slice(
            &STANDARD
                .decode(&prepared.request_bytes)
                .map_err(|_| Error::config("Invalid saved request"))?,
        )
        .map_err(|_| Error::config("Invalid saved request"))?;
        if a.owner != self.deployment.program
            || r.version != 1
            || r.request_hash != prepared.request_hash
            || r.operation_id != request.operation_id
            || r.signing_timestamp != request.signing_timestamp
        {
            return Err(Error::config("Receipt does not bind this policy execution"));
        }
        Ok(true)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn checked_budgets_cannot_wrap() {
        assert!(bounded_sum(u64::MAX, 1, u64::MAX).is_err());
        assert!(bounded_sum(7, 4, 10).is_err());
        assert!(bounded_sum(7, 3, 10).is_ok());
    }
}
