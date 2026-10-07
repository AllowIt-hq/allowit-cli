//! Deterministic transport fault and proof tests. Synthetic keys; no network.
use allowit_native::{
    client::{Config, Deployment, LOADER, NativeClient},
    crypto::{Key, LocalSigner},
    error::{Error, Result},
    journal::FileJournal,
    lifecycle::{
        AuthorizedExecution, NativeOperations, PolicyLifecycle, Record, intent_for,
        reconcile_record, validate_record,
    },
    native::{
        ApprovalCommitment, ApprovalRequest, ExecutionRequestIdentity, Options, Prepared,
        Simulation, State,
    },
    policy::{Policy, digest, units},
    release,
    rpc::Rpc,
    transaction::{Signed, Transaction},
};
use base64::Engine;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
struct Network {
    height: u64,
    block_height: u64,
    nonce: String,
    revision: String,
    sends: Vec<String>,
    receipt: Value,
    status: String,
    refreshed_status: Option<String>,
    blockhash_valid: bool,
    processed_blockhash_valid: Option<bool>,
}
struct FakeRpc {
    data: Mutex<Network>,
    journal: std::path::PathBuf,
}
impl Rpc for FakeRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut d = self.data.lock().unwrap();
        Ok(match method {
            "getBlockHeight" => json!(d.height),
            "isBlockhashValid" => {
                let valid = if params[1]["commitment"] == "processed" {
                    assert_eq!(params[1]["minContextSlot"], 99);
                    d.processed_blockhash_valid.unwrap_or(d.blockhash_valid)
                } else {
                    assert_eq!(params[1]["commitment"], "finalized");
                    d.blockhash_valid
                };
                json!({"value":valid,"context":{"slot":99}})
            }
            "getSlot" => json!(99),
            "getBlock" => {
                assert_eq!(params[1]["transactionDetails"], "none");
                assert_eq!(params[1]["rewards"], false);
                json!({"blockHeight":d.block_height})
            }
            "getTransaction" => d.receipt.clone(),
            "sendTransaction" => {
                assert_eq!(params[1]["skipPreflight"], false);
                assert_eq!(params[1]["maxRetries"], 0);
                let j = FileJournal::new(&self.journal);
                let records = j.entries::<Record>()?;
                assert!(records.iter().any(|r| r.signed_bytes == params[0]));
                assert!(j.read::<Value>("last")?.is_some());
                d.sends.push(params[0].as_str().unwrap().into());
                return Err(Error::uncertain("response lost"));
            }
            _ => panic!("Unexpected RPC {method}"),
        })
    }
}
struct Fixture {
    sdk: NativeClient,
    rpc: Arc<FakeRpc>,
    owner: LocalSigner,
    executor: LocalSigner,
    authority: LocalSigner,
    policy: Policy,
    journal: FileJournal,
    directory: std::path::PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Fixture {
    fn new() -> Self {
        let signer = |n| {
            LocalSigner::from_secret(
                &ed25519_dalek::SigningKey::from_bytes(&[n; 32]).to_keypair_bytes(),
            )
            .unwrap()
        };
        let owner = signer(7);
        let executor = signer(8);
        let authority = signer(9);
        let directory =
            std::env::temp_dir().join(format!("allowit-native-life-{}", uuid::Uuid::new_v4()));
        let journal = FileJournal::new(&directory);
        let rpc = Arc::new(FakeRpc {
            data: Mutex::new(Network {
                height: 10,
                block_height: 10,
                nonce: "0".into(),
                revision: "1".into(),
                sends: vec![],
                receipt: Value::Null,
                status: "uncertain".into(),
                refreshed_status: None,
                blockhash_valid: false,
                processed_blockhash_valid: None,
            }),
            journal: directory.clone(),
        });
        let policy =
            Policy::generate("solana:testnet", "Spend up to 5 test tokens per day").unwrap();
        let program = Key([2; 32]);
        let data = Key::find_program_address(&[&program.0], Key::parse(LOADER).unwrap())
            .unwrap()
            .0;
        let sdk = NativeClient::new(
            Config {
                network: policy.network.clone(),
                mint: Some(Key([3; 32])),
                executor: Some(executor.public_key()),
                authority: Some(authority.public_key()),
                deployment: Some(Deployment {
                    network: policy.network.clone(),
                    source_bundle: release().source_bundle.clone(),
                    policy: program,
                    policy_data: data,
                    custody: Key([4; 32]),
                }),
            },
            rpc.clone(),
        )
        .unwrap();
        Self {
            sdk,
            rpc,
            owner,
            executor,
            authority,
            policy,
            journal,
            directory,
        }
    }
    fn options(&self, amount: &str) -> Options {
        Options {
            amount: Some(amount.into()),
            recipient: Some(self.owner.public_key()),
            expires_at: Some(200),
            commitment: Some("11".repeat(32)),
            instance_slot: Some(77),
            ..Options::default()
        }
    }
    fn life(&self) -> PolicyLifecycle<'_> {
        PolicyLifecycle::new(self, &self.journal)
    }
    fn identity(&self, id: &str, action: &str) -> ExecutionRequestIdentity {
        ExecutionRequestIdentity::new(
            &self.policy,
            id,
            "1",
            self.owner.public_key(),
            action,
            "fixture merchant",
            &json!({"invoice":"fixed-1"}),
        )
        .unwrap()
    }
    fn authorized(&self, identity: &ExecutionRequestIdentity) -> AuthorizedExecution {
        let owner = self.owner.public_key();
        let state = self
            .state(&self.policy, owner, false, None)
            .unwrap()
            .unwrap();
        let evidence_digest = digest(b"numeric policy evidence");
        let request = ApprovalRequest {
            version: 1,
            operation_id: identity.operation_id.clone(),
            input_digest: identity.digest().unwrap(),
            vault_policy_id: self.policy.id.clone(),
            execution_policy_id: "fixture-numeric-policy".into(),
            execution_policy_digest: self.policy.execution_policy_digest.clone(),
            execution_requirements_digest: self.policy.execution_requirements_digest.clone(),
            execution_policy_revision: 1,
            recipient: identity.recipient,
            amount_units: units(&identity.amount).unwrap(),
            action: identity.action.clone(),
            merchant: identity.merchant.clone(),
            context_hash: identity.context_hash.clone(),
            decision_code: "PASS".into(),
            evidence_digest,
        };
        let approval = ApprovalCommitment::new(
            &self.policy,
            &state,
            &identity.operation_id,
            identity.recipient,
            &identity.amount,
            200,
            &request.digest().unwrap(),
            None,
        )
        .unwrap();
        let options = approval.options().unwrap();
        let prepared = self
            .prepare(&self.policy, owner, "execute", &options)
            .unwrap();
        let partial = prepared
            .transaction
            .partially_signed(&[(
                self.authority.public_key(),
                self.authority.sign(&prepared.transaction.message),
            )])
            .unwrap();
        AuthorizedExecution {
            binding: state.binding,
            request,
            approval,
            intent: intent_for(&self.sdk, &self.policy, owner, "execute", &options).unwrap(),
            message: prepared.transaction.message,
            partial_transaction: partial.clone(),
            blockhash: prepared.blockhash,
            last_valid_block_height: prepared.last_valid_block_height,
            nonce: prepared.nonce.unwrap(),
            revision: prepared.revision.unwrap(),
            simulation: Simulation {
                transaction_bytes: partial.len(),
                ..prepared.simulation
            },
        }
    }
    fn submit(
        &self,
        method: &str,
        options: &Options,
        id: &str,
        count: &AtomicUsize,
    ) -> Result<Record> {
        self.life().submit(
            &self.policy,
            self.owner.public_key(),
            method,
            options,
            Some(id),
            |tx, role| {
                count.fetch_add(1, Ordering::Relaxed);
                Ok(match role {
                    "executor" => self.executor.sign(&tx.message),
                    "authority" => self.authority.sign(&tx.message),
                    _ => self.owner.sign(&tx.message),
                })
            },
        )
    }
}

#[test]
fn authority_partial_is_validated_completed_and_retried_without_reapproval() {
    let f = Fixture::new();
    let identity = f.identity("authorized-request-001", "fetch fixed fixture");
    let approvals = AtomicUsize::new(0);
    let signatures = AtomicUsize::new(0);
    let result = f
        .life()
        .submit_authorized(
            &f.policy,
            f.owner.public_key(),
            &identity,
            || {
                approvals.fetch_add(1, Ordering::Relaxed);
                Ok(f.authorized(&identity))
            },
            |transaction| {
                signatures.fetch_add(1, Ordering::Relaxed);
                Ok(f.executor.sign(&transaction.message))
            },
        )
        .unwrap();
    assert_eq!(result.status, "uncertain");
    assert_eq!(approvals.load(Ordering::Relaxed), 1);
    assert_eq!(signatures.load(Ordering::Relaxed), 1);
    assert_eq!(result.signatures.len(), 2);
    assert_eq!(
        result.extra["executionRequestDigest"],
        identity.digest().unwrap()
    );
    let proof = Signed::parse(
        &base64::engine::general_purpose::STANDARD
            .decode(&result.signed_bytes)
            .unwrap(),
    )
    .unwrap();
    assert!(proof.signature(f.executor.public_key()).is_some());
    assert!(proof.signature(f.authority.public_key()).is_some());

    let replay = f
        .life()
        .submit_authorized(
            &f.policy,
            f.owner.public_key(),
            &identity,
            || Err(Error::config("authorization must not be called on retry")),
            |_| Err(Error::config("executor must not resign on retry")),
        )
        .unwrap();
    assert_eq!(replay.extra["replayed"], true);
    assert_eq!(replay.signed_bytes, result.signed_bytes);

    let changed = f.identity("authorized-request-001", "different action");
    assert!(
        f.life()
            .submit_authorized(
                &f.policy,
                f.owner.public_key(),
                &changed,
                || {
                    Err(Error::config(
                        "authorization must not be called on conflict",
                    ))
                },
                |_| Err(Error::config("executor must not sign on conflict")),
            )
            .err()
            .unwrap()
            .message
            .contains("conflict")
    );
}

#[test]
fn authority_partial_rejects_changed_envelope_message_and_signer_slots() {
    for index in 0..3 {
        let f = Fixture::new();
        let identity = f.identity(
            &format!("rejected-authority-{index:03}"),
            "fetch fixed fixture",
        );
        let mut response = f.authorized(&identity);
        match index {
            0 => response.request.action = "changed action".into(),
            1 => response.message[0] ^= 1,
            _ => {
                let parsed = Signed::parse_partial(&response.partial_transaction).unwrap();
                let transaction = Transaction::new(
                    f.executor.public_key(),
                    response.blockhash,
                    parsed.instructions,
                )
                .unwrap();
                response.partial_transaction = transaction
                    .partially_signed(&[(
                        f.executor.public_key(),
                        f.executor.sign(&transaction.message),
                    )])
                    .unwrap();
                response.message = transaction.message;
                response.simulation.transaction_bytes = response.partial_transaction.len();
            }
        }
        assert!(
            f.life()
                .submit_authorized(
                    &f.policy,
                    f.owner.public_key(),
                    &identity,
                    || Ok(response.clone()),
                    |transaction| Ok(f.executor.sign(&transaction.message)),
                )
                .is_err()
        );
        assert!(f.journal.entries::<Record>().unwrap().is_empty());
    }
}
impl NativeOperations for Fixture {
    fn client(&self) -> &NativeClient {
        &self.sdk
    }
    fn verify_release(&self, _: bool) -> Result<()> {
        Ok(())
    }
    fn status(&self, signature: &str) -> Result<Value> {
        let mut data = self.rpc.data.lock().unwrap();
        let status = data.status.clone();
        if let Some(next) = data.refreshed_status.take() {
            data.status = next;
        }
        Ok(
            json!({"status":status,"signature":signature,"transactionUrl":self.sdk.transaction_url(signature)?}),
        )
    }
    fn state(
        &self,
        policy: &Policy,
        owner: Key,
        _: bool,
        min: Option<u64>,
    ) -> Result<Option<State>> {
        assert!(min.is_none() || min == Some(99));
        let d = self.rpc.data.lock().unwrap();
        Ok(Some(State {
            binding: self.sdk.public_binding(policy, owner)?,
            abi: 2,
            source_bundle: policy.source_bundle.clone(),
            policy_artifact: policy.policy_artifact.clone(),
            vault_id: policy.id.clone(),
            daily_limit: "5000000".into(),
            action_limit: "5000000".into(),
            spent: "0".into(),
            spent_day: "0".into(),
            nonce: d.nonce.clone(),
            revision: d.revision.clone(),
            instance_slot: "77".into(),
            approved: true,
            balance: "10000000".into(),
        }))
    }
    fn prepare(
        &self,
        policy: &Policy,
        owner: Key,
        method: &str,
        options: &Options,
    ) -> Result<Prepared> {
        let d = self.rpc.data.lock().unwrap();
        let binding = self.sdk.public_binding(policy, owner)?;
        let blockhash = Key([9; 32]);
        let instructions = self.sdk.expected_instructions(
            policy,
            &binding,
            method,
            options,
            Some(&d.nonce),
            Some(&d.revision),
        )?;
        Ok(Prepared {
            transaction: Transaction::new(
                if method == "execute" {
                    binding.executor
                } else {
                    binding.owner
                },
                blockhash,
                instructions,
            )?,
            simulation: Simulation {
                context_slot: 99,
                units_consumed: 10_000,
                transaction_bytes: 500,
            },
            nonce: Some(d.nonce.clone()),
            revision: Some(d.revision.clone()),
            last_valid_block_height: 100,
            blockhash,
        })
    }
}
#[test]
fn owner_expiry_refreshes_lagging_status_before_allowing_addition() {
    let f = Fixture::new();
    let count = AtomicUsize::new(0);
    let options = Options {
        amount: Some("1".into()),
        ..Options::default()
    };
    let record = f
        .submit("fund", &options, "stale-owner-001", &count)
        .unwrap();
    {
        let mut data = f.rpc.data.lock().unwrap();
        data.height = 101;
        data.block_height = 101;
        data.refreshed_status = Some("failed".into());
    }
    let recovered = f
        .life()
        .recover(&record.id, &f.policy, f.owner.public_key())
        .unwrap();
    assert_eq!(recovered.status, "failed");
    assert!(!recovered.expired());
}
#[test]
fn lost_response_keeps_exact_proof_blocks_new_spend_and_never_resigns() {
    let f = Fixture::new();
    let count = AtomicUsize::new(0);
    let options = f.options("1");
    let first = f
        .submit("execute", &options, "same-request-001", &count)
        .unwrap();
    assert_eq!(first.status, "uncertain");
    let retry = f
        .submit("execute", &f.options("1.0"), "same-request-001", &count)
        .unwrap();
    assert_eq!(retry.extra["replayed"], true);
    assert_eq!(count.load(Ordering::Relaxed), 2);
    {
        let d = f.rpc.data.lock().unwrap();
        assert_eq!(d.sends.len(), 2);
        assert_eq!(d.sends[0], d.sends[1]);
    }
    assert!(
        f.submit("execute", &f.options("2"), "same-request-001", &count)
            .err()
            .unwrap()
            .message
            .contains("conflict")
    );
    assert!(
        f.submit("execute", &options, "next-request-001", &count)
            .err()
            .unwrap()
            .message
            .contains("uncertain")
    );
    {
        let mut d = f.rpc.data.lock().unwrap();
        d.height = 101;
        d.block_height = 101;
        d.nonce = "1".into();
    }
    let expired = f
        .life()
        .recover(&first.id, &f.policy, f.owner.public_key())
        .unwrap();
    assert_eq!(expired.status, "uncertain");
    assert!(expired.expired());
    assert_eq!(f.rpc.data.lock().unwrap().sends.len(), 2);
}
#[test]
fn expiry_needs_coherent_height_and_unchanged_nonce_even_after_revision() {
    let f = Fixture::new();
    let count = AtomicUsize::new(0);
    let record = f
        .submit("execute", &f.options("1"), "expiry-request-001", &count)
        .unwrap();
    {
        let mut d = f.rpc.data.lock().unwrap();
        d.height = 101;
        d.block_height = 100;
        d.revision = "2".into();
    }
    assert_eq!(
        f.life()
            .recover(&record.id, &f.policy, f.owner.public_key())
            .unwrap()
            .status,
        "uncertain"
    );
    f.rpc.data.lock().unwrap().block_height = 101;
    let expired = f
        .life()
        .recover(&record.id, &f.policy, f.owner.public_key())
        .unwrap();
    assert_eq!(expired.status, "failed");
    assert_eq!(expired.extra["decisionCode"], "EXPIRED_UNEXECUTED");
    assert_eq!(expired.extra["absence"]["revision"], "2");
    assert_eq!(
        f.life()
            .recover(&record.id, &f.policy, f.owner.public_key())
            .unwrap()
            .status,
        "failed"
    );
}
#[test]
fn owner_expiry_does_not_infer_absence_and_additional_operation_is_explicit() {
    for method in ["fund", "withdraw"] {
        let f = Fixture::new();
        let count = AtomicUsize::new(0);
        let options = Options {
            amount: Some("1".into()),
            ..Options::default()
        };
        let first = f
            .submit(method, &options, "owner-request-001", &count)
            .unwrap();
        {
            let mut d = f.rpc.data.lock().unwrap();
            d.height = 101;
            d.block_height = 101;
        }
        let expired = f
            .life()
            .recover(&first.id, &f.policy, f.owner.public_key())
            .unwrap();
        assert!(expired.expired());
        assert_eq!(expired.status, "uncertain");
        assert!(
            f.submit(method, &options, "additional-owner-001", &count)
                .is_err()
        );
        let options = Options {
            additional_owner_operation: true,
            ..options
        };
        let second = f
            .submit(method, &options, "additional-owner-001", &count)
            .unwrap();
        assert_eq!(second.status, "uncertain");
        assert_eq!(
            f.journal
                .read::<Record>("request-owner-request-001")
                .unwrap()
                .unwrap()
                .signed_bytes,
            first.signed_bytes
        );
    }
}
#[test]
fn superseded_expired_owner_proof_retains_bytes_without_blocking_future_operations() {
    for method in ["fund", "withdraw"] {
        let f = Fixture::new();
        let count = AtomicUsize::new(0);
        let options = Options {
            amount: Some("1".into()),
            ..Options::default()
        };
        let first = f
            .submit(method, &options, "old-owner-request", &count)
            .unwrap();
        {
            let mut d = f.rpc.data.lock().unwrap();
            d.height = 101;
            d.block_height = 101;
        }
        let override_options = Options {
            additional_owner_operation: true,
            ..options.clone()
        };
        assert!(
            f.life()
                .submit(
                    &f.policy,
                    f.owner.public_key(),
                    method,
                    &override_options,
                    Some("cancelled-owner-request"),
                    |_, _| Err(Error::config("Signer cancelled"))
                )
                .is_err()
        );
        assert!(
            !f.journal
                .read::<Record>("request-old-owner-request")
                .unwrap()
                .unwrap()
                .extra
                .contains_key("supersededBy")
        );
        let second = f
            .submit(
                method,
                &override_options,
                "additional-owner-request",
                &count,
            )
            .unwrap();
        let old = f
            .journal
            .read::<Record>("request-old-owner-request")
            .unwrap()
            .unwrap();
        assert_eq!(old.signed_bytes, first.signed_bytes);
        assert_eq!(old.extra["supersededBy"], second.id);
        assert_eq!(old.status, "uncertain");
        // Even a supersession marker cannot bypass an unresolved successor.
        {
            let mut d = f.rpc.data.lock().unwrap();
            d.height = 10;
            d.block_height = 10;
        }
        assert!(
            f.submit(method, &options, "third-owner-request", &count)
                .is_err()
        );
        assert_eq!(count.load(Ordering::Relaxed), 2);
        {
            let mut d = f.rpc.data.lock().unwrap();
            d.status = "settled".into();
            d.receipt = json!({"transaction":[second.signed_bytes,"base64"],"meta":{"err":null}});
        }
        let third_options = Options {
            amount: Some("2".into()),
            ..Options::default()
        };
        let third = f
            .submit(method, &third_options, "third-owner-request", &count)
            .unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 3);
        assert_ne!(third.signed_bytes, second.signed_bytes);
        assert_eq!(
            f.journal
                .read::<Record>("request-old-owner-request")
                .unwrap()
                .unwrap()
                .signed_bytes,
            first.signed_bytes
        );
    }
}
#[test]
fn saved_proof_cannot_change_amount_signature_or_context() {
    let f = Fixture::new();
    let count = AtomicUsize::new(0);
    let record = f
        .submit("execute", &f.options("1"), "integrity-request", &count)
        .unwrap();
    validate_record(&f.sdk, &f.policy, f.owner.public_key(), &record).unwrap();
    let b = f
        .sdk
        .public_binding(&f.policy, f.owner.public_key())
        .unwrap();
    let tx = Transaction::new(
        b.executor,
        record.blockhash,
        f.sdk
            .expected_instructions(
                &f.policy,
                &b,
                "execute",
                &f.options("2"),
                Some("0"),
                Some("1"),
            )
            .unwrap(),
    )
    .unwrap();
    let sig = f.executor.sign(&tx.message);
    let authority_sig = f.authority.sign(&tx.message);
    let mut changed = record.clone();
    changed.signed_bytes = base64::engine::general_purpose::STANDARD.encode(
        tx.signed_by(&[
            (f.executor.public_key(), sig),
            (f.authority.public_key(), authority_sig),
        ])
        .unwrap(),
    );
    changed.signature = bs58::encode(sig).into_string();
    changed.signatures = vec![
        changed.signature.clone(),
        bs58::encode(authority_sig).into_string(),
    ];
    changed.transaction_url = f.sdk.transaction_url(&changed.signature).unwrap();
    assert!(validate_record(&f.sdk, &f.policy, f.owner.public_key(), &changed).is_err());
    let mut config = f.sdk.config.clone();
    config.executor = Some(Key([6; 32]));
    let other = NativeClient::new(config, f.rpc.clone()).unwrap();
    assert!(validate_record(&other, &f.policy, f.owner.public_key(), &record).is_err());
    assert!(!record.public().to_string().contains("signedBytes"));
    assert!(!record.public().to_string().contains("intent"));
}
#[test]
fn orphaned_owner_proof_blocks_a_new_operation_after_slot_write_crash() {
    let f = Fixture::new();
    let count = AtomicUsize::new(0);
    let options = Options {
        amount: Some("1".into()),
        ..Options::default()
    };
    let first = f
        .submit("fund", &options, "orphan-owner-001", &count)
        .unwrap();
    f.journal.clear("owner-slot-fund").unwrap();
    assert!(
        f.submit("fund", &options, "additional-owner-001", &count)
            .is_err()
    );
    assert_eq!(count.load(Ordering::Relaxed), 1);
    assert_eq!(
        f.journal
            .read::<Record>("request-orphan-owner-001")
            .unwrap()
            .unwrap()
            .signed_bytes,
        first.signed_bytes
    );
}
#[test]
fn settled_requires_saved_message_both_cpis_and_exact_token_deltas() {
    let f = Fixture::new();
    let count = AtomicUsize::new(0);
    let record = f
        .submit("execute", &f.options("1"), "receipt-request-001", &count)
        .unwrap();
    let proof = Signed::parse(
        &base64::engine::general_purpose::STANDARD
            .decode(&record.signed_bytes)
            .unwrap(),
    )
    .unwrap();
    let b = f
        .sdk
        .public_binding(&f.policy, f.owner.public_key())
        .unwrap();
    let index = |k| proof.keys.iter().position(|a| a.key == k).unwrap();
    let balance = |account, amount: &str| json!({"accountIndex":index(account),"mint":b.mint.to_string(),"uiTokenAmount":{"amount":amount}});
    let receipt = json!({"transaction":[record.signed_bytes,"base64"],"meta":{"err":null,"innerInstructions":[{"instructions":[{"programIdIndex":index(b.policy)},{"programIdIndex":index(Key::parse(allowit_native::client::TOKEN_PROGRAM).unwrap())}]}],"preTokenBalances":[balance(b.token_account,"2000000"),balance(f.owner.public_key(),"0")],"postTokenBalances":[balance(b.token_account,"1000000"),balance(f.owner.public_key(),"1000000")]}});
    {
        let mut d = f.rpc.data.lock().unwrap();
        d.status = "settled".into();
        d.receipt = receipt.clone();
    }
    let mut stale = record.clone();
    stale
        .extra
        .insert("error".into(), json!("Earlier failed observation"));
    stale.extra.insert("replayed".into(), json!(true));
    f.journal
        .write(&format!("request-{}", record.id), &stale)
        .unwrap();
    let settled = f
        .life()
        .recover(&record.id, &f.policy, f.owner.public_key())
        .unwrap();
    assert_eq!(settled.status, "settled");
    assert!(!settled.extra.contains_key("error"));
    assert!(!settled.extra.contains_key("replayed"));
    f.rpc.data.lock().unwrap().receipt["meta"]["postTokenBalances"][1]["uiTokenAmount"]["amount"] =
        json!("999999");
    assert!(
        f.life()
            .recover(&record.id, &f.policy, f.owner.public_key())
            .err()
            .unwrap()
            .message
            .contains("deltas")
    );
    f.rpc.data.lock().unwrap().receipt = receipt;
    f.rpc.data.lock().unwrap().receipt["meta"]["innerInstructions"] = json!([]);
    assert!(
        f.life()
            .recover(&record.id, &f.policy, f.owner.public_key())
            .err()
            .unwrap()
            .message
            .contains("CPI")
    );
}

#[test]
fn server_reconciliation_requires_no_file_journal_or_signing() {
    let f = Fixture::new();
    let options = f.options("1");
    let owner = f.owner.public_key();
    let prepared = f.prepare(&f.policy, owner, "execute", &options).unwrap();
    let signature = f.executor.sign(&prepared.transaction.message);
    let authority_signature = f.authority.sign(&prepared.transaction.message);
    let signature_text = bs58::encode(signature).into_string();
    let signatures = vec![
        signature_text.clone(),
        bs58::encode(authority_signature).into_string(),
    ];
    let record = Record {
        id: "server-proof-0001".into(),
        intent: intent_for(&f.sdk, &f.policy, owner, "execute", &options).unwrap(),
        method: "execute".into(),
        status: "uncertain".into(),
        signature: signature_text.clone(),
        signatures,
        signed_bytes: base64::engine::general_purpose::STANDARD.encode(
            prepared
                .transaction
                .signed_by(&[
                    (f.executor.public_key(), signature),
                    (f.authority.public_key(), authority_signature),
                ])
                .unwrap(),
        ),
        blockhash: prepared.blockhash,
        last_valid_block_height: prepared.last_valid_block_height,
        nonce: prepared.nonce,
        revision: prepared.revision,
        expires_at: options.expires_at,
        commitment: options.commitment.clone(),
        instance_slot: options.instance_slot.map(|slot| slot.to_string()),
        transaction_url: f.sdk.transaction_url(&signature_text).unwrap(),
        extra: Default::default(),
    };
    assert!(!f.directory.exists());
    let observed = reconcile_record(&f, record.clone(), &f.policy, owner).unwrap();
    assert_eq!(observed.status, "uncertain");
    assert_eq!(observed.signature, record.signature);
    assert_eq!(observed.signed_bytes, record.signed_bytes);
    assert!(!f.directory.exists());
    assert!(f.rpc.data.lock().unwrap().sends.is_empty());
    // A foreign journal's unsigned validity height cannot infer nonexecution
    // while the original signed blockhash can still land.
    let mut low_height = record.clone();
    low_height.last_valid_block_height = 1;
    f.rpc.data.lock().unwrap().blockhash_valid = true;
    let observed = reconcile_record(&f, low_height.clone(), &f.policy, owner).unwrap();
    assert_eq!(observed.status, "uncertain");
    assert!(!observed.expired());
    assert!(!observed.extra.contains_key("absence"));
    f.rpc.data.lock().unwrap().blockhash_valid = false;
    f.rpc.data.lock().unwrap().processed_blockhash_valid = Some(true);
    let observed = reconcile_record(&f, low_height.clone(), &f.policy, owner).unwrap();
    assert_eq!(observed.status, "uncertain");
    assert!(!observed.expired());
    assert!(!observed.extra.contains_key("absence"));
    f.rpc.data.lock().unwrap().processed_blockhash_valid = Some(false);
    let observed = reconcile_record(&f, low_height, &f.policy, owner).unwrap();
    assert_eq!(observed.status, "failed");
    assert_eq!(observed.extra["decisionCode"], "EXPIRED_UNEXECUTED");
    assert!(!f.directory.exists());
    assert!(f.rpc.data.lock().unwrap().sends.is_empty());
    let mut substituted = record;
    substituted.intent = substituted.intent.replace("\"1\"", "\"2\"");
    assert!(reconcile_record(&f, substituted, &f.policy, owner).is_err());
}
