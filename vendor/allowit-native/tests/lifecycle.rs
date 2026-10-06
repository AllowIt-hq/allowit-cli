//! Deterministic transport fault and proof tests. Synthetic keys; no network.
use allowit_native::{
    client::{Config, Deployment, LOADER, NativeClient},
    crypto::{Key, LocalSigner},
    error::{Error, Result},
    journal::FileJournal,
    lifecycle::{NativeOperations, PolicyLifecycle, Record, validate_record},
    native::{Options, Prepared, State},
    policy::Policy,
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
            policy,
            journal,
            directory,
        }
    }
    fn options(&self, amount: &str) -> Options {
        Options {
            amount: Some(amount.into()),
            recipient: Some(self.owner.public_key()),
            ..Options::default()
        }
    }
    fn life(&self) -> PolicyLifecycle<'_> {
        PolicyLifecycle::new(self, &self.journal)
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
                Ok(if role == "executor" {
                    self.executor.sign(&tx.message)
                } else {
                    self.owner.sign(&tx.message)
                })
            },
        )
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
            abi: 1,
            source_bundle: policy.source_bundle.clone(),
            policy_artifact: policy.policy_artifact.clone(),
            vault_id: policy.id.clone(),
            daily_limit: "5000000".into(),
            spent: "0".into(),
            spent_day: "0".into(),
            nonce: d.nonce.clone(),
            revision: d.revision.clone(),
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
    assert_eq!(count.load(Ordering::Relaxed), 1);
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
    let mut changed = record.clone();
    changed.signed_bytes =
        base64::engine::general_purpose::STANDARD.encode(tx.signed(sig).unwrap());
    changed.signature = bs58::encode(sig).into_string();
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
    assert_eq!(
        f.life()
            .recover(&record.id, &f.policy, f.owner.public_key())
            .unwrap()
            .status,
        "settled"
    );
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
