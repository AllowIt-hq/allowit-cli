//! Golden saved proofs produced by the pinned JavaScript SDK, not this codec.
use allowit_native::{
    client::{Config, NativeClient},
    crypto::Key,
    error::Result,
    lifecycle::{Record, validate_record},
    native::Options,
    policy::Policy,
    rpc::Rpc,
    transaction::Transaction,
};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
struct Offline;
impl Rpc for Offline {
    fn call(&self, _: &str, _: Value) -> Result<Value> {
        panic!("Saved proof verification must be offline")
    }
}
#[derive(Deserialize)]
struct Fixture {
    config: FixtureConfig,
    owner: Key,
    policy: Policy,
    records: Vec<Record>,
}
#[derive(Deserialize)]
struct FixtureConfig {
    network: String,
    mint: Key,
    executor: Key,
    deployment: allowit_native::client::Deployment,
}
#[test]
fn all_js_sdk_saved_operations_recover_with_native_codec() {
    let f: Fixture = serde_json::from_str(include_str!("reference.json")).unwrap();
    f.policy.validate().unwrap();
    let sdk = NativeClient::new(
        Config {
            network: f.config.network,
            mint: Some(f.config.mint),
            executor: Some(f.config.executor),
            deployment: Some(f.config.deployment),
        },
        Arc::new(Offline),
    )
    .unwrap();
    assert_eq!(f.records.len(), 6);
    for record in f.records {
        let proof = validate_record(&sdk, &f.policy, f.owner, &record).unwrap();
        let intent: Value = serde_json::from_str(&record.intent).unwrap();
        let options = Options {
            amount: intent["amount"].as_str().map(str::to_owned),
            recipient: intent["recipient"].as_str().map(|k| Key::parse(k).unwrap()),
            ..Options::default()
        };
        let b = sdk.public_binding(&f.policy, f.owner).unwrap();
        let tx = Transaction::new(
            if record.method == "execute" {
                b.executor
            } else {
                b.owner
            },
            record.blockhash,
            sdk.expected_instructions(
                &f.policy,
                &b,
                &record.method,
                &options,
                record.nonce.as_deref(),
                record.revision.as_deref(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            tx.message, proof.message,
            "{} must remain readable by the original JavaScript validator",
            record.method
        );
        let signer = allowit_native::crypto::LocalSigner::from_secret(
            &ed25519_dalek::SigningKey::from_bytes(
                &[if record.method == "execute" { 8 } else { 7 }; 32],
            )
            .to_keypair_bytes(),
        )
        .unwrap();
        let raw = tx.signed(signer.sign(&tx.message)).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(raw),
            record.signed_bytes,
            "Rust emits exactly the proof accepted by the JavaScript validator"
        );
    }
}
