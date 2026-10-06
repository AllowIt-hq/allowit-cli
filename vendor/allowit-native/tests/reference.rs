//! Golden saved proofs produced by the pinned JavaScript SDK, not this codec.
use allowit_native::{
    client::{Config, NativeClient},
    crypto::Key,
    error::Result,
    lifecycle::{Record, validate_record},
    policy::Policy,
    rpc::Rpc,
};
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
        validate_record(&sdk, &f.policy, f.owner, &record).unwrap();
    }
}
