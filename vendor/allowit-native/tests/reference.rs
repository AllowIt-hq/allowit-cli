//! The retained JavaScript fixture is an ABI-v1 proof corpus. ABI v2 changes
//! the vault PDA seed, state identity, instruction bytes, and signer set, so an
//! old proof must fail closed rather than be reinterpreted as a current proof.
use allowit_native::policy::Policy;
use allowit_native::{
    crypto::Key,
    native::COMPUTE_BUDGET_PROGRAM,
    transaction::{Signed, Transaction},
};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

#[test]
fn abi_v1_js_sdk_saved_operations_are_explicitly_incompatible() {
    let fixture: Value = serde_json::from_str(include_str!("reference.json")).unwrap();
    assert_eq!(fixture["policy"]["version"], 1);
    assert_eq!(fixture["policy"]["profile"], "solana-native-v1");
    assert!(serde_json::from_value::<Policy>(fixture["policy"].clone()).is_err());
}

#[derive(Deserialize)]
struct CodecFixture {
    source: String,
    setup: CodecTransaction,
    execute: ExecuteTransaction,
}
#[derive(Deserialize)]
struct CodecTransaction {
    payer: Key,
    message: String,
    signed: String,
    bytes: usize,
}
#[derive(Deserialize)]
struct ExecuteTransaction {
    payer: Key,
    authority: Key,
    message: String,
    partial: String,
    signed: String,
    bytes: usize,
}
fn decode(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap()
}

#[test]
fn official_web3_codec_matches_setup_and_cosigner_layout() {
    let fixture: CodecFixture =
        serde_json::from_str(include_str!("v2-codec-reference.json")).unwrap();
    assert_eq!(fixture.source, "@solana/web3.js 1.98.4");

    let setup_raw = decode(&fixture.setup.signed);
    assert_eq!(setup_raw.len(), fixture.setup.bytes);
    assert!(setup_raw.len() <= 1232);
    let setup = Signed::parse(&setup_raw).unwrap();
    assert_eq!(setup.keys[0].key, fixture.setup.payer);
    assert_eq!(setup.message, decode(&fixture.setup.message));
    assert_eq!(setup.instructions.len(), 6);
    let compute = Key::parse(COMPUTE_BUDGET_PROGRAM).unwrap();
    assert_eq!(setup.instructions[0].program, compute);
    assert_eq!(setup.instructions[1].program, compute);
    assert_eq!(setup.instructions[3].data[0], 0);
    assert_eq!(setup.instructions[4].data[0], 1);
    assert_eq!(setup.instructions[5].data[0], 2);
    let expected = Transaction::new(
        fixture.setup.payer,
        setup.blockhash,
        setup.instructions.clone(),
    )
    .unwrap();
    setup.matches(&expected).unwrap();

    let partial_raw = decode(&fixture.execute.partial);
    assert!(Signed::parse(&partial_raw).is_err());
    let partial = Signed::parse_partial(&partial_raw).unwrap();
    assert_eq!(partial.message, decode(&fixture.execute.message));
    assert_eq!(partial.signature(fixture.execute.payer), None);
    assert!(partial.signature(fixture.execute.authority).is_some());
    let signed_raw = decode(&fixture.execute.signed);
    assert_eq!(signed_raw.len(), fixture.execute.bytes);
    assert!(signed_raw.len() <= 1232);
    let signed = Signed::parse(&signed_raw).unwrap();
    assert_eq!(signed.message, partial.message);
    let expected = Transaction::new(
        fixture.execute.payer,
        signed.blockhash,
        signed.instructions.clone(),
    )
    .unwrap();
    signed.matches(&expected).unwrap();
    assert_eq!(
        expected
            .partially_signed(&[(
                fixture.execute.authority,
                partial.signature(fixture.execute.authority).unwrap(),
            )])
            .unwrap(),
        partial_raw
    );
    assert_eq!(
        expected
            .add_signature(
                &partial_raw,
                fixture.execute.payer,
                signed.signature(fixture.execute.payer).unwrap(),
            )
            .unwrap(),
        signed_raw
    );
}
