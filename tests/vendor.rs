//! Offline integrity check for the pinned SDK submodule, through the one
//! verifier shared with provenance and license packaging.
#[test]
fn native_sdk_submodule_is_pinned() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts/sync-native-sdk.py"))
        .arg("verify")
        .output()
        .expect("python3 is required to verify the SDK submodule");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
