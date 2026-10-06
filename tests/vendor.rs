//! Offline integrity check for the exact canonical SDK crate source snapshot.
use sha2::{Digest, Sha256};
#[test]
fn native_sdk_source_is_pinned() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("vendor/native-sdk.json")).unwrap())
            .unwrap();
    let commit = source["commit"].as_str().unwrap();
    assert_eq!(commit.len(), 40);
    assert!(commit.bytes().all(|c| c.is_ascii_hexdigit()));
    let files = source["files"].as_object().unwrap();
    for (name, expected) in files {
        let path = std::path::Path::new(name);
        assert!(!path.is_absolute());
        assert!(
            path.components()
                .all(|c| !matches!(c, std::path::Component::ParentDir))
        );
        let bytes = std::fs::read(root.join("vendor/allowit-native").join(path)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            expected.as_str().unwrap(),
            "{name}"
        );
    }
    fn inventory(
        root: &std::path::Path,
        current: &std::path::Path,
        names: &mut std::collections::BTreeSet<String>,
    ) {
        for entry in std::fs::read_dir(current).unwrap() {
            let path = entry.unwrap().path();
            let info = std::fs::symlink_metadata(&path).unwrap();
            assert!(!info.file_type().is_symlink());
            if info.is_dir() {
                inventory(root, &path, names);
            } else {
                assert!(info.is_file());
                names.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/"),
                );
            }
        }
    }
    let vendor = root.join("vendor/allowit-native");
    let mut names = std::collections::BTreeSet::new();
    inventory(&vendor, &vendor, &mut names);
    assert_eq!(names, files.keys().cloned().collect());
}
