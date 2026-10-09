//! Bounded file ingress. The eventual command decodes directly into canonical SDK DTOs.
use crate::error::{Error, Result};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

pub(crate) const MAX_REQUEST_BYTES: usize = 65_536;
pub(crate) const MAX_JSON_DEPTH: usize = 48;
pub(crate) const MAX_JSON_ITEMS: usize = 4096;

/// Read an explicitly selected local regular file. Never resolve paths embedded in JSON.
pub(crate) fn read_request_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let initial =
        std::fs::metadata(path).map_err(|_| Error::usage("Cannot read request file metadata."))?;
    if !initial.is_file() {
        return Err(Error::usage(
            "The request path must name a local regular file.",
        ));
    }
    let file = File::open(path).map_err(|_| Error::usage("Cannot open the request file."))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::usage("Cannot read request file metadata."))?;
    if !metadata.is_file() {
        return Err(Error::usage(
            "The request path must name a local regular file.",
        ));
    }
    if metadata.len() > MAX_REQUEST_BYTES as u64 {
        return Err(Error::usage("The request file exceeds 65536 bytes."));
    }
    decode_reader(file)
}

/// Exact version-1 operation nonce. Preserve the caller's policy and request ID bytes.
pub(crate) fn operation_nonce(policy_id: &str, request_id: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"allowit-workflow-operation-v1");
    hash.update([0]);
    hash.update(policy_id.as_bytes());
    hash.update([0]);
    hash.update(request_id.as_bytes());
    hash.finalize().into()
}

fn decode_reader<T: DeserializeOwned>(reader: impl Read) -> Result<T> {
    // The stream cap also protects against a file that grows after the metadata check.
    let mut bytes = Vec::with_capacity(4096);
    reader
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::usage("Cannot read the request file."))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(Error::usage("The request file exceeds 65536 bytes."));
    }
    structural_bounds(&bytes)?;
    // Do not collapse objects into Value. Canonical struct deserialization rejects duplicate fields.
    // Suppress deserializer details: they can contain private request field values.
    let mut decoder = serde_json::Deserializer::from_slice(&bytes);
    let request = T::deserialize(&mut decoder)
        .map_err(|_| Error::usage("The request file does not match the typed request schema."))?;
    decoder
        .end()
        .map_err(|_| Error::usage("The request file must contain exactly one JSON object."))?;
    Ok(request)
}

/// Bound containers and field/entry separators before any recursive JSON deserialization.
fn structural_bounds(bytes: &[u8]) -> Result<()> {
    let mut depth = 0usize;
    let mut items = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut first = None;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        if !byte.is_ascii_whitespace() && first.is_none() {
            first = Some(byte);
        }
        match byte {
            b'"' => quoted = true,
            b'{' | b'[' => {
                depth += 1;
                items += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(Error::usage("The request file exceeds 48 nesting levels."));
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            b':' | b',' => {
                items += 1;
            }
            _ => {}
        }
        if items > MAX_JSON_ITEMS {
            return Err(Error::usage(
                "The request file contains too many JSON entries.",
            ));
        }
    }
    if first != Some(b'{') {
        return Err(Error::usage("The request file must contain a JSON object."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    // Test-only shape: production will use the canonical SDK DTO without Value preprocessing.
    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Request {
        name: String,
        child: Option<Box<Request>>,
    }
    fn parse(raw: &str) -> Result<Request> {
        decode_reader(raw.as_bytes())
    }
    #[test]
    fn preserves_unicode_and_escaped_container_characters() {
        let value = parse(r#"{"name":"雪 🌟 [{\\\"","child":null}"#).unwrap();
        assert!(value.name.starts_with("雪 🌟"));
    }
    #[test]
    fn canonical_deserializer_rejects_duplicate_fields_before_value_collapse() {
        assert!(parse(r#"{"name":"a","name":"b","child":null}"#).is_err());
        assert!(parse(r#"{"name":"a","child":{"name":"b","name":"c","child":null}}"#).is_err());
    }
    #[test]
    fn rejects_unknown_fields_without_echoing_private_values() {
        let error = parse(r#"{"name":"a","child":null,"outcome":"private-sentinel"}"#).unwrap_err();
        assert!(!error.message.contains("private-sentinel"));
    }
    #[test]
    fn rejects_trailing_objects_and_nonobjects() {
        assert!(parse(r#"{"name":"a","child":null}{}"#).is_err());
        assert!(parse("[]").is_err());
    }
    #[test]
    fn bounds_bytes_even_without_file_metadata() {
        let raw = format!(
            "{{\"name\":\"{}\",\"child\":null}}",
            "x".repeat(MAX_REQUEST_BYTES)
        );
        assert!(parse(&raw).unwrap_err().message.contains("65536"));
    }
    #[test]
    fn bounds_nesting_before_recursive_decode() {
        let raw = format!(
            "{{\"name\":{}{}{} }}",
            "[".repeat(MAX_JSON_DEPTH),
            "0",
            "]".repeat(MAX_JSON_DEPTH)
        );
        assert!(parse(&raw).unwrap_err().message.contains("nesting"));
    }
    #[test]
    fn bounds_large_flat_arrays_before_decode() {
        let raw = format!("{{\"name\":[{}]}}", vec!["0"; MAX_JSON_ITEMS + 1].join(","));
        assert!(parse(&raw).unwrap_err().message.contains("entries"));
    }
    #[test]
    fn exact_backend_golden_nonce_preserves_case_and_separators() {
        // Canonical backend encoding vector v1; public synthetic identity, not authorization.
        let expected = [
            12, 57, 238, 90, 29, 91, 223, 216, 248, 190, 15, 1, 76, 25, 43, 108, 77, 109, 38, 121,
            244, 115, 120, 219, 133, 162, 59, 202, 151, 160, 251, 18,
        ];
        assert_eq!(
            operation_nonce("owner-policy_Example-A", "cli-native-transfer-01"),
            expected
        );
        assert_ne!(
            operation_nonce("owner-policy_example-a", "cli-native-transfer-01"),
            expected
        );
        assert_ne!(
            operation_nonce("owner-policy_Example-A", "cli-native-transfer-01 "),
            expected
        );
    }
    #[test]
    fn reads_only_explicit_local_regular_file() {
        let path = std::env::temp_dir().join(format!(
            "allowit-request-reader-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"name":"retained","child":null}"#).unwrap();
        assert_eq!(
            read_request_file::<Request>(&path).unwrap().name,
            "retained"
        );
        std::fs::remove_file(path).unwrap();
        assert!(read_request_file::<Request>(&std::env::temp_dir()).is_err());
    }
}
