//! Native Tempo 0x76 encoding for self-paid executor calls.
//!
//! This deliberately supports one EOA-signed call with zero native value,
//! protocol nonce key zero, and an explicit fee token. It does not accept
//! sponsorship, access-key authorization, delegation, or additional calls.
use crate::error::{Error, Result};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

const TYPE: u8 = 0x76;
const MAX_CALLDATA_BYTES: usize = 65_536;
const MAX_RAW_BYTES: usize = MAX_CALLDATA_BYTES + 256;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTransaction {
    pub chain_id: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub nonce: u64,
    pub to: String,
    pub data: String,
    pub fee_token: String,
}

/// Signed bytes are an executable authorization; keep them out of diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransaction {
    pub raw: String,
    pub hash: String,
    pub from: String,
}

impl NativeTransaction {
    /// Sign the native transaction digest directly, without EIP-191 wrapping.
    pub fn sign(&self, key: &[u8; 32]) -> Result<SignedTransaction> {
        let fields = self.fields()?;
        let signer = SigningKey::from_bytes(key.into())
            .map_err(|_| Error::config("Invalid Tempo executor signing key"))?;
        let digest = keccak(&typed_payload(&fields, None));
        let (signature, recovery) = signer
            .sign_prehash_recoverable(&digest)
            .map_err(|_| Error::config("Cannot sign the native Tempo transaction"))?;
        if recovery.to_byte() > 1 || signature.normalize_s().is_some() {
            return Err(Error::config("Cannot produce a canonical Tempo signature"));
        }
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        // Tempo's primitive encoder uses Alloy Signature::as_bytes(), whose
        // final byte is Electrum notation (27 + y parity), not EIP-155 v.
        bytes[64] = 27 + recovery.to_byte();
        let raw = typed_payload(&fields, Some(&bytes));
        let signed = SignedTransaction {
            hash: hex(&keccak(&raw)),
            raw: hex(&raw),
            from: public_address(signer.verifying_key())?,
        };
        self.verify(&signed)?;
        Ok(signed)
    }

    /// Bind a persisted authorization to every expected field and its signer.
    ///
    /// Comparing the entire raw envelope with canonical re-encoding also
    /// rejects malformed RLP, extra fields, extra calls and trailing bytes.
    /// No tolerant transaction decoder or alternate transaction type is used.
    pub fn verify(&self, signed: &SignedTransaction) -> Result<()> {
        let fields = self.fields()?;
        let raw = unhex(&signed.raw, MAX_RAW_BYTES)?;
        if raw.len() < 65 {
            return Err(invalid_signed());
        }
        let signature_bytes = &raw[raw.len() - 65..];
        if raw != typed_payload(&fields, Some(signature_bytes)) {
            return Err(invalid_signed());
        }
        let expected_hash = unhex(&signed.hash, 32)?;
        if expected_hash.len() != 32 || expected_hash.as_slice() != keccak(&raw) {
            return Err(invalid_signed());
        }
        let signature =
            Signature::from_slice(&signature_bytes[..64]).map_err(|_| invalid_signed())?;
        if signature.normalize_s().is_some() {
            return Err(invalid_signed());
        }
        let parity = match signature_bytes[64] {
            27 => 0,
            28 => 1,
            _ => return Err(invalid_signed()),
        };
        let recovery = RecoveryId::from_byte(parity).ok_or_else(invalid_signed)?;
        let recovered = VerifyingKey::recover_from_prehash(
            &keccak(&typed_payload(&fields, None)),
            &signature,
            recovery,
        )
        .map_err(|_| invalid_signed())?;
        let expected_from = address(&signed.from)?;
        let actual_from = address(&public_address(&recovered)?)?;
        if expected_from != actual_from {
            return Err(invalid_signed());
        }
        Ok(())
    }

    fn fields(&self) -> Result<Vec<u8>> {
        if self.chain_id == 0
            || self.gas_limit == 0
            || self.max_fee_per_gas == 0
            || self.max_priority_fee_per_gas > self.max_fee_per_gas
        {
            return Err(Error::config("Invalid native Tempo transaction quantities"));
        }
        let to = address(&self.to)?;
        let fee_token = address(&self.fee_token)?;
        let data = unhex(&self.data, MAX_CALLDATA_BYTES)?;
        Ok(encode_fields(self, &to, &data, &fee_token))
    }
}

pub fn executor_address(key: &[u8; 32]) -> Result<String> {
    let signer = SigningKey::from_bytes(key.into())
        .map_err(|_| Error::config("Invalid Tempo executor signing key"))?;
    public_address(signer.verifying_key())
}

fn public_address(key: &VerifyingKey) -> Result<String> {
    let point = key.to_encoded_point(false);
    let coordinates = point
        .as_bytes()
        .get(1..)
        .filter(|bytes| bytes.len() == 64)
        .ok_or_else(|| Error::config("Invalid Tempo executor public key"))?;
    Ok(hex(&keccak(coordinates)[12..]))
}

fn invalid_signed() -> Error {
    Error::config("Native Tempo transaction failed exact envelope and signer verification")
}

fn address(value: &str) -> Result<Vec<u8>> {
    let bytes = unhex(value, 20)?;
    if bytes.len() != 20 || bytes.iter().all(|byte| *byte == 0) {
        return Err(Error::config("Invalid native Tempo account or fee token"));
    }
    Ok(bytes)
}

fn unhex(value: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| Error::config("Invalid native Tempo hexadecimal data"))?;
    if value.len() > max_bytes * 2
        || value.len() % 2 != 0
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::config(
            "Invalid or oversized native Tempo hexadecimal data",
        ));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = nibble(pair[0]);
            let low = nibble(pair[1]);
            Ok((high << 4) | low)
        })
        .collect()
}

// Called only for ASCII hexadecimal bytes checked by unhex.
fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn keccak(value: &[u8]) -> [u8; 32] {
    Keccak256::digest(value).into()
}

// The 13 mandatory fields in canonical Tempo protocol order. There is no
// key-authorization element at all when absent; it is not another empty slot.
fn encode_fields(tx: &NativeTransaction, to: &[u8], data: &[u8], fee_token: &[u8]) -> Vec<u8> {
    let mut fields = Vec::with_capacity(data.len() + 96);
    rlp_number(tx.chain_id.into(), &mut fields);
    rlp_number(tx.max_priority_fee_per_gas, &mut fields);
    rlp_number(tx.max_fee_per_gas, &mut fields);
    rlp_number(tx.gas_limit.into(), &mut fields);
    let mut call = Vec::with_capacity(data.len() + 24);
    rlp_bytes(to, &mut call);
    rlp_number(0, &mut call); // native value
    rlp_bytes(data, &mut call);
    let mut calls = Vec::with_capacity(call.len() + 4);
    rlp_list(&call, &mut calls);
    rlp_list(&calls, &mut fields);
    rlp_list(&[], &mut fields); // access list
    rlp_number(0, &mut fields); // protocol nonce key
    rlp_number(tx.nonce.into(), &mut fields);
    rlp_bytes(&[], &mut fields); // no validBefore
    rlp_bytes(&[], &mut fields); // no validAfter
    rlp_bytes(fee_token, &mut fields);
    rlp_bytes(&[], &mut fields); // self-paid, no fee payer signature
    rlp_list(&[], &mut fields); // no AA authorizations
    fields
}

fn typed_payload(fields: &[u8], signature: Option<&[u8]>) -> Vec<u8> {
    let mut payload = fields.to_vec();
    if let Some(signature) = signature {
        rlp_bytes(signature, &mut payload);
    }
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(TYPE);
    rlp_list(&payload, &mut out);
    out
}

fn rlp_number(value: u128, out: &mut Vec<u8>) {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_bytes(&bytes[first..], out);
}

fn rlp_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        rlp_header(bytes.len(), false, out);
        out.extend_from_slice(bytes);
    }
}

fn rlp_list(payload: &[u8], out: &mut Vec<u8>) {
    rlp_header(payload.len(), true, out);
    out.extend_from_slice(payload);
}

fn rlp_header(length: usize, list: bool, out: &mut Vec<u8>) {
    if length < 56 {
        out.push(if list { 0xc0 } else { 0x80 } + length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        let length_bytes = &bytes[first..];
        out.push(if list { 0xf7 } else { 0xb7 } + length_bytes.len() as u8);
        out.extend_from_slice(length_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction() -> NativeTransaction {
        NativeTransaction {
            chain_id: 42431,
            max_priority_fee_per_gas: 100,
            max_fee_per_gas: 1000,
            gas_limit: 200_000,
            nonce: 9,
            to: "0x1111111111111111111111111111111111111111".into(),
            data: "0x12345678".into(),
            fee_token: "0x20c0000000000000000000000000000000000001".into(),
        }
    }

    fn test_key() -> [u8; 32] {
        // A deterministic unit-test scalar; never a deployed executor key.
        let mut bytes = [0; 32];
        bytes[31] = 1;
        bytes
    }

    #[test]
    fn official_ox_signing_and_wire_vectors() {
        // Published Tempo codec vectors, not a JavaScript runtime dependency:
        // https://github.com/wevm/ox/blob/42a84e64caeb1cb55ed7e36f0135dbc504fcc346/src/tempo/TxEnvelopeTempo.test.ts
        // describe('getSignPayload') and describe('serialize') / secp256k1.
        // This historical minimal codec fixture omits feeToken and gas; the
        // public signer intentionally rejects those production omissions.
        let mut tx = transaction();
        tx.chain_id = 1;
        tx.max_priority_fee_per_gas = 0;
        tx.max_fee_per_gas = 0;
        tx.gas_limit = 0;
        tx.nonce = 0;
        let to = unhex("0x70997970c51812dc3a010c7d01b50e0d17dc79c8", 20).unwrap();
        let fields = encode_fields(&tx, &to, &[], &[]);
        assert_eq!(
            hex(&keccak(&typed_payload(&fields, None))),
            "0xe1222a45806457acbe3a13940aae4c34f3180659fa16613b5a45dc183adae07c"
        );
        let signature = unhex("0x6b37e17bf41d92dfee5ffdce55431bf01dd7875b2229d6258350c5ee6fe6a54225b867dc1b19c9ec97833ebdccd830d2846c5b724b72dcd754d694d08b5e80ee1c", 65).unwrap();
        assert_eq!(
            hex(&typed_payload(&fields, Some(&signature))),
            "0x76f86801808080d8d79470997970c51812dc3a010c7d01b50e0d17dc79c88080c0808080808080c0b8416b37e17bf41d92dfee5ffdce55431bf01dd7875b2229d6258350c5ee6fe6a54225b867dc1b19c9ec97833ebdccd830d2846c5b724b72dcd754d694d08b5e80ee1c"
        );
        assert!(tx.sign(&test_key()).is_err());
    }

    #[test]
    fn canonical_rlp_boundaries_and_zero_quantities() {
        let mut encoded = Vec::new();
        for number in [0, 1, 127, 128, 255, 256] {
            rlp_number(number, &mut encoded);
        }
        assert_eq!(hex(&encoded), "0x80017f818081ff820100");
        for length in [0, 1, 55, 56, 255, 256, MAX_CALLDATA_BYTES] {
            let bytes = vec![0xff; length];
            let mut encoded = Vec::new();
            rlp_bytes(&bytes, &mut encoded);
            let header_length = encoded.len() - length;
            assert_eq!(&encoded[header_length..], bytes);
            if length == 55 {
                assert_eq!(&encoded[..header_length], &[0xb7]);
            } else if length == 56 {
                assert_eq!(&encoded[..header_length], &[0xb8, 56]);
            } else if length == 256 {
                assert_eq!(&encoded[..header_length], &[0xb9, 1, 0]);
            }
        }
    }

    #[test]
    fn deterministic_signing_binds_executor_and_all_fields() {
        let tx = transaction();
        let signed = tx.sign(&test_key()).unwrap();
        assert_eq!(signed.raw, tx.sign(&test_key()).unwrap().raw);
        assert_eq!(signed.hash, tx.sign(&test_key()).unwrap().hash);
        assert_eq!(signed.from, executor_address(&test_key()).unwrap());
        assert_eq!(signed.from, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        tx.verify(&signed).unwrap();
        let mut variants = Vec::new();
        let mut changed = tx.clone();
        changed.chain_id += 1;
        variants.push(changed);
        let mut changed = tx.clone();
        changed.max_priority_fee_per_gas += 1;
        variants.push(changed);
        let mut changed = tx.clone();
        changed.max_fee_per_gas += 1;
        variants.push(changed);
        let mut changed = tx.clone();
        changed.gas_limit += 1;
        variants.push(changed);
        let mut changed = tx.clone();
        changed.nonce += 1;
        variants.push(changed);
        let mut changed = tx.clone();
        changed.to = "0x2222222222222222222222222222222222222222".into();
        variants.push(changed);
        let mut changed = tx.clone();
        changed.data.push_str("00");
        variants.push(changed);
        let mut changed = tx.clone();
        changed.fee_token = "0x20c0000000000000000000000000000000000002".into();
        variants.push(changed);
        for changed in variants {
            assert!(changed.verify(&signed).is_err());
        }
    }

    #[test]
    fn malformed_inputs_are_rejected_without_panics() {
        assert!(executor_address(&[0; 32]).is_err());
        assert!(executor_address(&[0xff; 32]).is_err());
        for data in ["", "1234", "0x1", "0xzz", "0xé", "0x\n00"] {
            let mut tx = transaction();
            tx.data = data.into();
            assert!(tx.sign(&test_key()).is_err());
        }
        for address in ["0x", "0x01", "0x0000000000000000000000000000000000000000"] {
            let mut tx = transaction();
            tx.to = address.into();
            assert!(tx.sign(&test_key()).is_err());
            tx = transaction();
            tx.fee_token = address.into();
            assert!(tx.sign(&test_key()).is_err());
        }
        let mut tx = transaction();
        tx.data = format!("0x{}", "00".repeat(MAX_CALLDATA_BYTES + 1));
        assert!(tx.sign(&test_key()).is_err());
        for change in 0..4 {
            let mut tx = transaction();
            match change {
                0 => tx.chain_id = 0,
                1 => tx.gas_limit = 0,
                2 => tx.max_fee_per_gas = 0,
                _ => tx.max_priority_fee_per_gas = tx.max_fee_per_gas + 1,
            }
            assert!(tx.sign(&test_key()).is_err());
        }
    }

    #[test]
    fn persisted_bytes_hash_and_signer_cannot_be_substituted() {
        let tx = transaction();
        let signed = tx.sign(&test_key()).unwrap();
        for raw in ["".into(), "0x00".into(), format!("{}00", signed.raw)] {
            let mut changed = signed.clone();
            changed.raw = raw;
            assert!(tx.verify(&changed).is_err());
        }
        let mut changed = signed.clone();
        changed.raw = changed.raw.replacen("0x76", "0x02", 1);
        assert!(tx.verify(&changed).is_err());
        let mut changed = signed.clone();
        changed.hash = format!("0x{}", "00".repeat(32));
        assert!(tx.verify(&changed).is_err());
        let mut changed = signed.clone();
        changed.from = "0x3333333333333333333333333333333333333333".into();
        assert!(tx.verify(&changed).is_err());
        // A valid signature under another key must not impersonate executor.
        let other = tx.sign(&[2; 32]).unwrap();
        let changed = SignedTransaction {
            from: signed.from.clone(),
            ..other
        };
        assert!(tx.verify(&changed).is_err());
    }

    #[test]
    fn noncanonical_rlp_and_signature_forms_are_rejected() {
        let tx = transaction();
        let signed = tx.sign(&test_key()).unwrap();
        let original = unhex(&signed.raw, MAX_RAW_BYTES).unwrap();
        for v in [0, 1, 29, 35, 255] {
            let mut raw = original.clone();
            *raw.last_mut().unwrap() = v;
            let changed = SignedTransaction {
                hash: hex(&keccak(&raw)),
                raw: hex(&raw),
                from: signed.from.clone(),
            };
            assert!(tx.verify(&changed).is_err());
        }
        // Add a forbidden empty keyAuthorization field before the signature.
        let mut fields = tx.fields().unwrap();
        fields.push(0x80);
        let raw = typed_payload(&fields, Some(&original[original.len() - 65..]));
        let changed = SignedTransaction {
            hash: hex(&keccak(&raw)),
            raw: hex(&raw),
            from: signed.from.clone(),
        };
        assert!(tx.verify(&changed).is_err());
        // An otherwise equivalent integer with leading zero is noncanonical.
        let mut fields = tx.fields().unwrap();
        assert_eq!(&fields[..3], &[0x82, 0xa5, 0xbf]);
        fields.splice(..3, [0x83, 0x00, 0xa5, 0xbf]);
        let raw = typed_payload(&fields, Some(&original[original.len() - 65..]));
        let changed = SignedTransaction {
            hash: hex(&keccak(&raw)),
            raw: hex(&raw),
            from: signed.from.clone(),
        };
        assert!(tx.verify(&changed).is_err());
        let mut raw = original.clone();
        let start = raw.len() - 65;
        raw[start..start + 64].fill(0);
        let changed = SignedTransaction {
            hash: hex(&keccak(&raw)),
            raw: hex(&raw),
            from: signed.from.clone(),
        };
        assert!(tx.verify(&changed).is_err());
        // The opposite-s variant is mathematically valid ECDSA but forbidden.
        let order = num_bigint::BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap();
        let s = num_bigint::BigUint::from_bytes_be(&original[start + 32..start + 64]);
        let high_s = (order - s).to_bytes_be();
        let mut raw = original;
        raw[start + 32..start + 64].fill(0);
        raw[start + 64 - high_s.len()..start + 64].copy_from_slice(&high_s);
        let changed = SignedTransaction {
            hash: hex(&keccak(&raw)),
            raw: hex(&raw),
            from: signed.from,
        };
        assert!(tx.verify(&changed).is_err());
    }

    #[test]
    fn maximum_supported_calldata_and_quantities_round_trip() {
        let mut tx = transaction();
        tx.chain_id = u64::MAX;
        tx.gas_limit = u64::MAX;
        tx.nonce = u64::MAX;
        tx.max_priority_fee_per_gas = u128::MAX;
        tx.max_fee_per_gas = u128::MAX;
        tx.data = format!("0x{}", "ff".repeat(MAX_CALLDATA_BYTES));
        let signed = tx.sign(&test_key()).unwrap();
        assert!(unhex(&signed.raw, MAX_RAW_BYTES).is_ok());
        tx.verify(&signed).unwrap();
    }
}
