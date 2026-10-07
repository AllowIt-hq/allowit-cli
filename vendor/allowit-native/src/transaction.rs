//! Narrow Solana legacy transaction codec for the native policy profile.
//! No dynamic program instructions or remote signing requests are accepted.
use crate::{
    crypto::{Key, verify},
    error::{Error, Result},
};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub key: Key,
    pub writable: bool,
    pub signer: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub program: Key,
    pub accounts: Vec<Meta>,
    pub data: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct Transaction {
    pub payer: Key,
    pub blockhash: Key,
    pub instructions: Vec<Instruction>,
    pub signers: Vec<Key>,
    pub message: Vec<u8>,
}
impl Transaction {
    pub fn new(payer: Key, blockhash: Key, instructions: Vec<Instruction>) -> Result<Self> {
        let roles = roles(payer, &instructions)?;
        let mut keys: Vec<_> = roles
            .iter()
            .map(|(key, (signer, writable))| Meta {
                key: *key,
                signer: *signer,
                writable: *writable,
            })
            .collect();
        keys.sort_by(|a, b| {
            (a.key != payer, !a.signer, !a.writable)
                .cmp(&(b.key != payer, !b.signer, !b.writable))
                .then_with(|| compare_base58(a.key, b.key))
        });
        if keys.len() > 256 {
            return Err(Error::config("Transaction has too many accounts"));
        }
        let signers: Vec<_> = keys.iter().filter(|a| a.signer).map(|a| a.key).collect();
        let readonly_signers = keys.iter().filter(|a| a.signer && !a.writable).count();
        let readonly = keys.iter().filter(|a| !a.signer && !a.writable).count();
        let mut message = vec![signers.len() as u8, readonly_signers as u8, readonly as u8];
        short(&mut message, keys.len());
        for a in &keys {
            message.extend(a.key.0);
        }
        message.extend(blockhash.0);
        short(&mut message, instructions.len());
        let index = |key: Key| keys.iter().position(|a| a.key == key).unwrap() as u8;
        for i in &instructions {
            message.push(index(i.program));
            short(&mut message, i.accounts.len());
            message.extend(i.accounts.iter().map(|a| index(a.key)));
            short(&mut message, i.data.len());
            message.extend(&i.data);
        }
        let mut signature_prefix = Vec::new();
        short(&mut signature_prefix, signers.len());
        if message.len() + signature_prefix.len() + signers.len() * 64 > 1232 {
            return Err(Error::config("Native transaction exceeds the packet limit"));
        }
        Ok(Self {
            payer,
            blockhash,
            instructions,
            signers,
            message,
        })
    }
    pub fn signed(&self, signature: [u8; 64]) -> Result<Vec<u8>> {
        if self.signers.len() != 1 {
            return Err(Error::config(
                "All required native transaction signatures must be supplied",
            ));
        }
        self.signed_by(&[(self.signers[0], signature)])
    }
    pub fn signed_by(&self, signatures: &[(Key, [u8; 64])]) -> Result<Vec<u8>> {
        self.encode_signatures(signatures, true)
    }
    pub fn partially_signed(&self, signatures: &[(Key, [u8; 64])]) -> Result<Vec<u8>> {
        self.encode_signatures(signatures, false)
    }
    pub fn add_signature(&self, raw: &[u8], signer: Key, signature: [u8; 64]) -> Result<Vec<u8>> {
        let partial = Signed::parse_partial(raw)?;
        partial.matches(self)?;
        let mut signatures: Vec<_> = self
            .signers
            .iter()
            .copied()
            .zip(partial.signatures.iter().copied())
            .filter(|(_, signature)| *signature != [0; 64])
            .collect();
        if let Some((_, current)) = signatures.iter().find(|(key, _)| *key == signer) {
            if *current != signature {
                return Err(Error::config("Conflicting native transaction signature"));
            }
        } else {
            signatures.push((signer, signature));
        }
        self.encode_signatures(&signatures, false)
    }
    fn encode_signatures(
        &self,
        signatures: &[(Key, [u8; 64])],
        require_all: bool,
    ) -> Result<Vec<u8>> {
        let mut supplied = BTreeMap::new();
        for (key, signature) in signatures {
            if !self.signers.contains(key) || supplied.insert(*key, *signature).is_some() {
                return Err(Error::config("Unexpected native transaction signer"));
            }
            verify(*key, &self.message, signature)?;
        }
        if require_all && supplied.len() != self.signers.len() {
            return Err(Error::config(
                "All required native transaction signatures must be supplied",
            ));
        }
        let mut raw = Vec::new();
        short(&mut raw, self.signers.len());
        for signer in &self.signers {
            raw.extend(supplied.get(signer).copied().unwrap_or([0; 64]));
        }
        raw.extend(&self.message);
        Ok(raw)
    }
}
// web3.js localeCompare on base58's ASCII alphabet: compare primary Latin
// letters without case, then prefer lowercase on an otherwise equal string.
fn compare_base58(a: Key, b: Key) -> std::cmp::Ordering {
    let a = a.to_string();
    let b = b.to_string();
    a.to_ascii_lowercase()
        .cmp(&b.to_ascii_lowercase())
        .then_with(|| {
            a.bytes()
                .map(|c| c.is_ascii_uppercase())
                .cmp(b.bytes().map(|c| c.is_ascii_uppercase()))
        })
}

fn roles(payer: Key, instructions: &[Instruction]) -> Result<BTreeMap<Key, (bool, bool)>> {
    let mut roles = BTreeMap::from([(payer, (true, true))]);
    for i in instructions {
        roles.entry(i.program).or_insert((false, false));
        for a in &i.accounts {
            let entry = roles.entry(a.key).or_default();
            entry.0 |= a.signer;
            entry.1 |= a.writable;
        }
    }
    Ok(roles)
}
pub struct Signed {
    pub signatures: Vec<[u8; 64]>,
    pub message: Vec<u8>,
    pub keys: Vec<Meta>,
    pub blockhash: Key,
    pub instructions: Vec<Instruction>,
}
impl Signed {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        Self::parse_inner(raw, false)
    }
    pub fn parse_partial(raw: &[u8]) -> Result<Self> {
        Self::parse_inner(raw, true)
    }
    pub fn primary_signature(&self) -> Result<[u8; 64]> {
        self.signatures
            .first()
            .copied()
            .filter(|signature| *signature != [0; 64])
            .ok_or_else(|| Error::config("Native transaction payer signature is missing"))
    }
    pub fn signature(&self, signer: Key) -> Option<[u8; 64]> {
        self.keys
            .iter()
            .take(self.signatures.len())
            .position(|meta| meta.key == signer)
            .and_then(|index| self.signatures.get(index).copied())
            .filter(|signature| *signature != [0; 64])
    }
    fn parse_inner(raw: &[u8], allow_partial: bool) -> Result<Self> {
        if raw.len() > 1232 {
            return Err(Error::config("Invalid signed transaction"));
        }
        let mut r = Reader {
            data: raw,
            offset: 0,
        };
        let signature_count = r.short()?;
        if signature_count == 0 || signature_count > 16 {
            return Err(Error::config("Invalid native transaction signatures"));
        }
        let mut signatures = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            signatures.push(r.array::<64>()?);
        }
        let start = r.offset;
        let required = r.byte()?;
        let readonly_signers = r.byte()?;
        let readonly = r.byte()?;
        if required == 0 || required as usize != signature_count || readonly_signers > required {
            return Err(Error::config("Invalid native message header"));
        }
        let count = r.short()?;
        if count == 0
            || count > 256
            || required as usize > count
            || readonly as usize > count - required as usize
        {
            return Err(Error::config("Invalid native account table"));
        }
        let mut keys = Vec::new();
        for i in 0..count {
            let key = Key(r.array()?);
            if keys.iter().any(|a: &Meta| a.key == key) {
                return Err(Error::config("Duplicate transaction account"));
            }
            keys.push(Meta {
                key,
                signer: i < required as usize,
                writable: if i < required as usize {
                    i < required as usize - readonly_signers as usize
                } else {
                    i < count - readonly as usize
                },
            });
        }
        let blockhash = Key(r.array()?);
        let count = r.short()?;
        if count > 16 {
            return Err(Error::config("Invalid native instruction count"));
        }
        let mut instructions = Vec::new();
        for _ in 0..count {
            let p = r.byte()? as usize;
            let n = r.short()?;
            if n > 256 {
                return Err(Error::config("Invalid native accounts"));
            }
            let mut accounts = Vec::new();
            for _ in 0..n {
                let index = r.byte()? as usize;
                accounts.push(
                    keys.get(index)
                        .cloned()
                        .ok_or_else(|| Error::config("Invalid instruction account"))?,
                );
            }
            let n = r.short()?;
            let data = r.bytes(n)?.to_vec();
            instructions.push(Instruction {
                program: keys
                    .get(p)
                    .ok_or_else(|| Error::config("Invalid native program"))?
                    .key,
                accounts,
                data,
            });
        }
        if r.offset != raw.len() {
            return Err(Error::config("Trailing transaction bytes"));
        }
        let message = raw[start..].to_vec();
        for (key, signature) in keys.iter().take(signature_count).zip(&signatures) {
            if *signature == [0; 64] {
                if !allow_partial {
                    return Err(Error::config("Native transaction signature is missing"));
                }
            } else {
                verify(key.key, &message, signature)?;
            }
        }
        Ok(Self {
            signatures,
            message,
            keys,
            blockhash,
            instructions,
        })
    }
    /// Requires the exact pre-approved message bytes. A wallet may add only its
    /// signature; account order, privileges, instructions, and blockhash cannot
    /// be canonicalized or rewritten after approval.
    pub fn matches(&self, expected: &Transaction) -> Result<()> {
        let expected_roles = roles(expected.payer, &expected.instructions)?;
        if self.message != expected.message
            || self.keys[0].key != expected.payer
            || self.blockhash != expected.blockhash
            || self.keys.len() != expected_roles.len()
            || self.instructions.len() != expected.instructions.len()
        {
            return Err(Error::config(
                "Saved signed transaction does not match this operation",
            ));
        }
        for a in &self.keys {
            if expected_roles.get(&a.key) != Some(&(a.signer, a.writable)) {
                return Err(Error::config(
                    "Saved transaction account privileges changed",
                ));
            }
        }
        for (a, b) in self.instructions.iter().zip(&expected.instructions) {
            if a.program != b.program
                || a.data != b.data
                || a.accounts.len() != b.accounts.len()
                || a.accounts
                    .iter()
                    .zip(&b.accounts)
                    .any(|(x, y)| x.key != y.key)
            {
                return Err(Error::config(
                    "Saved signed transaction does not match this operation",
                ));
            }
        }
        Ok(())
    }
}
fn short(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut byte = (n & 127) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 128;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}
struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| Error::config("Invalid transaction bytes"))?;
        let bytes = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| Error::config("Invalid transaction bytes"))?;
        self.offset = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().unwrap())
    }
    fn short(&mut self) -> Result<usize> {
        let mut n = 0;
        for i in 0..3 {
            let b = self.byte()?;
            if i == 2 && b > 3 {
                return Err(Error::config("Invalid compact transaction length"));
            }
            n |= ((b & 127) as usize) << (7 * i);
            if b & 128 == 0 {
                if i > 0 && b == 0 {
                    return Err(Error::config("Noncanonical compact transaction length"));
                }
                return Ok(n);
            }
        }
        Err(Error::config("Invalid compact transaction length"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::LocalSigner;
    #[test]
    fn signed_intent_and_privileges_are_bound() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let signer = LocalSigner::from_secret(&key.to_keypair_bytes()).unwrap();
        let ix = Instruction {
            program: Key([3; 32]),
            accounts: vec![
                Meta {
                    key: signer.public_key(),
                    signer: true,
                    writable: false,
                },
                Meta {
                    key: Key([2; 32]),
                    signer: false,
                    writable: true,
                },
            ],
            data: vec![1, 2, 3],
        };
        let tx = Transaction::new(signer.public_key(), Key([9; 32]), vec![ix]).unwrap();
        let raw = tx.signed(signer.sign(&tx.message)).unwrap();
        let proof = Signed::parse(&raw).unwrap();
        proof.matches(&tx).unwrap();
        let mut changed = tx.clone();
        changed.instructions[0].data[0] = 2;
        assert!(proof.matches(&changed).is_err());
        changed = tx.clone();
        changed.instructions[0].accounts[1].writable = false;
        assert!(proof.matches(&changed).is_err());
        let mut corrupted = raw.clone();
        corrupted[20] ^= 1;
        assert!(Signed::parse(&corrupted).is_err());
        let mut trailing = raw;
        trailing.push(0);
        assert!(Signed::parse(&trailing).is_err());
    }

    #[test]
    fn partial_cosignatures_preserve_the_exact_message_and_slots() {
        let executor = LocalSigner::from_secret(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).to_keypair_bytes(),
        )
        .unwrap();
        let authority = LocalSigner::from_secret(
            &ed25519_dalek::SigningKey::from_bytes(&[8; 32]).to_keypair_bytes(),
        )
        .unwrap();
        let tx = Transaction::new(
            executor.public_key(),
            Key([9; 32]),
            vec![Instruction {
                program: Key([3; 32]),
                accounts: vec![
                    Meta {
                        key: executor.public_key(),
                        signer: true,
                        writable: false,
                    },
                    Meta {
                        key: authority.public_key(),
                        signer: true,
                        writable: false,
                    },
                ],
                data: vec![4, 5, 6],
            }],
        )
        .unwrap();
        assert_eq!(
            tx.signers,
            vec![executor.public_key(), authority.public_key()]
        );
        let authority_signature = authority.sign(&tx.message);
        let partial = tx
            .partially_signed(&[(authority.public_key(), authority_signature)])
            .unwrap();
        assert!(Signed::parse(&partial).is_err());
        let parsed = Signed::parse_partial(&partial).unwrap();
        assert_eq!(
            parsed.signature(authority.public_key()),
            Some(authority_signature)
        );
        assert_eq!(parsed.signature(executor.public_key()), None);
        parsed.matches(&tx).unwrap();
        let complete = tx
            .add_signature(&partial, executor.public_key(), executor.sign(&tx.message))
            .unwrap();
        let parsed = Signed::parse(&complete).unwrap();
        parsed.matches(&tx).unwrap();
        assert_eq!(
            parsed.primary_signature().unwrap(),
            executor.sign(&tx.message)
        );
        assert_eq!(parsed.message, tx.message);
    }
}
