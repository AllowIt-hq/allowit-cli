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
        let readonly = keys.iter().filter(|a| !a.signer && !a.writable).count();
        let mut message = vec![1, 0, readonly as u8];
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
        if message.len() + 65 > 1232 {
            return Err(Error::config("Native transaction exceeds the packet limit"));
        }
        Ok(Self {
            payer,
            blockhash,
            instructions,
            message,
        })
    }
    pub fn signed(&self, signature: [u8; 64]) -> Result<Vec<u8>> {
        verify(self.payer, &self.message, &signature)?;
        let mut raw = vec![1];
        raw.extend(signature);
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
    if roles
        .iter()
        .any(|(key, (signer, _))| *signer && *key != payer)
    {
        return Err(Error::config(
            "Native transaction must have one designated signer",
        ));
    }
    Ok(roles)
}
pub struct Signed {
    pub signature: [u8; 64],
    pub message: Vec<u8>,
    pub keys: Vec<Meta>,
    pub blockhash: Key,
    pub instructions: Vec<Instruction>,
}
impl Signed {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1232 {
            return Err(Error::config("Invalid signed transaction"));
        }
        let mut r = Reader {
            data: raw,
            offset: 0,
        };
        if r.short()? != 1 {
            return Err(Error::config(
                "Native proof must have exactly one signature",
            ));
        }
        let signature = r.array::<64>()?;
        let start = r.offset;
        let required = r.byte()?;
        let readonly_signers = r.byte()?;
        let readonly = r.byte()?;
        if required != 1 || readonly_signers != 0 {
            return Err(Error::config("Invalid native message header"));
        }
        let count = r.short()?;
        if count == 0 || count > 256 || readonly as usize >= count {
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
                signer: i == 0,
                writable: i < count - readonly as usize,
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
        verify(keys[0].key, &message, &signature)?;
        Ok(Self {
            signature,
            message,
            keys,
            blockhash,
            instructions,
        })
    }
    /// Accepts the original SDK's account ordering while requiring the exact
    /// intended instructions, payer, blockhash, and global account privileges.
    pub fn matches(&self, expected: &Transaction) -> Result<()> {
        let expected_roles = roles(expected.payer, &expected.instructions)?;
        if self.keys[0].key != expected.payer
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
}
