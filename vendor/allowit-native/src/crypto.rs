use crate::error::{Error, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer as _, Verifier as _};
use sha2::{Digest, Sha256};
use std::{fmt, io::Read, path::Path};
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub [u8; 32]);
impl Key {
    pub fn parse(value: &str) -> Result<Self> {
        let decoded = bs58::decode(value)
            .into_vec()
            .map_err(|_| Error::config("Invalid public key"))?;
        let key = decoded
            .try_into()
            .map_err(|_| Error::config("Invalid public key"))?;
        Ok(Self(key))
    }
    pub fn on_curve(&self) -> bool {
        CompressedEdwardsY(self.0).decompress().is_some()
    }
    pub fn find_program_address(seeds: &[&[u8]], program: Key) -> Result<(Self, u8)> {
        if seeds.len() >= 16 || seeds.iter().any(|s| s.len() > 32) {
            return Err(Error::config("Invalid PDA seeds"));
        }
        for bump in (0u8..=255).rev() {
            let mut h = Sha256::new();
            for seed in seeds {
                h.update(seed);
            }
            h.update([bump]);
            h.update(program.0);
            h.update(b"ProgramDerivedAddress");
            let key = Self(h.finalize().into());
            if !key.on_curve() {
                return Ok((key, bump));
            }
        }
        Err(Error::config("Cannot derive program address"))
    }
}
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl serde::Serialize for Key {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
impl<'de> serde::Deserialize<'de> for Key {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}
// Secrets deliberately have no Debug/Serialize implementation.
pub struct LocalSigner(ed25519_dalek::SigningKey);
impl LocalSigner {
    pub fn from_secret(bytes: &[u8]) -> Result<Self> {
        let mut pair: [u8; 64] = bytes
            .try_into()
            .map_err(|_| Error::config("Invalid signer file"))?;
        let signer = ed25519_dalek::SigningKey::from_keypair_bytes(&pair)
            .map(Self)
            .map_err(|_| Error::config("Invalid signer file"));
        pair.fill(0);
        signer
    }
    pub fn load(path: &Path) -> Result<Self> {
        let info = std::fs::symlink_metadata(path)
            .map_err(|_| Error::config("Cannot read signer key file"))?;
        if !info.is_file() || info.file_type().is_symlink() {
            return Err(Error::config(
                "Signer key file must be a private regular file (0600)",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if info.permissions().mode() & 0o077 != 0 {
                return Err(Error::config(
                    "Signer key file must be a private regular file (0600)",
                ));
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut f = options
            .open(path)
            .map_err(|_| Error::config("Cannot read signer key file"))?;
        let opened = f
            .metadata()
            .map_err(|_| Error::config("Cannot read signer key file"))?;
        if !opened.is_file() {
            return Err(Error::config(
                "Signer key file must be a private regular file (0600)",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if opened.permissions().mode() & 0o077 != 0 {
                return Err(Error::config(
                    "Signer key file must be a private regular file (0600)",
                ));
            }
        }
        let mut bytes = Vec::new();
        f.by_ref()
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::config("Cannot read signer key file"))?;
        if bytes.len() > 4096 {
            bytes.fill(0);
            return Err(Error::config("Invalid signer file"));
        }
        let parsed = serde_json::from_slice::<Vec<u8>>(&bytes);
        bytes.fill(0);
        let mut data = parsed.map_err(|_| Error::config("Invalid signer file"))?;
        let signer = Self::from_secret(&data);
        data.fill(0);
        signer
    }
    pub fn public_key(&self) -> Key {
        Key(self.0.verifying_key().to_bytes())
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}
pub fn verify(public: Key, message: &[u8], signature: &[u8]) -> Result<()> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&public.0)
        .map_err(|_| Error::config("Invalid signature key"))?;
    let signature = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| Error::config("Invalid signature"))?;
    key.verify(message, &signature)
        .map_err(|_| Error::config("Invalid signature"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_are_local_and_verified() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let signer = LocalSigner::from_secret(&signing.to_keypair_bytes()).unwrap();
        let signature = signer.sign(b"bound message");
        verify(signer.public_key(), b"bound message", &signature).unwrap();
        assert!(verify(signer.public_key(), b"different message", &signature).is_err());
        let mut invalid = signing.to_keypair_bytes();
        invalid[63] ^= 1;
        assert!(LocalSigner::from_secret(&invalid).is_err());
    }
    #[test]
    fn pda_is_deterministic_and_off_curve() {
        let program = Key::parse("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
        let (a, bump) = Key::find_program_address(&[&[3u8; 32]], program).unwrap();
        assert!(!a.on_curve());
        assert_eq!(
            Key::find_program_address(&[&[3u8; 32]], program).unwrap(),
            (a, bump)
        );
        assert_eq!(Key::parse(&a.to_string()).unwrap(), a);
    }
}
