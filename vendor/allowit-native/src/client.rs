use crate::{
    crypto::Key,
    error::{Error, Result},
    policy::{Policy, digest, genesis},
    release,
    rpc::{self, Rpc},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub network: String,
    pub source_bundle: String,
    pub policy: Key,
    pub policy_data: Key,
    pub custody: Key,
}
#[derive(Clone, Serialize)]
pub struct Config {
    pub network: String,
    pub mint: Option<Key>,
    pub executor: Option<Key>,
    pub deployment: Option<Deployment>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    pub owner: Key,
    pub executor: Key,
    pub mint: Key,
    pub vault: Key,
    pub token_account: Key,
    pub policy: Key,
    pub policy_data: Key,
    pub custody: Key,
    pub bump: u8,
}
pub struct NativeClient {
    pub config: Config,
    pub rpc: Arc<dyn Rpc>,
    verified: std::sync::Mutex<Option<(String, bool)>>,
}
impl NativeClient {
    pub fn new(config: Config, rpc: Arc<dyn Rpc>) -> Result<Self> {
        genesis(&config.network)?;
        Ok(Self {
            config,
            rpc,
            verified: std::sync::Mutex::new(None),
        })
    }
    pub fn check_network(&self) -> Result<()> {
        let observed = self.rpc.call("getGenesisHash", json!([]))?;
        if observed != genesis(&self.config.network)? {
            return Err(Error::config(
                "RPC genesis does not match the policy network",
            ));
        }
        Ok(())
    }
    pub fn public_binding(&self, policy: &Policy, owner: Key) -> Result<Binding> {
        let d = self
            .config
            .deployment
            .as_ref()
            .ok_or_else(|| Error::config("Deployment/network mismatch"))?;
        if policy.network != self.config.network
            || d.network != self.config.network
            || d.source_bundle != release().source_bundle
        {
            return Err(Error::config("Deployment/network mismatch"));
        }
        let loader = Key::parse(LOADER)?;
        if d.policy_data != Key::find_program_address(&[&d.policy.0], loader)?.0 {
            return Err(Error::config("Policy ProgramData mismatch"));
        }
        let id = hex32(&policy.id)?;
        let (vault, bump) =
            Key::find_program_address(&[b"allowit-vault-v1", &owner.0, &id], d.custody)?;
        let mint = self
            .config
            .mint
            .ok_or_else(|| Error::config("Invalid native mint"))?;
        let executor = self
            .config
            .executor
            .ok_or_else(|| Error::config("Invalid native executor"))?;
        let token_account = associated_token_address(mint, vault, true)?;
        Ok(Binding {
            owner,
            executor,
            mint,
            vault,
            token_account,
            policy: d.policy,
            policy_data: d.policy_data,
            custody: d.custody,
            bump,
        })
    }
    pub fn verify_release(&self, recovery: bool) -> Result<Deployment> {
        self.check_network()?;
        let identity = digest(
            serde_json::to_vec(&self.config)
                .map_err(|_| Error::config("Invalid native configuration"))?,
        );
        let d = self.config.deployment.as_ref().ok_or_else(|| {
            Error::config("Configure an independently verified native deployment")
        })?;
        if d.network != self.config.network || d.source_bundle != release().source_bundle {
            return Err(Error::config(
                "Configure an independently verified native deployment",
            ));
        }
        if self
            .verified
            .lock()
            .map_err(|_| Error::config("Native verification state unavailable"))?
            .as_ref()
            .is_some_and(|(key, full)| *key == identity && (*full || recovery))
        {
            return Ok(d.clone());
        }
        for (program, expected) in [
            (d.policy, &release().artifacts[0].sha256),
            (d.custody, &release().artifacts[1].sha256),
        ]
        .into_iter()
        .skip(usize::from(recovery))
        {
            let loader = Key::parse(LOADER)?;
            let info = rpc::account(self.rpc.as_ref(), program, None)?
                .ok_or_else(|| Error::config("Invalid deployed native program"))?;
            if !info.executable
                || info.owner != loader
                || info.data.len() != 36
                || u32::from_le_bytes(info.data[..4].try_into().unwrap()) != 2
            {
                return Err(Error::config("Invalid deployed native program"));
            }
            let linked = Key(info.data[4..36].try_into().unwrap());
            if linked != Key::find_program_address(&[&program.0], loader)?.0 {
                return Err(Error::config("Invalid ProgramData link"));
            }
            let data = rpc::account(self.rpc.as_ref(), linked, None)?.ok_or_else(|| {
                Error::config("Native deployment must have exact immutable artifact bytes")
            })?;
            if data.owner != loader
                || data.data.len() < 46
                || u32::from_le_bytes(data.data[..4].try_into().unwrap()) != 3
                || data.data[12] != 0
                || digest(&data.data[45..]) != *expected
            {
                return Err(Error::config(
                    "Native deployment must have exact immutable artifact bytes",
                ));
            }
        }
        if d.policy_data != Key::find_program_address(&[&d.policy.0], Key::parse(LOADER)?)?.0 {
            return Err(Error::config("Configured policy ProgramData mismatch"));
        }
        self.mint(
            self.config
                .mint
                .ok_or_else(|| Error::config("Invalid native mint"))?,
        )?;
        let mut verified = self
            .verified
            .lock()
            .map_err(|_| Error::config("Native verification state unavailable"))?;
        let full = !recovery
            || verified
                .as_ref()
                .is_some_and(|(key, full)| *key == identity && *full);
        *verified = Some((identity, full));
        Ok(d.clone())
    }
    pub fn binding(&self, policy: &Policy, owner: Key, recovery: bool) -> Result<Binding> {
        policy.validate()?;
        if policy.network != self.config.network {
            return Err(Error::config("Policy network mismatch"));
        }
        self.verify_release(recovery)?;
        self.public_binding(policy, owner)
    }
    pub fn mint(&self, address: Key) -> Result<()> {
        let a = rpc::account(self.rpc.as_ref(), address, None)?
            .ok_or_else(|| Error::config("Expected a classic SPL Token account"))?;
        if a.owner != Key::parse(TOKEN_PROGRAM)? || a.data.len() != 82 {
            return Err(Error::config("Expected a classic SPL Token account"));
        }
        if a.data[44] != 6
            || a.data[45] != 1
            || u32::from_le_bytes(a.data[46..50].try_into().unwrap()) != 0
        {
            return Err(Error::config(
                "Expected an initialized six-decimal test mint",
            ));
        }
        Ok(())
    }
    pub fn token(&self, address: Key) -> Result<TokenAccount> {
        let a = rpc::account(self.rpc.as_ref(), address, None)?
            .ok_or_else(|| Error::config("Expected a classic SPL Token account"))?;
        if a.owner != Key::parse(TOKEN_PROGRAM)? || a.data.len() != 165 {
            return Err(Error::config("Expected a classic SPL Token account"));
        }
        let d = &a.data;
        if d[108] != 1 {
            return Err(Error::config(
                "Expected an initialized unfrozen token account",
            ));
        }
        for offset in [72, 109, 129] {
            if u32::from_le_bytes(d[offset..offset + 4].try_into().unwrap()) > 1 {
                return Err(Error::config("Invalid SPL option"));
            }
        }
        Ok(TokenAccount {
            mint: Key(d[..32].try_into().unwrap()),
            owner: Key(d[32..64].try_into().unwrap()),
            amount: u64::from_le_bytes(d[64..72].try_into().unwrap()),
            delegate: u32::from_le_bytes(d[72..76].try_into().unwrap()) != 0,
            close_authority: u32::from_le_bytes(d[129..133].try_into().unwrap()) != 0,
        })
    }
}
#[derive(Debug)]
pub struct TokenAccount {
    pub mint: Key,
    pub owner: Key,
    pub amount: u64,
    pub delegate: bool,
    pub close_authority: bool,
}
pub fn associated_token_address(mint: Key, owner: Key, off_curve: bool) -> Result<Key> {
    if !off_curve && !owner.on_curve() {
        return Err(Error::config("Owner must be an Ed25519 account"));
    }
    Ok(Key::find_program_address(
        &[&owner.0, &Key::parse(TOKEN_PROGRAM)?.0, &mint.0],
        Key::parse(ATA_PROGRAM)?,
    )?
    .0)
}
pub fn hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::config("Invalid digest"));
    }
    let mut bytes = [0; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    struct FakeRpc(serde_json::Value);
    impl Rpc for FakeRpc {
        fn call(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value> {
            Ok(self.0.clone())
        }
    }
    fn client(response: serde_json::Value) -> NativeClient {
        NativeClient::new(
            Config {
                network: "solana:testnet".into(),
                mint: None,
                executor: None,
                deployment: None,
            },
            Arc::new(FakeRpc(response)),
        )
        .unwrap()
    }
    fn account(data: &[u8], owner: Key, slot: u64) -> serde_json::Value {
        json!({"context":{"slot":slot},"value":{"owner":owner.to_string(),"executable":false,"data":[base64::engine::general_purpose::STANDARD.encode(data),"base64"]}})
    }
    #[test]
    fn network_and_context_are_bound() {
        assert!(
            client(json!(genesis("solana:devnet").unwrap()))
                .check_network()
                .is_err()
        );
        assert!(
            NativeClient::new(
                Config {
                    network: "solana:mainnet".into(),
                    mint: None,
                    executor: None,
                    deployment: None
                },
                Arc::new(FakeRpc(json!(null)))
            )
            .is_err()
        );
        let response = account(&[], Key([1; 32]), 9);
        assert!(rpc::account(&FakeRpc(response.clone()), Key([2; 32]), Some(10)).is_err());
        assert!(rpc::account(&FakeRpc(response), Key([2; 32]), Some(9)).is_ok());
        assert!(rpc::account(&FakeRpc(json!({"value":null})), Key([2; 32]), None).is_err());
    }
    #[test]
    fn token_layout_and_authorities_are_checked() {
        let mut bytes = vec![0; 165];
        bytes[..32].fill(3);
        bytes[32..64].fill(4);
        bytes[64..72].copy_from_slice(&12u64.to_le_bytes());
        bytes[108] = 1;
        let program = Key::parse(TOKEN_PROGRAM).unwrap();
        let token = client(account(&bytes, program, 1))
            .token(Key([5; 32]))
            .unwrap();
        assert_eq!(token.amount, 12);
        assert_eq!(token.owner, Key([4; 32]));
        assert!(!token.delegate);
        bytes[72] = 2;
        assert!(
            client(account(&bytes, program, 1))
                .token(Key([5; 32]))
                .is_err()
        );
        bytes[72] = 0;
        bytes[108] = 2;
        assert!(
            client(account(&bytes, program, 1))
                .token(Key([5; 32]))
                .is_err()
        );
        bytes[108] = 1;
        assert!(
            client(account(&bytes, Key([9; 32]), 1))
                .token(Key([5; 32]))
                .is_err()
        );
    }
    #[test]
    fn public_binding_requires_canonical_program_data() {
        let p = Policy::generate("solana:testnet", "Spend up to 5 test tokens per day").unwrap();
        let policy = Key([2; 32]);
        let data = Key::find_program_address(&[&policy.0], Key::parse(LOADER).unwrap())
            .unwrap()
            .0;
        let mut c = client(json!(null));
        c.config.mint = Some(Key([3; 32]));
        c.config.executor = Some(Key([4; 32]));
        c.config.deployment = Some(Deployment {
            network: p.network.clone(),
            source_bundle: release().source_bundle.clone(),
            policy,
            policy_data: data,
            custody: Key([5; 32]),
        });
        let binding = c.public_binding(&p, Key([6; 32])).unwrap();
        assert!(!binding.vault.on_curve());
        c.config.deployment.as_mut().unwrap().policy_data = Key([9; 32]);
        assert!(c.public_binding(&p, Key([6; 32])).is_err());
    }
    #[test]
    fn verification_cache_is_scoped_to_exact_configuration_and_recovery_profile() {
        let mut c = client(json!(genesis("solana:testnet").unwrap()));
        let program = Key([2; 32]);
        let data = Key::find_program_address(&[&program.0], Key::parse(LOADER).unwrap())
            .unwrap()
            .0;
        c.config.mint = Some(Key([3; 32]));
        c.config.executor = Some(Key([4; 32]));
        c.config.deployment = Some(Deployment {
            network: c.config.network.clone(),
            source_bundle: release().source_bundle.clone(),
            policy: program,
            policy_data: data,
            custody: Key([5; 32]),
        });
        let identity = digest(serde_json::to_vec(&c.config).unwrap());
        *c.verified.lock().unwrap() = Some((identity.clone(), true));
        assert!(c.verify_release(false).is_ok());
        c.config.mint = Some(Key([6; 32]));
        assert!(c.verify_release(false).is_err());
        c.config.mint = Some(Key([3; 32]));
        *c.verified.lock().unwrap() = Some((identity, false));
        assert!(c.verify_release(true).is_ok());
        assert!(c.verify_release(false).is_err());
    }
}
