use crate::{
    error::{Error, Result},
    release,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const PROFILE: &str = "solana-native-v1";
pub const MAX_DAILY_UNITS: u64 = 50_000_000;
pub fn genesis(network: &str) -> Result<&'static str> {
    match network {
        "solana:testnet" => Ok("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"),
        "solana:devnet" => Ok("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
        _ => Err(Error::config(
            "Native lifecycle is restricted to explicit Solana test networks",
        )),
    }
}
pub fn units(value: &str) -> Result<u64> {
    if !regex::Regex::new(r"^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$")
        .unwrap()
        .is_match(value)
    {
        return Err(Error::config(
            "Use an exact decimal with at most six places",
        ));
    }
    let (whole, frac) = value.split_once('.').unwrap_or((value, ""));
    whole
        .parse::<u64>()
        .ok()
        .and_then(|w| w.checked_mul(1_000_000))
        .and_then(|w| {
            format!("{frac}{}", "0".repeat(6 - frac.len()))
                .parse::<u64>()
                .ok()
                .and_then(|f| w.checked_add(f))
        })
        .ok_or_else(|| Error::config("Amount exceeds u64"))
}
pub fn decimal(n: u64) -> String {
    let fraction = format!("{:06}", n % 1_000_000);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        (n / 1_000_000).to_string()
    } else {
        format!("{}.{fraction}", n / 1_000_000)
    }
}
pub fn digest(data: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(data.as_ref()))
}
fn js_trim(value: &str) -> &str {
    value.trim_matches(|c| {
        matches!(
            c,
            '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    })
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub version: u32,
    pub instance: String,
    pub profile: String,
    pub network: String,
    pub prompt: String,
    pub daily_limit: String,
    pub pay_discovery: bool,
    pub source_bundle: String,
    pub id: String,
    pub policy_artifact: String,
    pub rust: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Identity<'a> {
    instance: &'a str,
    profile: &'a str,
    network: &'a str,
    prompt: &'a str,
    daily_limit: &'a str,
    pay_discovery: bool,
    source_bundle: &'a str,
}
impl Policy {
    fn identity(&self) -> Identity<'_> {
        Identity {
            instance: &self.instance,
            profile: &self.profile,
            network: &self.network,
            prompt: &self.prompt,
            daily_limit: &self.daily_limit,
            pay_discovery: self.pay_discovery,
            source_bundle: &self.source_bundle,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.profile != PROFILE || genesis(&self.network).is_err() {
            return Err(Error::config("Unsupported policy profile/network"));
        }
        let r = release();
        if self.source_bundle != r.source_bundle
            || self.policy_artifact != r.artifacts[0].sha256
            || self.rust != r.sources["policy.rs"]
        {
            return Err(Error::config("Policy source/artifact binding changed"));
        }
        let limit = units(&self.daily_limit)?;
        if limit == 0 || limit > MAX_DAILY_UNITS {
            return Err(Error::config(
                "Daily limit must be positive and within the native ceiling",
            ));
        }
        if !regex::Regex::new(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        .unwrap()
        .is_match(&self.instance)
        {
            return Err(Error::config("Invalid policy instance"));
        }
        if js_trim(&self.prompt).is_empty() || self.prompt.encode_utf16().count() > 8000 {
            return Err(Error::config("Invalid policy prompt"));
        }
        if self.id != digest(serde_json::to_vec(&self.identity()).unwrap()) {
            return Err(Error::config("Policy identity changed"));
        }
        Ok(())
    }
    pub fn generate(network: &str, prompt: &str) -> Result<Self> {
        genesis(network)?;
        if js_trim(prompt).is_empty() || prompt.encode_utf16().count() > 8000 {
            return Err(Error::config("Supply one bounded policy prompt"));
        }
        let re=regex::Regex::new(r"(?i-u)^Spend up to ([0-9]+(?:\.[0-9]{1,6})?) (?:tokens|test tokens) per day(?P<discovery> with PaySH discovery)?\.?$").unwrap();
        let matched=re.captures(js_trim(prompt)).ok_or_else(||Error::denied("This native profile supports a daily token ceiling only. Use “Spend up to 5 test tokens per day” or configure the prompt author. Other rules must not be silently dropped."))?;
        let daily_limit = decimal(units(&matched[1])?);
        let r = release();
        let mut policy = Self {
            version: 1,
            instance: uuid::Uuid::new_v4().to_string(),
            profile: PROFILE.into(),
            network: network.into(),
            prompt: prompt.into(),
            daily_limit,
            pay_discovery: matched.name("discovery").is_some(),
            source_bundle: r.source_bundle.clone(),
            id: String::new(),
            policy_artifact: r.artifacts[0].sha256.clone(),
            rust: r.sources["policy.rs"].clone(),
        };
        policy.id = digest(serde_json::to_vec(&policy.identity()).unwrap());
        policy.validate()?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_identity_and_artifact_are_bound() {
        let p = Policy::generate("solana:testnet", "Spend up to 5 test tokens per day").unwrap();
        assert_eq!(p.daily_limit, "5");
        assert!(!p.pay_discovery);
        p.validate().unwrap();
        let mut changed = p.clone();
        changed.daily_limit = "6".into();
        assert!(changed.validate().unwrap_err().message.contains("identity"));
        changed = p;
        changed.rust.push(' ');
        assert!(changed.validate().unwrap_err().message.contains("binding"));
    }
    #[test]
    fn refuses_constraints_it_cannot_enforce() {
        assert_eq!(
            Policy::generate(
                "solana:testnet",
                "Spend up to 5 test tokens per day only at one merchant"
            )
            .unwrap_err()
            .code,
            20
        );
        assert!(Policy::generate("solana:mainnet", "Spend up to 5 test tokens per day").is_err());
        assert!(Policy::generate("solana:testnet", "Spend up to 51 test tokens per day").is_err());
        assert!(
            Policy::generate(
                "solana:devnet",
                "Spend up to 5 test tokens per day with PaySH discovery"
            )
            .unwrap()
            .pay_discovery
        );
    }
    #[test]
    fn amounts_are_exact_u64() {
        assert_eq!(units("1.000001").unwrap(), 1_000_001);
        assert_eq!(decimal(1_000_001), "1.000001");
        for v in ["-1", "1e6", "0.0000001", "01", "1.", "18446744073709551616"] {
            assert!(units(v).is_err(), "{v}");
        }
    }
    #[test]
    fn author_matches_javascript_ascii_case_and_whitespace() {
        assert!(
            Policy::generate(
                "solana:testnet",
                "Spend up to 5 test tokens per day with PayſH discovery"
            )
            .is_err()
        );
        assert!(
            Policy::generate("solana:testnet", "\u{85}Spend up to 5 test tokens per day").is_err()
        );
        assert!(
            Policy::generate(
                "solana:testnet",
                "\u{feff}Spend up to 5 test tokens per day\u{feff}"
            )
            .is_ok()
        );
    }
}
