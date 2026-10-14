//! Scoped engine capability transport and local verification of Stellar decisions.
use crate::{
    VERSION,
    config::{env_value, parse_origin},
    error::{Error, Result},
};
use allowit_stellar::{Config, DetachedApproval, PreparedPayment, SignedPayment};
use reqwest::{blocking::Client, redirect::Policy, tls::Version};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};

const MAX_BODY: usize = 1_048_576;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyBinding {
    pub id: String,
    pub revision: u64,
    pub source_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bundle {
    pub version: u8,
    pub profile: String,
    pub origin: String,
    pub capability: String,
    pub config: Config,
    pub policy: PolicyBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Value>,
    #[serde(
        rename = "executorSeed",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub executor_seed: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub action: String,
    pub merchant: String,
    pub context: Value,
}

fn invalid() -> Error {
    Error::config("Stellar engine response failed exact origin, policy or operation binding")
}

impl Bundle {
    pub fn validate(&self) -> Result<()> {
        let secret = self
            .capability
            .strip_prefix("stellar-executor.")
            .unwrap_or_default();
        if self.version != 1
            || self.profile != allowit_stellar::PROFILE
            || parse_origin(&self.origin)? != self.origin
            || !self.origin.starts_with("https://")
            || secret.len() != 32
            || !secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || self.policy.id.len() != 64
            || !self.policy.id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.policy.revision == 0
            || allowit_stellar::unhex::<32>(&self.policy.source_hash).is_err()
            || self.policy.source_hash.bytes().all(|b| b == b'0')
        {
            return Err(Error::config(
                "Invalid Stellar executor capability or hosted policy binding",
            ));
        }
        allowit_stellar::validate_config(&self.config)
            .map_err(|_| Error::config("Invalid pinned Stellar executor configuration"))?;
        if let Some(routes) = &self.routes
            && routes
                != &json!({"execute":"/api/stellar/execute","report":"/api/stellar/report","delivery":"/api/stellar/delivery","status":"/api/stellar/status"})
        {
            return Err(Error::config(
                "Stellar capability routes must match its exact engine origin",
            ));
        }
        let configured = env_value("ALLOWIT_URL");
        if !configured.is_empty() && parse_origin(&configured)? != self.origin {
            return Err(Error::config(
                "ALLOWIT_URL differs from the exported Stellar engine origin",
            ));
        }
        Ok(())
    }

    pub fn call(&self, route: &str, body: Value) -> Result<Value> {
        self.validate()?;
        if !["execute", "report", "delivery", "status"].contains(&route) {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(&body).map_err(|_| invalid())?;
        if bytes.len() > MAX_BODY {
            return Err(Error::config("Stellar engine request exceeds 1 MiB"));
        }
        let mut builder = Client::builder()
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(Policy::none())
            .min_tls_version(Version::TLS_1_2)
            .timeout(Duration::from_secs(60));
        #[cfg(test)]
        if let Ok(address) = std::env::var("ALLOWIT_STELLAR_TEST_DNS").and_then(|s| {
            s.parse::<std::net::SocketAddr>()
                .map_err(|_| std::env::VarError::NotPresent)
        }) {
            builder = builder.resolve("merchant.example", address);
        }
        let ca = env_value("ALLOWIT_CA_FILE");
        if !ca.is_empty() {
            let pem =
                std::fs::read(ca).map_err(|_| Error::config("Cannot read ALLOWIT_CA_FILE"))?;
            for certificate in reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| Error::config("Invalid ALLOWIT_CA_FILE"))?
            {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder
            .build()
            .map_err(|_| Error::config("Cannot configure Stellar engine transport"))?;
        let mut response = client
            .post(format!("{}/api/stellar/{route}", self.origin))
            .bearer_auth(&self.capability)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", format!("allowit-cli/{VERSION}"))
            .body(bytes)
            .send()
            .map_err(|_| Error::uncertain("Stellar engine outcome is unresolved; retain the original request ID and journal"))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::uncertain(
                "Stellar engine did not acknowledge the original operation; no credential was sent",
            ));
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                Error::uncertain(
                    "Stellar engine acknowledgment is unavailable; preserve the journal",
                )
            })?;
        if bytes.len() > MAX_BODY {
            return Err(invalid());
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if !value.is_object() {
            return Err(invalid());
        }
        Ok(value)
    }

    pub fn check_binding(&self, result: &Value, id: &str) -> Result<()> {
        if result["requestId"] != id
            || result["policyId"] != self.policy.id
            || result["binding"] != json!({"config":self.config,"policy":self.policy})
            || result["operation"]["id"] != id
            || result["operation"]["policyId"] != self.policy.id
            || result["operation"]["method"] != "execute"
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn execute(
        &self,
        id: &str,
        max: u64,
        intent: &Intent,
        prepared: &PreparedPayment,
    ) -> Result<Value> {
        let result = self.call("execute", json!({"policyId":self.policy.id,"requestId":id,"maxAmount":max.to_string(),"action":intent.action,"merchant":intent.merchant,"context":intent.context,"prepared":prepared}))?;
        self.check_binding(&result, id)?;
        Ok(result)
    }

    pub fn approval(&self, result: &Value, prepared: &PreparedPayment) -> Result<DetachedApproval> {
        if result["decision"] != "allow"
            || !matches!(
                result["operation"]["status"].as_str(),
                Some("prepared" | "authorized")
            )
        {
            return Err(invalid());
        }
        let approval: DetachedApproval =
            serde_json::from_value(result["approval"].clone()).map_err(|_| invalid())?;
        allowit_stellar::verify_approval(&self.config, prepared, &approval)
            .map_err(|_| invalid())?;
        Ok(approval)
    }

    pub fn report(
        &self,
        id: &str,
        signed: &SignedPayment,
        transaction: Option<&str>,
        attempted: bool,
    ) -> Result<Value> {
        let mut body =
            json!({"policyId":self.policy.id,"requestId":id,"signed":signed,"attempted":attempted});
        if let Some(hash) = transaction {
            body["transactionHash"] = json!(hash);
        }
        let result = self.call("report", body)?;
        self.check_proof(&result, id, signed)?;
        Ok(result)
    }

    pub fn check_proof(&self, result: &Value, id: &str, signed: &SignedPayment) -> Result<()> {
        self.check_binding(result, id)?;
        if result["proofAcknowledged"] != true
            || result["signedDigest"] != signed_digest(signed)?
            || !matches!(
                result["operation"]["status"].as_str(),
                Some("signed" | "submitted" | "uncertain" | "settled")
            )
        {
            return Err(Error::uncertain(
                "The engine did not durably acknowledge the exact Stellar credential; preserve the journal",
            ));
        }
        Ok(())
    }
}

pub(crate) fn signed_digest(signed: &SignedPayment) -> Result<String> {
    let value = serde_json::to_value(signed).map_err(|_| invalid())?;
    Ok(allowit_stellar::hex(&allowit_stellar::sha256(
        allowit_stellar::canonical_json(&value).map_err(|_| invalid())?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bundle() -> Bundle {
        let fixture: Value = serde_json::from_str(include_str!(
            "../repos/AllowIt-hq--allowit-sdk/stellar-rust/tests/fixtures/x402-vault.json"
        ))
        .unwrap();
        Bundle {
            version: 1,
            profile: allowit_stellar::PROFILE.into(),
            origin: "https://engine.example".into(),
            capability: format!("stellar-executor.{}", "a".repeat(32)),
            config: serde_json::from_value(fixture["config"].clone()).unwrap(),
            policy: PolicyBinding {
                id: "a".repeat(64),
                revision: 1,
                source_hash: "b".repeat(64),
            },
            routes: None,
            executor_seed: None,
        }
    }
    #[test]
    fn scoped_bundle_rejects_routes_origins_and_hosted_source_confusion() {
        let original = bundle();
        original.validate().unwrap();
        let mut changed = original.clone();
        changed.capability = "tempo-executor.secret".into();
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.origin = "https://engine.example/".into();
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.routes = Some(json!({"execute":"https://merchant.example"}));
        assert!(changed.validate().is_err());
        changed = original.clone();
        changed.policy.source_hash = "0".repeat(64);
        assert!(changed.validate().is_err());
        assert_ne!(
            original.policy.source_hash,
            original.config.policy_source_hash
        );
    }
    #[test]
    fn exact_binding_is_required_even_for_a_deny_or_owner_question() {
        let bundle = bundle();
        let mut value = json!({"requestId":"request-001","policyId":bundle.policy.id,"binding":{"config":bundle.config,"policy":bundle.policy},"operation":{"id":"request-001","policyId":bundle.policy.id,"method":"execute"},"decision":"deny"});
        bundle.check_binding(&value, "request-001").unwrap();
        value["binding"]["config"]["owner"] = json!(allowit_stellar::account_for_seed(&[9; 32]));
        assert!(bundle.check_binding(&value, "request-001").is_err());
        assert!(bundle.check_binding(&value, "request-002").is_err());
    }
}
