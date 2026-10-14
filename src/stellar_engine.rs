//! Scoped engine capability transport and local verification of Stellar decisions.
use crate::{
    VERSION,
    config::{env_value, parse_origin},
    error::{Error, Result},
};
use allowit_stellar::http_binding::{
    AttestationClaims, HTTP_BINDING_PROFILE, validate_http_binding_quote,
    verify_merchant_attestation,
};
use allowit_stellar::{Config, DetachedApproval, PreparedPayment, SignedPayment};
use reqwest::{blocking::Client, redirect::Policy, tls::Version};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MerchantBinding {
    claims: AttestationClaims,
    signature: String,
    verification_key: String,
}

fn invalid() -> Error {
    Error::config(
        "Stellar engine response failed exact merchant, request, policy or operation binding",
    )
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| invalid())
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
                "Stellar engine did not acknowledge the original operation; keep its original ID and journal",
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
        self.check_request(&result, intent, prepared)?;
        Ok(result)
    }

    fn check_request(
        &self,
        result: &Value,
        intent: &Intent,
        prepared: &PreparedPayment,
    ) -> Result<()> {
        let request_hash = allowit_stellar::hex(
            &allowit_stellar::request_hash(&prepared.request).map_err(|_| invalid())?,
        );
        let identity = json!({"action":intent.action,"merchant":intent.merchant,"context":intent.context,"url":prepared.request.url,"recipient":prepared.request.selected_offer["payTo"],"amount":prepared.request.selected_offer["amount"]});
        if request_hash != prepared.request_hash
            || result["requestHash"] != request_hash
            || result["operation"]["requestHash"] != request_hash
            || result["operation"]["identity"] != identity
            || result["operation"]["exactRequest"] != identity
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn check_delivery_binding(
        &self,
        result: &Value,
        intent: &Intent,
        prepared: &PreparedPayment,
    ) -> Result<()> {
        self.check_merchant_binding(result, intent, prepared, now()?)
    }

    fn check_merchant_binding(
        &self,
        result: &Value,
        intent: &Intent,
        prepared: &PreparedPayment,
        at: u64,
    ) -> Result<()> {
        self.check_request(result, intent, prepared)?;
        let quote = validate_http_binding_quote(&prepared.request.selected_offer, at)
            .map_err(|_| invalid())?;
        let binding: MerchantBinding =
            serde_json::from_value(result["merchantBinding"].clone()).map_err(|_| invalid())?;
        let claims = &binding.claims;
        let origin = url::Url::parse(&prepared.request.url)
            .map_err(|_| invalid())?
            .origin()
            .ascii_serialization();
        let challenge_hash = allowit_stellar::hex(&allowit_stellar::sha256(
            allowit_stellar::canonical_json(&prepared.request.payment_required)
                .map_err(|_| invalid())?,
        ));
        if prepared.expires_at <= at
            || quote.issued_at > prepared.created_at
            || quote.expires_at < prepared.expires_at
            || quote.merchant != intent.merchant
            || quote.action != intent.action
            || binding.verification_key != quote.verification_key
            || result["operation"]["merchantBinding"] != result["merchantBinding"]
            || claims.profile != HTTP_BINDING_PROFILE
            || claims.merchant != intent.merchant
            || claims.action != intent.action
            || claims.origin != origin
            || claims.request_hash != prepared.request_hash
            || claims.challenge_hash != challenge_hash
            || claims.verifier_hash != quote.verifier_hash
            || claims.issued_at < prepared.created_at
            || claims.issued_at > at
            || claims.expires_at <= at
            || claims.expires_at > quote.expires_at
        {
            return Err(invalid());
        }
        verify_merchant_attestation(claims, &binding.signature, &quote.verification_key)
            .map_err(|_| invalid())
    }

    pub fn approval(
        &self,
        result: &Value,
        id: &str,
        intent: &Intent,
        prepared: &PreparedPayment,
    ) -> Result<DetachedApproval> {
        self.check_binding(result, id)?;
        if result["decision"] != "allow"
            || !matches!(
                result["operation"]["status"].as_str(),
                Some("prepared" | "authorized")
            )
        {
            return Err(invalid());
        }
        self.check_delivery_binding(result, intent, prepared)?;
        let approval: DetachedApproval =
            serde_json::from_value(result["approval"].clone()).map_err(|_| invalid())?;
        allowit_stellar::verify_approval(&self.config, prepared, &approval)
            .map_err(|_| invalid())?;
        Ok(approval)
    }

    pub fn report(
        &self,
        id: &str,
        intent: &Intent,
        prepared: &PreparedPayment,
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
        if !attempted {
            self.check_delivery_binding(&result, intent, prepared)?;
        }
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
    use ed25519_dalek::{Signer, SigningKey};
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

    fn bound_response(at: u64) -> (Bundle, Intent, PreparedPayment, Value) {
        let bundle = bundle();
        let fixture: Value = serde_json::from_str(include_str!(
            "../repos/AllowIt-hq--allowit-sdk/stellar-rust/tests/fixtures/x402-vault.json"
        ))
        .unwrap();
        let intent = Intent {
            action: "research".into(),
            merchant: "fixture".into(),
            context: json!({"purpose":"dataset"}),
        };
        let mut request: allowit_stellar::PaymentRequest =
            serde_json::from_value(fixture["prepared"]["request"].clone()).unwrap();
        request.selected_offer["extra"] = json!({
            "areFeesSponsored":true,
            "paymentFlow":"upfront",
            "allowitHttpBinding": {
                "profile":HTTP_BINDING_PROFILE,"quoteId":"c".repeat(64),
                "issuedAt":at,"expiresAt":at+300,"merchant":intent.merchant,"action":intent.action,
                "verificationKey":allowit_stellar::account_for_seed(&[8;32]),"verifierHash":"d".repeat(64)
            }
        });
        request.payment_required["accepts"][0] = request.selected_offer.clone();
        let prepared = allowit_stellar::prepare_payment(
            &bundle.config,
            &serde_json::from_value(fixture["state"].clone()).unwrap(),
            request,
            fixture["authorizationXdr"].as_str().unwrap(),
            3500,
            at + 100,
            at,
        )
        .unwrap();
        let claims = AttestationClaims {
            profile: HTTP_BINDING_PROFILE.into(),
            merchant: intent.merchant.clone(),
            action: intent.action.clone(),
            origin: url::Url::parse(&prepared.request.url)
                .unwrap()
                .origin()
                .ascii_serialization(),
            request_hash: prepared.request_hash.clone(),
            challenge_hash: allowit_stellar::hex(&allowit_stellar::sha256(
                allowit_stellar::canonical_json(&prepared.request.payment_required).unwrap(),
            )),
            nonce: "e".repeat(64),
            issued_at: at,
            expires_at: at + 45,
            verifier_hash: "d".repeat(64),
        };
        // Public deterministic test seed. No deployed merchant key is used or read.
        let signature = SigningKey::from_bytes(&[8; 32])
            .sign(&allowit_stellar::http_binding::attestation_digest(&claims).unwrap());
        let binding = json!({"claims":claims,"signature":allowit_stellar::hex(&signature.to_bytes()),"verificationKey":allowit_stellar::account_for_seed(&[8;32])});
        let identity = json!({"action":intent.action,"merchant":intent.merchant,"context":intent.context,"url":prepared.request.url,"recipient":prepared.request.selected_offer["payTo"],"amount":prepared.request.selected_offer["amount"]});
        let approval =
            allowit_stellar::authority_sign(&bundle.config, &prepared, &[4; 32]).unwrap();
        let result = json!({"requestId":"request-001","policyId":bundle.policy.id,"binding":{"config":bundle.config,"policy":bundle.policy},"decision":"allow","approval":approval,"requestHash":prepared.request_hash,"merchantBinding":binding,"operation":{"id":"request-001","policyId":bundle.policy.id,"method":"execute","status":"authorized","requestHash":prepared.request_hash,"identity":identity,"exactRequest":identity,"merchantBinding":binding}});
        (bundle, intent, prepared, result)
    }

    #[test]
    fn merchant_binding_requires_exact_original_request_intent_and_public_key_pins() {
        let at = now().unwrap();
        let (bundle, intent, prepared, result) = bound_response(at);
        bundle
            .approval(&result, "request-001", &intent, &prepared)
            .unwrap();
        for (path, value) in [
            ("/requestHash", json!("f".repeat(64))),
            ("/operation/requestHash", json!("f".repeat(64))),
            (
                "/operation/exactRequest/context",
                json!({"purpose":"other"}),
            ),
            ("/operation/identity/action", json!("other")),
            ("/merchantBinding/claims/profile", json!("unsupported")),
            ("/merchantBinding/claims/action", json!("other")),
            ("/merchantBinding/claims/merchant", json!("other")),
            (
                "/merchantBinding/claims/origin",
                json!("https://other.example"),
            ),
            ("/merchantBinding/claims/requestHash", json!("f".repeat(64))),
            (
                "/merchantBinding/claims/challengeHash",
                json!("f".repeat(64)),
            ),
            (
                "/merchantBinding/claims/verifierHash",
                json!("f".repeat(64)),
            ),
            ("/merchantBinding/claims/nonce", json!("0".repeat(64))),
            ("/merchantBinding/claims/issuedAt", json!(at + 1)),
            ("/merchantBinding/claims/expiresAt", json!(at)),
            ("/merchantBinding/claims/expiresAt", json!(at + 61)),
            ("/merchantBinding/claims/expiresAt", json!(at + 301)),
            ("/merchantBinding/signature", json!("00".repeat(64))),
            (
                "/merchantBinding/verificationKey",
                json!(allowit_stellar::account_for_seed(&[9; 32])),
            ),
        ] {
            let mut changed = result.clone();
            *changed.pointer_mut(path).unwrap() = value;
            if path.starts_with("/merchantBinding/claims/") {
                let claims: AttestationClaims =
                    serde_json::from_value(changed["merchantBinding"]["claims"].clone()).unwrap();
                if let Ok(digest) = allowit_stellar::http_binding::attestation_digest(&claims) {
                    // Valid signatures for another request still fail the local binding checks.
                    let signature = SigningKey::from_bytes(&[8; 32]).sign(&digest);
                    changed["merchantBinding"]["signature"] =
                        json!(allowit_stellar::hex(&signature.to_bytes()));
                }
            }
            // Exercise the local comparisons even when both response copies agree.
            if path.starts_with("/merchantBinding/") {
                changed["operation"]["merchantBinding"] = changed["merchantBinding"].clone();
            }
            assert!(
                bundle
                    .check_merchant_binding(&changed, &intent, &prepared, at)
                    .is_err(),
                "accepted {path}"
            );
        }
        let mut changed = result.clone();
        changed["operation"]["merchantBinding"]["signature"] = json!("00".repeat(64));
        assert!(
            bundle
                .check_merchant_binding(&changed, &intent, &prepared, at)
                .is_err()
        );
        changed = result.clone();
        changed.as_object_mut().unwrap().remove("merchantBinding");
        assert!(
            bundle
                .approval(&changed, "request-001", &intent, &prepared)
                .is_err()
        );
        assert!(
            bundle
                .check_merchant_binding(&result, &intent, &prepared, at + 45)
                .is_err()
        );
    }

    #[test]
    fn merchant_binding_cannot_replace_the_original_quote_or_prepared_hash() {
        let at = now().unwrap();
        let (bundle, intent, prepared, result) = bound_response(at);
        for path in [
            "/extra/paymentFlow",
            "/extra/allowitHttpBinding/profile",
            "/extra/allowitHttpBinding/verificationKey",
            "/extra/allowitHttpBinding/verifierHash",
        ] {
            let mut changed = prepared.clone();
            *changed.request.selected_offer.pointer_mut(path).unwrap() = json!("other");
            assert!(
                bundle
                    .check_merchant_binding(&result, &intent, &changed, at)
                    .is_err()
            );
        }
        let mut changed = prepared.clone();
        changed.request_hash = "f".repeat(64);
        assert!(
            bundle
                .check_merchant_binding(&result, &intent, &changed, at)
                .is_err()
        );
        let mut changed_intent = intent.clone();
        changed_intent.merchant = "other".into();
        assert!(
            bundle
                .check_merchant_binding(&result, &changed_intent, &prepared, at)
                .is_err()
        );
    }

    #[test]
    fn historical_signed_proof_acknowledgment_does_not_require_fresh_merchant_evidence() {
        let (bundle, intent, prepared, mut result) = bound_response(now().unwrap());
        let approval = serde_json::from_value(result["approval"].clone()).unwrap();
        let signed =
            allowit_stellar::sign_payment(&bundle.config, &prepared, &[2; 32], &approval).unwrap();
        result.as_object_mut().unwrap().remove("merchantBinding");
        result["operation"]
            .as_object_mut()
            .unwrap()
            .remove("merchantBinding");
        result["operation"]["status"] = json!("settled");
        result["proofAcknowledged"] = json!(true);
        result["signedDigest"] = json!(signed_digest(&signed).unwrap());
        bundle.check_proof(&result, "request-001", &signed).unwrap();
        assert!(
            bundle
                .check_delivery_binding(&result, &intent, &prepared)
                .is_err()
        );
        result["signedDigest"] = json!("f".repeat(64));
        assert!(bundle.check_proof(&result, "request-001", &signed).is_err());
    }
}
