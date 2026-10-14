//! Bounded Soroban reads. This module never broadcasts or accepts a chain chosen by a quote.
use crate::{
    config::env_value,
    error::{Error, Result},
};
use allowit_stellar::{Config, VaultState};
use reqwest::{blocking::Client, redirect::Policy};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};

fn checked<T>(value: std::result::Result<T, String>) -> Result<T> {
    value.map_err(|_| {
        Error::config("Stellar configuration, contract or authorization validation failed")
    })
}

pub(crate) struct Rpc {
    client: Client,
    url: String,
}
impl Rpc {
    pub(crate) fn new(config: &Config) -> Result<Self> {
        let override_url = env_value("ALLOWIT_STELLAR_RPC_URL");
        let url = if override_url.is_empty() {
            &config.rpc_url
        } else {
            &override_url
        };
        let parsed = url::Url::parse(url).map_err(|_| Error::config("Invalid Stellar RPC URL"))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::config(
                "Stellar RPC requires HTTPS without credentials, query or fragment",
            ));
        }
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(30));
        #[cfg(test)]
        if let Ok(address) = std::env::var("ALLOWIT_STELLAR_TEST_DNS").and_then(|s| {
            s.parse::<std::net::SocketAddr>()
                .map_err(|_| std::env::VarError::NotPresent)
        }) {
            builder = builder.resolve("merchant.example", address);
        }
        let ca = env_value("ALLOWIT_CA_FILE");
        if !ca.is_empty() {
            let bytes =
                std::fs::read(ca).map_err(|_| Error::config("Cannot read ALLOWIT_CA_FILE"))?;
            for cert in reqwest::Certificate::from_pem_bundle(&bytes)
                .map_err(|_| Error::config("Invalid ALLOWIT_CA_FILE"))?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder
            .build()
            .map_err(|_| Error::config("Cannot configure Stellar RPC"))?;
        Ok(Self {
            client,
            url: url.to_owned(),
        })
    }
    pub(crate) fn read(&self, method: &str, params: Value) -> Result<Value> {
        if ![
            "getNetwork",
            "getLatestLedger",
            "getLedgerEntries",
            "simulateTransaction",
            "getTransaction",
        ]
        .contains(&method)
        {
            return Err(Error::config("Unsupported Stellar read operation"));
        }
        let request =
            serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":1,"method":method,"params":params}))
                .map_err(|_| Error::config("Invalid Stellar RPC request"))?;
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(request)
            .send()
            .map_err(|_| {
                Error::uncertain("Stellar RPC outcome is unavailable; retain the original journal")
            })?;
        if !response.status().is_success() {
            return Err(Error::uncertain(
                "Stellar RPC did not return a successful response",
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(2_097_153)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::uncertain("Stellar RPC response is unavailable"))?;
        if bytes.len() > 2_097_152 {
            return Err(Error::uncertain("Stellar RPC response exceeds its bound"));
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::uncertain("Invalid Stellar RPC response"))?;
        if value["jsonrpc"] != "2.0"
            || value["id"] != 1
            || !value["error"].is_null()
            || !value["result"].is_object()
        {
            return Err(Error::uncertain(
                "Stellar RPC returned an error or invalid envelope",
            ));
        }
        Ok(value["result"].clone())
    }
    pub(crate) fn simulate(&self, transaction: &str) -> Result<Value> {
        let result = self.read("simulateTransaction", json!({"transaction":transaction}))?;
        checked_simulation(result)
    }
    pub(crate) fn network(&self, config: &Config) -> Result<()> {
        let network = self.read("getNetwork", json!({}))?;
        let passphrase = match config.network.as_str() {
            "stellar:pubnet" => "Public Global Stellar Network ; September 2015",
            "stellar:testnet" => "Test SDF Network ; September 2015",
            _ => return Err(Error::config("Unsupported Stellar network")),
        };
        if network["passphrase"] != passphrase {
            return Err(Error::config(
                "RPC network differs from the pinned Stellar configuration",
            ));
        }
        Ok(())
    }
    pub(crate) fn live(&self, config: &Config) -> Result<(VaultState, u32)> {
        self.network(config)?;
        let sequence = self.read("getLatestLedger", json!({}))?["sequence"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::config("Invalid Stellar ledger sequence"))?;
        let keys = checked(allowit_stellar::ledger_keys(config))?;
        let ledger = self.read("getLedgerEntries", json!({"keys":keys}))?;
        let entries = ledger["entries"]
            .as_array()
            .ok_or_else(|| Error::config("Pinned Stellar contract entries are unavailable"))?;
        checked(allowit_stellar::validate_contract_entries(config, entries))?;
        let read_transaction = checked(allowit_stellar::state_read_transaction(config))?;
        let simulation = self.simulate(&read_transaction)?;
        let xdr = simulation["results"][0]["xdr"]
            .as_str()
            .ok_or_else(|| Error::config("Stellar vault state is missing"))?;
        let state = checked(allowit_stellar::parse_vault_state(xdr))?;
        Ok((state, sequence))
    }
}

fn checked_simulation(result: Value) -> Result<Value> {
    if !result["restorePreamble"].is_null() {
        return Err(Error::config(
            "Stellar simulation requires unsupported restoration; no signing key was read",
        ));
    }
    if !result["error"].is_null() || result["results"].as_array().is_none_or(|r| r.len() != 1) {
        return Err(Error::config(
            "Stellar simulation failed or returned ambiguous results",
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restoration_and_ambiguous_simulation_are_rejected_before_signing() {
        let result = json!({"results":[{"xdr":"AAAAAQ==","auth":[]}],"restorePreamble":{"transactionData":"AAAA","minResourceFee":"1"}});
        assert!(checked_simulation(result).is_err());
        assert!(checked_simulation(json!({"results":[]})).is_err());
        assert!(checked_simulation(json!({"results":[{},{}]})).is_err());
        assert!(checked_simulation(json!({"results":[{}],"error":"failed"})).is_err());
        assert!(checked_simulation(json!({"results":[{}]})).is_ok());
    }
}
