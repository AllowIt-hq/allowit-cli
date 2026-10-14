//! Bounded Soroban reads. This module never broadcasts or accepts a chain chosen by a quote.
use crate::{
    config::env_value,
    error::{Error, Result},
};
use allowit_stellar::{Config, PreparedPayment, SignedPayment, VaultState};
use reqwest::{blocking::Client, redirect::Policy};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};
use stellar_xdr::{
    ContractEventBody, ContractEventType, DiagnosticEvent, HostFunction, Limits, OperationBody,
    ReadXdr, ScAddress, ScVal, SorobanTransactionData, TransactionEnvelope,
};

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
    pub(crate) fn enforce(
        &self,
        config: &Config,
        prepared: &PreparedPayment,
        signed: &SignedPayment,
    ) -> Result<()> {
        checked(allowit_stellar::validate_signed(config, prepared, signed))?;
        let result = self.read(
            "simulateTransaction",
            json!({"transaction":signed.transaction_xdr,"authMode":"enforce"}),
        )?;
        let result = checked_simulation(result)?;
        if result["latestLedger"].as_u64().is_none_or(|ledger| {
            ledger == 0 || ledger >= u64::from(prepared.signature_expiration_ledger)
        }) {
            return Err(Error::config(
                "Stellar signed simulation is stale; retain the original signed journal",
            ));
        }
        validate_enforcement(signed, result)
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

fn validate_enforcement(signed: &SignedPayment, result: Value) -> Result<()> {
    let invalid = || {
        Error::config(
            "Stellar signed authorization simulation failed exact transfer or facilitator fee checks; retain the original signed journal",
        )
    };
    let fee = result["minResourceFee"]
        .as_str()
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(invalid)?;
    if fee
        .checked_add(100)
        .is_none_or(|n| n > allowit_stellar::MAX_TRANSACTION_FEE_STROOPS)
        || result["results"][0]["xdr"] != "AAAAAQ=="
    {
        return Err(invalid());
    }
    let limits = Limits {
        depth: 64,
        len: 2_097_152,
    };
    let resources = SorobanTransactionData::from_xdr_base64(
        result["transactionData"].as_str().ok_or_else(invalid)?,
        limits.clone(),
    )
    .map_err(|_| invalid())?;
    if resources.resource_fee < 0 || resources.resource_fee > i64::from(fee) {
        return Err(invalid());
    }
    let envelope = TransactionEnvelope::from_xdr_base64(&signed.transaction_xdr, limits.clone())
        .map_err(|_| invalid())?;
    let TransactionEnvelope::Tx(tx) = envelope else {
        return Err(invalid());
    };
    let operation = tx.tx.operations.first().ok_or_else(invalid)?;
    let OperationBody::InvokeHostFunction(op) = &operation.body else {
        return Err(invalid());
    };
    let HostFunction::InvokeContract(transfer) = &op.host_function else {
        return Err(invalid());
    };
    let ScAddress::Contract(asset) = &transfer.contract_address else {
        return Err(invalid());
    };
    if transfer.args.len() != 3 {
        return Err(invalid());
    }
    let events = result["events"].as_array().ok_or_else(invalid)?;
    let mut contract_events = 0;
    for encoded in events {
        let event =
            DiagnosticEvent::from_xdr_base64(encoded.as_str().ok_or_else(invalid)?, limits.clone())
                .map_err(|_| invalid())?;
        if event.event.type_ != ContractEventType::Contract {
            continue;
        }
        contract_events += 1;
        let ContractEventBody::V0(body) = &event.event.body;
        if !event.in_successful_contract_call
            || event.event.contract_id.as_ref() != Some(asset)
            || !(3..=4).contains(&body.topics.len())
            || body.topics[0] != ScVal::Symbol("transfer".try_into().map_err(|_| invalid())?)
            || body.topics[1] != transfer.args[0]
            || body.topics[2] != transfer.args[1]
            || body.data != transfer.args[2]
        {
            return Err(invalid());
        }
    }
    if contract_events != 1 {
        return Err(invalid());
    }
    Ok(())
}

fn checked_simulation(result: Value) -> Result<Value> {
    if !result["restorePreamble"].is_null() {
        return Err(Error::config(
            "Stellar simulation requires unsupported restoration; retain the original journal",
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
    use stellar_xdr::{Int128Parts, TransactionMeta, WriteXdr};

    #[test]
    fn enforcement_requires_one_successful_exact_asset_transfer() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../repos/AllowIt-hq--allowit-sdk/stellar-rust/tests/fixtures/x402-vault.json"
        ))
        .unwrap();
        let signed: SignedPayment = serde_json::from_value(fixture["signed"].clone()).unwrap();
        let meta = TransactionMeta::from_xdr_base64(
            fixture["rpcTransaction"]["resultMetaXdr"].as_str().unwrap(),
            Limits::none(),
        )
        .unwrap();
        let events = match meta {
            TransactionMeta::V3(meta) => meta.soroban_meta.unwrap().events.to_vec(),
            TransactionMeta::V4(meta) => meta.operations[0].events.to_vec(),
            _ => panic!("Expected golden Soroban metadata"),
        };
        let event = DiagnosticEvent {
            in_successful_contract_call: true,
            event: events[0].clone(),
        };
        let simulation = |events: Vec<DiagnosticEvent>| {
            json!({
                "minResourceFee":"49900", "transactionData":fixture["transactionData"],
                "results":[{"xdr":"AAAAAQ=="}],
                "events":events.iter().map(|e|e.to_xdr_base64(Limits::none()).unwrap()).collect::<Vec<_>>()
            })
        };
        assert!(validate_enforcement(&signed, simulation(vec![event.clone()])).is_ok());
        assert!(
            validate_enforcement(&signed, simulation(vec![event.clone(), event.clone()])).is_err()
        );
        for mutation in 0..5 {
            let mut altered = event.clone();
            match mutation {
                0 => altered.in_successful_contract_call = false,
                1 => altered.event.contract_id = None,
                2 => {
                    let ContractEventBody::V0(body) = &mut altered.event.body;
                    *body.topics.iter_mut().nth(1).unwrap() = ScVal::Void;
                }
                3 => {
                    let ContractEventBody::V0(body) = &mut altered.event.body;
                    *body.topics.iter_mut().nth(2).unwrap() = ScVal::Void;
                }
                _ => {
                    let ContractEventBody::V0(body) = &mut altered.event.body;
                    body.data = ScVal::I128(Int128Parts { hi: 0, lo: 1 });
                }
            }
            assert!(validate_enforcement(&signed, simulation(vec![altered])).is_err());
        }
    }
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
