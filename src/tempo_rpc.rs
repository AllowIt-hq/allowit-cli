//! Native Tempo RPC. Capabilities and signing keys never enter this transport.
use crate::{
    config::env_value,
    error::{Error, Result},
    tempo::{Bundle, Intent, address},
    tempo_transaction::{NativeTransaction, SignedTransaction},
};
use reqwest::{blocking::Client, redirect::Policy, tls::Version};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};

fn unknown() -> Error {
    Error::uncertain(
        "Tempo RPC outcome is unknown; preserve the journal and resume the original request",
    )
}
pub(crate) fn quantity(value: &Value) -> Result<u128> {
    let s = value.as_str().ok_or_else(unknown)?;
    let digits = s.strip_prefix("0x").ok_or_else(unknown)?;
    if digits.is_empty()
        || digits.len() > 32
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(unknown());
    }
    u128::from_str_radix(digits, 16).map_err(|_| unknown())
}
fn hash(value: &Value) -> Result<String> {
    let s = value.as_str().ok_or_else(unknown)?;
    if s.len() != 66 || !s.starts_with("0x") || !s[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(unknown());
    }
    Ok(s.to_ascii_lowercase())
}
fn eq_hex(value: &Value, expected: &str) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.eq_ignore_ascii_case(expected))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Finality {
    pub block_number: u64,
    pub block_hash: String,
    pub success: bool,
}
pub(crate) trait Chain {
    fn build(&self, plan: &allowit_tempo::Transaction) -> Result<NativeTransaction>;
    fn send(&self, signed: &SignedTransaction) -> Result<()>;
    fn known(&self, tx: &NativeTransaction, signed: &SignedTransaction) -> Result<bool>;
    fn finalized(
        &self,
        tx: &NativeTransaction,
        signed: &SignedTransaction,
        intent: &Intent,
        token: &str,
    ) -> Result<Option<Finality>>;
}
pub(crate) struct Rpc {
    url: url::Url,
    client: Client,
    chain_id: u64,
    max_gas: u64,
    max_fee: u128,
}
impl Rpc {
    pub fn new(bundle: &Bundle) -> Result<Self> {
        let explicit = env_value("ALLOWIT_TEMPO_RPC_URL");
        let endpoint = if explicit.is_empty() {
            bundle.value["config"]["rpcUrl"]
                .as_str()
                .unwrap_or_default()
        } else {
            &explicit
        };
        let url = url::Url::parse(endpoint).map_err(|_| Error::config("Invalid Tempo RPC URL"))?;
        let loopback = matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::config(
                "Tempo RPC requires HTTPS or loopback HTTP, without URL credentials",
            ));
        }
        let max_gas = env_value("ALLOWIT_TEMPO_MAX_GAS");
        let max_gas = if max_gas.is_empty() {
            1_500_000
        } else {
            max_gas
                .parse::<u64>()
                .map_err(|_| Error::config("Invalid ALLOWIT_TEMPO_MAX_GAS"))?
        };
        if !(21_000..=10_000_000).contains(&max_gas) {
            return Err(Error::config(
                "Tempo gas cap must be between 21000 and 10000000",
            ));
        }
        let fee = env_value("ALLOWIT_TEMPO_MAX_FEE");
        let units =
            allowit_tempo::units(if fee.is_empty() { "0.1" } else { &fee }).map_err(|_| {
                Error::config("Tempo fee cap must be an exact six-place test-dollar amount")
            })?;
        if units == 0 || units > 1_000_000 {
            return Err(Error::config(
                "Tempo fee cap must be positive and at most 1 test dollar",
            ));
        }
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .min_tls_version(Version::TLS_1_2)
            .timeout(Duration::from_secs(15));
        let ca = env_value("ALLOWIT_CA_FILE");
        if !ca.is_empty() {
            let pem =
                std::fs::read(ca).map_err(|_| Error::config("Cannot read ALLOWIT_CA_FILE"))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| Error::config("Invalid ALLOWIT_CA_FILE"))?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        let chain_id = bundle.value["config"]["chainId"]
            .as_u64()
            .ok_or_else(unknown)?;
        Ok(Self {
            url,
            client: builder
                .build()
                .map_err(|_| Error::config("Cannot configure Tempo RPC"))?,
            chain_id,
            max_gas,
            max_fee: u128::from(units) * 1_000_000_000_000,
        })
    }
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
                .map_err(|_| unknown())?;
        if body.len() > 131_072 {
            return Err(unknown());
        }
        // No redirect, no bearer capability, and exactly one sendRawTransaction attempt.
        let mut response = self
            .client
            .post(self.url.clone())
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|_| unknown())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(unknown());
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take(2_097_153)
            .read_to_end(&mut bytes)
            .map_err(|_| unknown())?;
        if bytes.len() > 2_097_152 {
            return Err(unknown());
        }
        let reply: Value = serde_json::from_slice(&bytes).map_err(|_| unknown())?;
        if reply["jsonrpc"] != "2.0" || reply["id"] != 1 || reply.get("error").is_some() {
            return Err(unknown());
        }
        reply.get("result").cloned().ok_or_else(unknown)
    }
    fn check_chain(&self) -> Result<()> {
        if quantity(&self.call("eth_chainId", json!([]))?)? != u128::from(self.chain_id) {
            return Err(Error::config(
                "Tempo RPC chain differs from the imported policy; nothing is sent",
            ));
        }
        Ok(())
    }
}
impl Chain for Rpc {
    fn build(&self, plan: &allowit_tempo::Transaction) -> Result<NativeTransaction> {
        self.check_chain()?;
        if plan.chain_id != self.chain_id || plan.value != "0x0" || !address(&plan.from) {
            return Err(Error::config("Invalid native Tempo plan"));
        }
        let nonce =
            quantity(&self.call("eth_getTransactionCount", json!([plan.from, "pending"]))?)?;
        let latest =
            quantity(&self.call("eth_getTransactionCount", json!([plan.from, "latest"]))?)?;
        if nonce != latest {
            return Err(Error::uncertain(
                "Executor has an unresolved account nonce; reconcile its existing transaction before paying",
            ));
        }
        let nonce =
            u64::try_from(nonce).map_err(|_| Error::config("Unsupported Tempo account nonce"))?;
        let estimated = quantity(&self.call("eth_estimateGas", json!([{
            "type":"0x76","chainId":format!("0x{:x}",self.chain_id),"from":plan.from,
            "calls":[{"to":plan.to,"data":plan.data,"value":"0x0"}],
            "feeToken":plan.fee_token,"nonceKey":"0x0","nonce":format!("0x{nonce:x}"),"keyType":"secp256k1"
        }]))?)?;
        let gas = estimated
            .checked_mul(6)
            .and_then(|n| n.checked_add(4))
            .map(|n| n / 5)
            .ok_or_else(|| Error::config("Tempo gas estimate exceeds the cap"))?;
        let price = quantity(&self.call("eth_gasPrice", json!([]))?)?
            .checked_mul(2)
            .ok_or_else(|| Error::config("Tempo gas price exceeds the fee cap"))?;
        if gas == 0
            || gas > u128::from(self.max_gas)
            || price == 0
            || gas.checked_mul(price).is_none_or(|fee| fee > self.max_fee)
        {
            return Err(Error::config(
                "Tempo estimate exceeds the configured gas or total fee cap; nothing is signed",
            ));
        }
        Ok(NativeTransaction {
            chain_id: self.chain_id,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: price,
            gas_limit: gas as u64,
            nonce,
            to: plan.to.clone(),
            data: plan.data.clone(),
            fee_token: plan.fee_token.clone(),
        })
    }
    fn send(&self, signed: &SignedTransaction) -> Result<()> {
        self.check_chain()?;
        let reply = self.call("eth_sendRawTransaction", json!([signed.raw]))?;
        if !eq_hex(&reply, &signed.hash) {
            return Err(unknown());
        }
        Ok(())
    }
    fn known(&self, tx: &NativeTransaction, signed: &SignedTransaction) -> Result<bool> {
        self.check_chain()?;
        let chain_tx = self.call("eth_getTransactionByHash", json!([signed.hash]))?;
        if chain_tx.is_null() {
            return Ok(false);
        }
        check_transaction(&chain_tx, tx, signed)?;
        Ok(true)
    }
    fn finalized(
        &self,
        tx: &NativeTransaction,
        signed: &SignedTransaction,
        intent: &Intent,
        token: &str,
    ) -> Result<Option<Finality>> {
        self.check_chain()?;
        let receipt = self.call("eth_getTransactionReceipt", json!([signed.hash]))?;
        if receipt.is_null() {
            return Ok(None);
        }
        let chain_tx = self.call("eth_getTransactionByHash", json!([signed.hash]))?;
        check_transaction(&chain_tx, tx, signed)?;
        let block_number = quantity(&receipt["blockNumber"])?;
        let block_hash = hash(&receipt["blockHash"])?;
        let status = quantity(&receipt["status"])?;
        if status > 1
            || !eq_hex(&receipt["transactionHash"], &signed.hash)
            || !eq_hex(&receipt["from"], &signed.from)
            || !eq_hex(&receipt["to"], &tx.to)
            || quantity(&chain_tx["blockNumber"])? != block_number
            || !eq_hex(&chain_tx["blockHash"], &block_hash)
        {
            return Err(unknown());
        }
        let finalized = self.call("eth_getBlockByNumber", json!(["finalized", false]))?;
        if finalized.is_null() || quantity(&finalized["number"])? < block_number {
            return Ok(None);
        }
        let canonical = self.call(
            "eth_getBlockByNumber",
            json!([format!("0x{block_number:x}"), false]),
        )?;
        if quantity(&canonical["number"])? != block_number
            || !eq_hex(&canonical["hash"], &block_hash)
        {
            return Err(unknown());
        }
        if status == 1 {
            check_transfer(&receipt, token, &tx.to, &intent.recipient, &intent.amount)?;
            if let Some(mpp) = &intent.mpp_request {
                check_mpp_transfer(
                    &receipt,
                    token,
                    &tx.to,
                    &intent.recipient,
                    &intent.amount,
                    &allowit_tempo::mpp_memo(&mpp.challenge).map_err(|_| unknown())?,
                )?;
            }
        }
        Ok(Some(Finality {
            block_number: u64::try_from(block_number).map_err(|_| unknown())?,
            block_hash,
            success: status == 1,
        }))
    }
}
fn check_transaction(
    value: &Value,
    tx: &NativeTransaction,
    signed: &SignedTransaction,
) -> Result<()> {
    let calls = value["calls"].as_array().ok_or_else(unknown)?;
    if quantity(&value["type"])? != 0x76
        || !eq_hex(&value["hash"], &signed.hash)
        || !eq_hex(&value["from"], &signed.from)
        || quantity(&value["chainId"])? != u128::from(tx.chain_id)
        || !eq_hex(&value["feeToken"], &tx.fee_token)
        || quantity(&value["nonce"])? != u128::from(tx.nonce)
        || quantity(&value["nonceKey"])? != 0
        || quantity(&value["gas"])? != u128::from(tx.gas_limit)
        || quantity(&value["maxFeePerGas"])? != tx.max_fee_per_gas
        || quantity(&value["maxPriorityFeePerGas"])? != tx.max_priority_fee_per_gas
        || !value["accessList"]
            .as_array()
            .is_some_and(|list| list.is_empty())
        || !value["aaAuthorizationList"]
            .as_array()
            .is_some_and(|list| list.is_empty())
        || !value["feePayerSignature"].is_null()
        || !value["keyAuthorization"].is_null()
        || !value["validBefore"].is_null()
        || !value["validAfter"].is_null()
        || calls.len() != 1
        || !eq_hex(&calls[0]["to"], &tx.to)
        || quantity(&calls[0]["value"])? != 0
        || !eq_hex(calls[0].get("input").unwrap_or(&calls[0]["data"]), &tx.data)
    {
        return Err(unknown());
    }
    Ok(())
}
fn check_transfer(
    receipt: &Value,
    token: &str,
    vault: &str,
    recipient: &str,
    amount: &str,
) -> Result<()> {
    if !address(token) || !address(vault) || !address(recipient) {
        return Err(unknown());
    }
    let topic = allowit_tempo::hex(&allowit_tempo::keccak("Transfer(address,address,uint256)"));
    let owner = format!("0x{}{}", "0".repeat(24), &vault[2..]);
    let receiver = format!("0x{}{}", "0".repeat(24), &recipient[2..]);
    let units = allowit_tempo::units(amount).map_err(|_| unknown())?;
    let data = format!("0x{units:064x}");
    let logs = receipt["logs"].as_array().ok_or_else(unknown)?;
    let matches = logs
        .iter()
        .filter(|log| {
            eq_hex(&log["address"], token)
                && log["topics"].as_array().is_some_and(|topics| {
                    topics.len() == 3
                        && eq_hex(&topics[0], &topic)
                        && eq_hex(&topics[1], &owner)
                        && eq_hex(&topics[2], &receiver)
                })
                && eq_hex(&log["data"], &data)
                && log["removed"] != true
        })
        .count();
    if matches != 1 {
        return Err(unknown());
    }
    Ok(())
}
fn check_mpp_transfer(
    receipt: &Value,
    token: &str,
    vault: &str,
    recipient: &str,
    amount: &str,
    memo: &str,
) -> Result<()> {
    let topic = allowit_tempo::hex(&allowit_tempo::keccak(
        "TransferWithMemo(address,address,uint256,bytes32)",
    ));
    let sender = format!("0x{}{}", "0".repeat(24), &vault[2..]);
    let receiver = format!("0x{}{}", "0".repeat(24), &recipient[2..]);
    let data = format!(
        "0x{:064x}",
        allowit_tempo::units(amount).map_err(|_| unknown())?
    );
    let count = receipt["logs"]
        .as_array()
        .ok_or_else(unknown)?
        .iter()
        .filter(|log| {
            eq_hex(&log["address"], token)
                && log["removed"] != true
                && eq_hex(&log["data"], &data)
                && log["topics"].as_array().is_some_and(|t| {
                    t.len() == 4
                        && eq_hex(&t[0], &topic)
                        && eq_hex(&t[1], &sender)
                        && eq_hex(&t[2], &receiver)
                        && eq_hex(&t[3], memo)
                })
        })
        .count();
    if count != 1 {
        return Err(unknown());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::tests::{Reply, Seen, Server, serve};

    #[test]
    fn mpp_finality_requires_one_exact_challenge_bound_token_memo_from_vault() {
        let (tx, _, intent, token, _, _) = fixture();
        let memo =
            allowit_tempo::mpp_memo(&json!({"id":"original-charge","realm":"merchant.example"}))
                .unwrap();
        let receipt = json!({"logs":[{"address":token,"removed":false,"topics":[
            allowit_tempo::hex(&allowit_tempo::keccak("TransferWithMemo(address,address,uint256,bytes32)")),
            format!("0x{}{}","0".repeat(24),&tx.to[2..]),
            format!("0x{}{}","0".repeat(24),&intent.recipient[2..]),memo],"data":format!("0x{:064x}",1_000_000)}]});
        assert!(
            check_mpp_transfer(&receipt, &token, &tx.to, &intent.recipient, "1", &memo).is_ok()
        );
        for field in ["memo", "sender", "token", "removed", "duplicate", "amount"] {
            let mut changed = receipt.clone();
            match field {
                "memo" => {
                    changed["logs"][0]["topics"][3] = json!(
                        allowit_tempo::mpp_memo(
                            &json!({"id":"other-charge","realm":"merchant.example"})
                        )
                        .unwrap()
                    )
                }
                "sender" => {
                    changed["logs"][0]["topics"][1] = changed["logs"][0]["topics"][2].clone()
                }
                "token" => changed["logs"][0]["address"] = json!(intent.recipient),
                "removed" => changed["logs"][0]["removed"] = json!(true),
                "duplicate" => {
                    let duplicate = changed["logs"][0].clone();
                    changed["logs"].as_array_mut().unwrap().push(duplicate);
                }
                _ => changed["logs"][0]["data"] = json!(format!("0x{:064x}", 2_000_000)),
            }
            assert!(
                check_mpp_transfer(&changed, &token, &tx.to, &intent.recipient, "1", &memo)
                    .is_err(),
                "{field}"
            );
        }
    }

    fn rpc_script(results: Vec<Value>) -> (Rpc, Server) {
        let replies = results
            .into_iter()
            .map(|result| {
                let body = json!({"jsonrpc":"2.0","id":1,"result":result}).to_string();
                Reply::Status(200, Box::leak(body.into_boxed_str()))
            })
            .collect();
        let (client, server) = serve(replies);
        (
            Rpc {
                url: url::Url::parse(&client.cfg.origin).unwrap(),
                client: Client::builder()
                    .no_proxy()
                    .redirect(Policy::none())
                    .timeout(Duration::from_secs(2))
                    .build()
                    .unwrap(),
                chain_id: 42431,
                max_gas: 1_000_000,
                max_fee: 100_000_000_000_000_000,
            },
            server,
        )
    }

    fn assert_reads_only(seen: &[Seen]) {
        for request in seen {
            let value: Value = serde_json::from_slice(&request.body).unwrap();
            assert_ne!(value["method"], "eth_sendRawTransaction");
            assert!(!request.head.to_ascii_lowercase().contains("authorization:"));
        }
    }

    fn fixture() -> (
        NativeTransaction,
        SignedTransaction,
        Intent,
        String,
        Value,
        Value,
    ) {
        let tx = NativeTransaction {
            chain_id: 42431,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1000,
            gas_limit: 200_000,
            nonce: 9,
            to: "0x1111111111111111111111111111111111111111".into(),
            data: "0x12345678".into(),
            fee_token: "0x20c0000000000000000000000000000000000001".into(),
        };
        let mut key = [0; 32];
        key[31] = 1;
        let signed = tx.sign(&key).unwrap();
        let intent = Intent {
            id: "rpc-test-0001".into(),
            recipient: "0x2222222222222222222222222222222222222222".into(),
            amount: "1".into(),
            action: "transfer".into(),
            merchant: String::new(),
            context: json!({}),
            mpp_request: None,
        };
        let token = tx.fee_token.clone();
        let block_hash = format!("0x{}", "51".repeat(32));
        let chain_tx = json!({"type":"0x76","chainId":"0xa5bf","hash":signed.hash,"from":signed.from,
            "nonceKey":"0x0","nonce":"0x9","gas":"0x30d40","maxFeePerGas":"0x3e8","maxPriorityFeePerGas":"0x1",
            "feeToken":token,"calls":[{"to":tx.to,"value":"0x0","input":tx.data}],
            "accessList":[],"aaAuthorizationList":[],"feePayerSignature":null,"keyAuthorization":null,
            "validBefore":null,"validAfter":null,"blockNumber":"0x64","blockHash":block_hash});
        let receipt = json!({"transactionHash":signed.hash,"from":signed.from,"to":tx.to,
            "status":"0x1","blockNumber":"0x64","blockHash":block_hash,"logs":[{
                "address":token,"topics":[
                    allowit_tempo::hex(&allowit_tempo::keccak("Transfer(address,address,uint256)")),
                    format!("0x{}{}","0".repeat(24),&tx.to[2..]),
                    format!("0x{}{}","0".repeat(24),&intent.recipient[2..])],
                "data":format!("0x{:064x}",1_000_000),"removed":false}]});
        (tx, signed, intent, token, chain_tx, receipt)
    }

    fn finalized_script(chain_tx: Value, receipt: Value) -> Vec<Value> {
        vec![
            json!("0xa5bf"),
            receipt.clone(),
            chain_tx,
            json!({"number":"0x65"}),
            json!({"number":"0x64","hash":receipt["blockHash"]}),
        ]
    }

    #[test]
    fn finality_requires_finalized_height_and_canonical_payment_proof() {
        let (tx, signed, intent, token, chain_tx, receipt) = fixture();
        let (rpc, server) = rpc_script(finalized_script(chain_tx, receipt));
        let finality = rpc
            .finalized(&tx, &signed, &intent, &token)
            .unwrap()
            .unwrap();
        assert!(finality.success);
        assert_eq!(finality.block_number, 100);
        assert_eq!(finality.block_hash, format!("0x{}", "51".repeat(32)));
        let seen = server.finish();
        assert_eq!(seen.len(), 5);
        assert_reads_only(&seen);
        let request: Value = serde_json::from_slice(&seen[3].body).unwrap();
        assert_eq!(request["method"], "eth_getBlockByNumber");
        assert_eq!(request["params"], json!(["finalized", false]));
    }

    #[test]
    fn unavailable_receipt_or_finality_is_pending_without_broadcast() {
        let (tx, signed, intent, token, chain_tx, receipt) = fixture();
        for results in [
            vec![json!("0xa5bf"), Value::Null],
            vec![
                json!("0xa5bf"),
                receipt.clone(),
                chain_tx.clone(),
                Value::Null,
            ],
            vec![
                json!("0xa5bf"),
                receipt.clone(),
                chain_tx.clone(),
                json!({"number":"0x63"}),
            ],
        ] {
            let expected = results.len();
            let (rpc, server) = rpc_script(results);
            assert!(
                rpc.finalized(&tx, &signed, &intent, &token)
                    .unwrap()
                    .is_none()
            );
            let seen = server.finish();
            assert_eq!(seen.len(), expected);
            assert_reads_only(&seen);
        }
    }

    #[test]
    fn canonical_block_change_and_receipt_mismatch_stay_unknown() {
        let (tx, signed, intent, token, chain_tx, receipt) = fixture();
        let mut results = finalized_script(chain_tx.clone(), receipt.clone());
        results[4]["hash"] = json!(format!("0x{}", "52".repeat(32)));
        let (rpc, server) = rpc_script(results);
        assert_eq!(
            rpc.finalized(&tx, &signed, &intent, &token)
                .err()
                .unwrap()
                .code,
            5
        );
        assert_reads_only(&server.finish());
        for (field, value) in [
            ("transactionHash", json!(format!("0x{}", "aa".repeat(32)))),
            ("from", json!(intent.recipient)),
            ("to", json!(intent.recipient)),
            ("blockHash", json!(format!("0x{}", "52".repeat(32)))),
            ("status", json!("0x2")),
        ] {
            let mut changed = receipt.clone();
            changed[field] = value;
            let (rpc, server) = rpc_script(vec![json!("0xa5bf"), changed, chain_tx.clone()]);
            assert_eq!(
                rpc.finalized(&tx, &signed, &intent, &token)
                    .err()
                    .unwrap()
                    .code,
                5
            );
            assert_reads_only(&server.finish());
        }
    }

    #[test]
    fn finalized_revert_is_failed_execution_not_a_payment() {
        let (tx, signed, intent, token, chain_tx, mut receipt) = fixture();
        receipt["status"] = json!("0x0");
        receipt["logs"] = json!([]);
        let (rpc, server) = rpc_script(finalized_script(chain_tx, receipt));
        let finality = rpc
            .finalized(&tx, &signed, &intent, &token)
            .unwrap()
            .unwrap();
        assert!(!finality.success);
        assert_eq!(finality.block_number, 100);
        assert_reads_only(&server.finish());
    }

    #[test]
    fn chain_transaction_must_match_native_envelope_and_only_call() {
        let (tx, signed, intent, token, chain_tx, receipt) = fixture();
        let mut variants = Vec::new();
        for (field, value) in [
            ("type", json!("0x2")),
            ("chainId", json!("0x1")),
            ("hash", json!(format!("0x{}", "aa".repeat(32)))),
            ("from", json!(intent.recipient)),
            ("feeToken", json!(intent.recipient)),
            ("nonce", json!("0xa")),
            ("nonceKey", json!("0x1")),
            ("gas", json!("0x30d41")),
            ("maxFeePerGas", json!("0x3e9")),
            ("maxPriorityFeePerGas", json!("0x2")),
            ("accessList", json!([{"address":tx.to,"storageKeys":[]}])),
            ("aaAuthorizationList", json!([{}])),
            ("feePayerSignature", json!({})),
            ("keyAuthorization", json!({})),
            ("validBefore", json!("0x1")),
            ("validAfter", json!("0x1")),
        ] {
            let mut changed = chain_tx.clone();
            changed[field] = value;
            variants.push(changed);
        }
        for (field, value) in [
            ("to", json!(intent.recipient)),
            ("value", json!("0x1")),
            ("input", json!("0x12345679")),
        ] {
            let mut changed = chain_tx.clone();
            changed["calls"][0][field] = value;
            variants.push(changed);
        }
        let mut changed = chain_tx.clone();
        changed["calls"]
            .as_array_mut()
            .unwrap()
            .push(chain_tx["calls"][0].clone());
        variants.push(changed);
        let mut changed = chain_tx.clone();
        changed.as_object_mut().unwrap().remove("nonceKey");
        variants.push(changed);
        variants.push(Value::Null);
        for changed in variants {
            let (rpc, server) = rpc_script(vec![json!("0xa5bf"), receipt.clone(), changed]);
            assert_eq!(
                rpc.finalized(&tx, &signed, &intent, &token)
                    .err()
                    .unwrap()
                    .code,
                5
            );
            let seen = server.finish();
            assert_eq!(seen.len(), 3);
            assert_reads_only(&seen);
        }
        // Some RPC providers name the same call bytes data instead of input.
        let mut data_variant = chain_tx;
        let call = data_variant["calls"][0].as_object_mut().unwrap();
        let input = call.remove("input").unwrap();
        call.insert("data".into(), input);
        assert!(check_transaction(&data_variant, &tx, &signed).is_ok());
    }

    #[test]
    fn payment_logs_require_one_exact_nonremoved_transfer() {
        let (tx, signed, intent, token, chain_tx, receipt) = fixture();
        let mut variants = Vec::new();
        for changed in [
            json!({"address":intent.recipient,"topics":receipt["logs"][0]["topics"],"data":receipt["logs"][0]["data"]}),
            json!({"address":token,"topics":receipt["logs"][0]["topics"],"data":format!("0x{:064x}",2_000_000)}),
        ] {
            let mut value = receipt.clone();
            value["logs"] = json!([changed]);
            variants.push(value);
        }
        let mut value = receipt.clone();
        value["logs"][0]["topics"][1] = value["logs"][0]["topics"][2].clone();
        variants.push(value);
        let mut value = receipt.clone();
        value["logs"][0]["topics"][2] = value["logs"][0]["topics"][1].clone();
        variants.push(value);
        let mut value = receipt.clone();
        value["logs"][0]["removed"] = json!(true);
        variants.push(value);
        let mut value = receipt.clone();
        value["logs"]
            .as_array_mut()
            .unwrap()
            .push(receipt["logs"][0].clone());
        variants.push(value);
        let mut value = receipt.clone();
        value["logs"] = json!([]);
        variants.push(value);
        for changed in variants {
            let (rpc, server) = rpc_script(finalized_script(chain_tx.clone(), changed));
            assert_eq!(
                rpc.finalized(&tx, &signed, &intent, &token)
                    .err()
                    .unwrap()
                    .code,
                5
            );
            assert_reads_only(&server.finish());
        }
        for bad in ["", "x", "0xé"] {
            assert!(check_transfer(&receipt, &token, bad, &intent.recipient, "1").is_err());
            assert!(check_transfer(&receipt, &token, &tx.to, bad, "1").is_err());
        }
    }

    #[test]
    fn build_uses_protocol_pending_nonce_and_explicit_native_call() {
        let (tx, signed, _, _, _, _) = fixture();
        let plan = allowit_tempo::Transaction {
            chain_id: tx.chain_id,
            from: signed.from,
            to: tx.to.clone(),
            data: tx.data.clone(),
            value: "0x0".into(),
            fee_token: tx.fee_token.clone(),
        };
        let (rpc, server) = rpc_script(vec![
            json!("0xa5bf"),
            json!("0x9"),
            json!("0x9"),
            json!("0x5208"),
            json!("0x64"),
        ]);
        let built = rpc.build(&plan).unwrap();
        assert_eq!(built.nonce, 9);
        assert_eq!(built.gas_limit, 25_200);
        assert_eq!(built.max_fee_per_gas, 200);
        assert_eq!(built.fee_token, plan.fee_token);
        let seen = server.finish();
        assert_eq!(seen.len(), 5);
        assert_reads_only(&seen);
        let pending: Value = serde_json::from_slice(&seen[1].body).unwrap();
        assert_eq!(pending["params"], json!([plan.from, "pending"]));
        let estimation: Value = serde_json::from_slice(&seen[3].body).unwrap();
        let request = &estimation["params"][0];
        assert_eq!(estimation["method"], "eth_estimateGas");
        assert_eq!(request["type"], "0x76");
        assert_eq!(request["keyType"], "secp256k1");
        assert_eq!(request["nonceKey"], "0x0");
        assert_eq!(request["feeToken"], plan.fee_token);
        assert_eq!(
            request["calls"],
            json!([{"to":plan.to,"data":plan.data,"value":"0x0"}])
        );
        assert!(request.get("to").is_none());
        assert!(request.get("data").is_none());
    }

    #[test]
    fn wrong_chain_unresolved_nonce_and_gas_or_fee_caps_never_broadcast() {
        let (tx, signed, _, _, _, _) = fixture();
        let plan = allowit_tempo::Transaction {
            chain_id: tx.chain_id,
            from: signed.from.clone(),
            to: tx.to,
            data: tx.data,
            value: "0x0".into(),
            fee_token: tx.fee_token,
        };
        for results in [
            vec![json!("0x1")],
            vec![json!("0xa5bf"), json!("0xa"), json!("0x9")],
            vec![
                json!("0xa5bf"),
                json!("0x9"),
                json!("0x9"),
                json!("0xf4240"),
                json!("0x64"),
            ],
            vec![
                json!("0xa5bf"),
                json!("0x9"),
                json!("0x9"),
                json!("0x5208"),
                json!("0xffffffffffffffff"),
            ],
        ] {
            let expected = results.len();
            let (rpc, server) = rpc_script(results);
            assert!(rpc.build(&plan).is_err());
            let seen = server.finish();
            assert_eq!(seen.len(), expected);
            assert_reads_only(&seen);
        }
        // The broadcast gate itself also checks the chain before any send.
        let (rpc, server) = rpc_script(vec![json!("0x1")]);
        assert_eq!(rpc.send(&signed).err().unwrap().code, 3);
        let seen = server.finish();
        assert_eq!(seen.len(), 1);
        assert_reads_only(&seen);
    }

    #[test]
    fn known_null_and_matching_pending_transactions_use_only_saved_hash() {
        let (tx, signed, _, _, mut chain_tx, _) = fixture();
        chain_tx["blockNumber"] = Value::Null;
        chain_tx["blockHash"] = Value::Null;
        for (value, expected) in [(Value::Null, false), (chain_tx, true)] {
            let (rpc, server) = rpc_script(vec![json!("0xa5bf"), value]);
            assert_eq!(rpc.known(&tx, &signed).unwrap(), expected);
            let seen = server.finish();
            assert_eq!(seen.len(), 2);
            assert_reads_only(&seen);
            let request: Value = serde_json::from_slice(&seen[1].body).unwrap();
            assert_eq!(request["method"], "eth_getTransactionByHash");
            assert_eq!(request["params"], json!([signed.hash]));
        }
    }

    #[test]
    fn known_transaction_rejects_mismatched_body_sender_and_hash() {
        let (tx, signed, intent, _, chain_tx, _) = fixture();
        for (field, value) in [
            ("nonce", json!("0xa")),
            ("from", json!(intent.recipient)),
            ("hash", json!(format!("0x{}", "aa".repeat(32)))),
            ("type", json!("0x2")),
        ] {
            let mut changed = chain_tx.clone();
            changed[field] = value;
            let (rpc, server) = rpc_script(vec![json!("0xa5bf"), changed]);
            assert_eq!(rpc.known(&tx, &signed).err().unwrap().code, 5);
            let seen = server.finish();
            assert_eq!(seen.len(), 2);
            assert_reads_only(&seen);
        }
    }

    #[test]
    fn known_transaction_checks_chain_before_querying_saved_hash() {
        let (tx, signed, _, _, _, _) = fixture();
        let (rpc, server) = rpc_script(vec![json!("0x1")]);
        assert_eq!(rpc.known(&tx, &signed).err().unwrap().code, 3);
        let seen = server.finish();
        assert_eq!(seen.len(), 1);
        assert_reads_only(&seen);
    }

    #[test]
    fn quantities_are_bounded_exact_hex() {
        for bad in [
            json!(1),
            json!("1"),
            json!("0x"),
            json!("0x00"),
            json!("0x-1"),
            json!(format!("0x{}", "f".repeat(33))),
        ] {
            assert!(quantity(&bad).is_err());
        }
        assert_eq!(quantity(&json!("0xa5bf")).unwrap(), 42431);
    }
    #[test]
    fn transfer_proof_requires_exact_token_vault_recipient_and_amount() {
        let token = format!("0x{}", "20".repeat(20));
        let vault = format!("0x{}", "30".repeat(20));
        let recipient = format!("0x{}", "40".repeat(20));
        let receipt = json!({"logs":[{"address":token,"topics":[
            allowit_tempo::hex(&allowit_tempo::keccak("Transfer(address,address,uint256)")),
            format!("0x{}{}","0".repeat(24),&vault[2..]),format!("0x{}{}","0".repeat(24),&recipient[2..])],
            "data":format!("0x{:064x}",1_000_000)}]});
        assert!(check_transfer(&receipt, &token, &vault, &recipient, "1").is_ok());
        assert!(check_transfer(&receipt, &token, &vault, &recipient, "2").is_err());
        assert!(check_transfer(&receipt, &vault, &token, &recipient, "1").is_err());
        let mut removed = receipt.clone();
        removed["logs"][0]["removed"] = json!(true);
        assert!(check_transfer(&removed, &token, &vault, &recipient, "1").is_err());
    }
}
