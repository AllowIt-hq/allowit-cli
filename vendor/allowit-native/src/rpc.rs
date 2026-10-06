use crate::{
    crypto::Key,
    error::{Error, Result},
};
use base64::Engine;
use serde_json::{Value, json};
use std::{
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
/// Host-injected transport; tests can model missing responses without any keys.
pub trait Rpc: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value>;
}
pub struct HttpRpc {
    url: String,
    client: reqwest::blocking::Client,
    next: AtomicU64,
}
impl HttpRpc {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        let parsed = reqwest::Url::parse(&url).map_err(|_| Error::config("Invalid RPC URL"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(Error::config("Invalid RPC URL"));
        }
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .map_err(|_| Error::config("Cannot configure RPC connection"))?;
        Ok(Self {
            url,
            client,
            next: AtomicU64::new(1),
        })
    }
}
impl Rpc for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let body =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
                .map_err(|_| Error::config("Invalid RPC request"))?;
        let mut response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|_| Error::config("RPC request failed"))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::config("RPC request failed"));
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut response)
            .take(4_194_305)
            .read_to_end(&mut raw)
            .map_err(|_| Error::config("RPC response could not be read"))?;
        if raw.len() > 4_194_304 {
            return Err(Error::config("RPC response exceeded its size limit"));
        }
        let envelope: Value =
            serde_json::from_slice(&raw).map_err(|_| Error::config("Invalid RPC response"))?;
        if envelope["jsonrpc"] != "2.0" || envelope["id"] != id {
            return Err(Error::config("RPC response does not match the request"));
        }
        if !envelope["error"].is_null() {
            return Err(Error::config("RPC refused the request"));
        }
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| Error::config("Invalid RPC response"))
    }
}
#[derive(Debug, Clone)]
pub struct Account {
    pub owner: Key,
    pub executable: bool,
    pub data: Vec<u8>,
}
pub fn account(
    rpc: &dyn Rpc,
    address: Key,
    min_context_slot: Option<u64>,
) -> Result<Option<Account>> {
    let mut config = json!({"commitment":"finalized","encoding":"base64"});
    if let Some(slot) = min_context_slot {
        config["minContextSlot"] = json!(slot);
    }
    let response = rpc.call("getAccountInfo", json!([address.to_string(), config]))?;
    let observed = response["context"]["slot"]
        .as_u64()
        .ok_or_else(|| Error::config("Invalid account context"))?;
    if min_context_slot.is_some_and(|s| observed < s) {
        return Err(Error::config("Incoherent finalized vault observation"));
    }
    let value = &response["value"];
    if value.is_null() {
        return Ok(None);
    }
    let owner = Key::parse(
        value["owner"]
            .as_str()
            .ok_or_else(|| Error::config("Invalid account owner"))?,
    )?;
    let executable = value["executable"]
        .as_bool()
        .ok_or_else(|| Error::config("Invalid account executable flag"))?;
    if value["data"][1] != "base64" {
        return Err(Error::config("Invalid account encoding"));
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(
            value["data"][0]
                .as_str()
                .ok_or_else(|| Error::config("Invalid account data"))?,
        )
        .map_err(|_| Error::config("Invalid account data"))?;
    Ok(Some(Account {
        owner,
        executable,
        data,
    }))
}
