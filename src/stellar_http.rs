//! Bounded x402 HTTP transport. Keys never enter this module.
use crate::{
    VERSION,
    config::env_value,
    error::{Error, Result},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    blocking::{Client, Response},
    header::HeaderMap,
    redirect::Policy,
    tls::Version,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io::Read, time::Duration};

pub(crate) const MAX_BODY: usize = 65_536;
const MAX_HEADER: usize = 16_384;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Delivery {
    pub status: u16,
    pub receipt: Value,
    pub receipt_header: String,
    pub body: Option<String>,
}

pub(crate) fn endpoint(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw).map_err(|_| Error::usage("Invalid Stellar purchase URL"))?;
    if raw.len() > 4096
        || url.as_str() != raw
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::usage(
            "Use an exact HTTPS URL without credentials or fragment; query strings are supported",
        ));
    }
    Ok(url)
}

fn transport() -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .min_tls_version(Version::TLS_1_2)
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
        let pem = std::fs::read(ca).map_err(|_| Error::config("Cannot read ALLOWIT_CA_FILE"))?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|_| Error::config("Invalid ALLOWIT_CA_FILE"))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|_| Error::config("Cannot configure Stellar HTTPS transport"))
}

fn header(headers: &HeaderMap, name: &str) -> Result<String> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| Error::uncertain("The required x402 response header is missing"))?;
    if values.next().is_some() || value.as_bytes().len() > MAX_HEADER {
        return Err(Error::uncertain(
            "Ambiguous or oversized x402 response header",
        ));
    }
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|_| Error::uncertain("Invalid x402 response header"))
}

fn decoded_header(headers: &HeaderMap, name: &str) -> Result<Value> {
    let encoded = header(headers, name)?;
    let bytes = STANDARD
        .decode(&encoded)
        .map_err(|_| Error::uncertain("Invalid base64 x402 response header"))?;
    if bytes.len() > MAX_HEADER || STANDARD.encode(&bytes) != encoded {
        return Err(Error::uncertain(
            "Noncanonical or oversized x402 response header",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::uncertain("Invalid JSON x402 response header"))
}

fn body(response: Response) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    response
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            Error::uncertain("The paid response is unavailable; retain the original journal")
        })?;
    if bytes.len() > MAX_BODY {
        return Err(Error::uncertain(
            "The paid response exceeds 64 KiB; retain the original journal",
        ));
    }
    Ok(bytes)
}

pub(crate) fn quote(url: &str) -> Result<Value> {
    endpoint(url)?;
    let response = transport()?
        .get(url)
        .header("User-Agent", format!("allowit-cli/{VERSION}"))
        .send()
        .map_err(|_| Error::uncertain("The original x402 challenge is unavailable"))?;
    if response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
        return Err(Error::config(
            "The endpoint did not return an x402 402 challenge",
        ));
    }
    decoded_header(response.headers(), "payment-required")
}

/// Caller must fsync an attempted marker before invoking this function.
pub(crate) fn deliver(url: &str, credential: &str, request_id: &str) -> Result<Delivery> {
    endpoint(url)?;
    let response = transport()?
        .get(url)
        .header("User-Agent", format!("allowit-cli/{VERSION}"))
        .header("PAYMENT-SIGNATURE", credential)
        .header("Idempotency-Key", request_id)
        .send()
        .map_err(|_| {
            Error::uncertain("Payment or delivery is unresolved; resume the same request ID")
        })?;
    let status = response.status().as_u16();
    let receipt_header = header(response.headers(), "payment-response")?;
    let receipt = decoded_header(response.headers(), "payment-response")?;
    // Keep the exact original settlement header even when HTTP delivery fails.
    let body = body(response)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    Ok(Delivery {
        status,
        receipt,
        receipt_header,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_query_is_preserved_and_unsafe_url_is_refused() {
        let raw = "https://agent402.tools/api/weather?city=Almaty&units=metric";
        assert_eq!(endpoint(raw).unwrap().as_str(), raw);
        for raw in [
            "http://agent402.tools/x",
            "https://user:pass@agent402.tools/x",
            "https://agent402.tools/x#secret",
            "https://AGENT402.tools/x",
        ] {
            assert!(endpoint(raw).is_err());
        }
    }
    #[test]
    fn duplicate_or_noncanonical_headers_are_refused() {
        let mut headers = HeaderMap::new();
        let raw = STANDARD.encode(br#"{"x402Version":2}"#);
        headers.insert("payment-required", raw.parse().unwrap());
        assert_eq!(
            decoded_header(&headers, "payment-required").unwrap()["x402Version"],
            2
        );
        headers.append("payment-required", raw.parse().unwrap());
        assert!(decoded_header(&headers, "payment-required").is_err());
        headers.clear();
        headers.insert("payment-required", "not-base64".parse().unwrap());
        assert!(decoded_header(&headers, "payment-required").is_err());
    }
}
