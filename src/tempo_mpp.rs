//! Bounded MPP HTTP transport. No wallet, capability or signing key enters it.
use crate::{
    VERSION,
    config::env_value,
    error::{Error, Result},
    tempo::{Bundle, Intent, amount, request_id},
};
use allowit_tempo::MppPaymentRequest;
use mpp::{PaymentChallenge, PaymentCredential, PaymentPayload, Receipt};
use reqwest::{blocking::Client, header::HeaderMap, redirect::Policy, tls::Version};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Read, time::Duration};

const MAX_CHALLENGE: usize = 16_384;
const MAX_RECEIPT: usize = 4_096;
const MAX_RESPONSE: usize = 65_536;

pub(crate) struct CallOptions {
    pub url: String,
    pub id: String,
    pub max_amount: String,
    pub json_output: bool,
}
impl CallOptions {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut endpoint = None;
        let mut id = None;
        let mut max_amount = None;
        let mut json_output = false;
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--id" if id.is_none() => id = args.next().cloned(),
                "--max-amount" if max_amount.is_none() => max_amount = args.next().cloned(),
                "--json" if !json_output => json_output = true,
                _ if !arg.starts_with('-') && endpoint.is_none() => endpoint = Some(arg.clone()),
                _ => {
                    return Err(Error::usage(
                        "Use allowit tempo call URL --id REQUEST_ID --max-amount AMOUNT [--json]",
                    ));
                }
            }
        }
        let url = endpoint.ok_or_else(|| Error::usage("Missing HTTPS URL"))?;
        endpoint_url(&url)?;
        let id = id.ok_or_else(|| Error::usage("MPP call requires --id REQUEST_ID"))?;
        request_id(&id)?;
        let max_amount =
            max_amount.ok_or_else(|| Error::usage("MPP call requires --max-amount AMOUNT"))?;
        amount(&max_amount)?;
        Ok(Self {
            url,
            id,
            max_amount,
            json_output,
        })
    }
}

pub(crate) fn endpoint_url(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw).map_err(|_| Error::usage("Invalid MPP HTTPS URL"))?;
    if raw.len() > 2_048
        || url.as_str() != raw
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::usage(
            "MPP requires an exact HTTPS URL without query, fragment or credentials",
        ));
    }
    Ok(url)
}
pub(crate) fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error::config("Cannot determine MPP challenge validity"))
}
fn transport() -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .min_tls_version(Version::TLS_1_2)
        .timeout(Duration::from_secs(30));
    let ca = env_value("ALLOWIT_CA_FILE");
    if !ca.is_empty() {
        let bytes = std::fs::read(ca).map_err(|_| Error::config("Cannot read ALLOWIT_CA_FILE"))?;
        for cert in reqwest::Certificate::from_pem_bundle(&bytes)
            .map_err(|_| Error::config("Invalid ALLOWIT_CA_FILE"))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|_| Error::config("Cannot configure the MPP HTTPS transport"))
}
fn single_header<'a>(headers: &'a HeaderMap, name: &str, limit: usize) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| Error::config("Required MPP response header is missing"))?;
    if values.next().is_some() || value.as_bytes().len() > limit {
        return Err(Error::config(
            "MPP response headers are ambiguous or exceed the supported bound",
        ));
    }
    value
        .to_str()
        .map_err(|_| Error::config("Invalid MPP response header"))
}

/// The official parser handles syntax and core fields. This narrow adapter also
/// refuses duplicate/unknown parameters so an unsupported extension is never
/// silently removed from the merchant's original challenge echo.
fn supported_parameters(header: &str) -> Result<()> {
    let (scheme, parameters) = header
        .split_once(' ')
        .ok_or_else(|| Error::config("Invalid MPP challenge"))?;
    if !scheme.eq_ignore_ascii_case("Payment") || !header.is_ascii() || header.len() > MAX_CHALLENGE
    {
        return Err(Error::config("Expected one bounded MPP Payment challenge"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut chars = parameters.trim().chars().peekable();
    while chars.peek().is_some() {
        let mut key = String::new();
        while chars
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '-')
        {
            key.push(chars.next().unwrap());
        }
        while chars.peek().is_some_and(|c| matches!(*c, ' ' | '\t')) {
            chars.next();
        }
        if ![
            "id",
            "realm",
            "method",
            "intent",
            "request",
            "expires",
            "digest",
            "opaque",
            "description",
            "header",
        ]
        .contains(&key.as_str())
            || !seen.insert(key)
            || chars.next() != Some('=')
        {
            return Err(Error::config(
                "Unsupported or duplicate MPP challenge parameter",
            ));
        }
        while chars.peek().is_some_and(|c| matches!(*c, ' ' | '\t')) {
            chars.next();
        }
        if chars.next() != Some('"') {
            return Err(Error::config("MPP challenge parameters must be quoted"));
        }
        loop {
            match chars.next() {
                Some('"') => break,
                Some('\\') => {
                    if chars.next().is_none() {
                        return Err(Error::config("Invalid MPP challenge escape"));
                    }
                }
                Some(c) if !c.is_control() => {}
                _ => return Err(Error::config("Invalid MPP challenge value")),
            }
        }
        while chars.peek().is_some_and(|c| matches!(*c, ' ' | '\t')) {
            chars.next();
        }
        if chars.peek().is_some() {
            if chars.next() != Some(',') {
                return Err(Error::config("Invalid MPP challenge separator"));
            }
            while chars.peek().is_some_and(|c| matches!(*c, ' ' | '\t')) {
                chars.next();
            }
            if chars.peek().is_none() {
                return Err(Error::config("Invalid MPP challenge separator"));
            }
        }
    }
    Ok(())
}
pub(crate) fn parse_challenge(header: &str, url: &str) -> Result<MppPaymentRequest> {
    endpoint_url(url)?;
    supported_parameters(header)?;
    let challenge = PaymentChallenge::from_header(header)
        .map_err(|_| Error::config("Cannot parse the merchant's MPP challenge"))?;
    challenge
        .validate_for_charge("tempo")
        .map_err(|_| Error::config("MPP supports unexpired Tempo charge challenges only"))?;
    let challenge = serde_json::to_value(challenge.to_echo())
        .map_err(|_| Error::config("Cannot preserve the original MPP challenge"))?;
    Ok(MppPaymentRequest {
        version: 1,
        method: "GET".into(),
        url: url.into(),
        challenge,
    })
}
pub(crate) fn validate_intent(bundle: &Bundle, intent: &Intent, at: u64) -> Result<()> {
    let request = intent
        .mpp_request
        .as_ref()
        .ok_or_else(|| Error::config("Missing original MPP challenge"))?;
    let url = endpoint_url(&request.url)?;
    let header = request.challenge.get("header");
    if header.is_some_and(|v| {
        v.as_str().is_none_or(|s| {
            !s.eq_ignore_ascii_case("Authorization")
                && !s.eq_ignore_ascii_case("Payment-Authorization")
        })
    }) {
        return Err(Error::config(
            "Unsupported MPP credential header; no payment is authorized",
        ));
    }
    if intent.action != format!("GET {}", request.url)
        || intent.merchant != url.origin().ascii_serialization()
    {
        return Err(Error::config(
            "MPP request differs from its exact action and merchant",
        ));
    }
    allowit_tempo::validate_mpp_request(
        request,
        bundle.value["config"]["chainId"]
            .as_u64()
            .unwrap_or_default(),
        bundle.value["policy"]["token"].as_str().unwrap_or_default(),
        &intent.recipient,
        &intent.amount,
        at,
    )
    .map_err(|_| {
        Error::config("MPP challenge does not match the vault network, token or exact payment")
    })?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Purchase {
    pub max_amount: String,
    pub http_attempted: bool,
    pub response: Option<ApiResponse>,
    pub delivery_reported: bool,
}
impl Purchase {
    pub fn new(max_amount: String) -> Self {
        Self {
            max_amount,
            http_attempted: false,
            response: None,
            delivery_reported: false,
        }
    }
    pub fn matches(&self, bundle: &Bundle, intent: &Intent) -> Result<()> {
        amount(&self.max_amount)?;
        validate_intent(bundle, intent, 0)?;
        if allowit_tempo::units(&intent.amount)
            .map_err(|_| Error::config("Invalid MPP payment amount"))?
            > allowit_tempo::units(&self.max_amount)
                .map_err(|_| Error::config("Invalid MPP maximum amount"))?
            || (self.response.is_some() || self.delivery_reported) && !self.http_attempted
        {
            return Err(Error::config("Inconsistent original MPP purchase journal"));
        }
        if let Some(response) = &self.response {
            response.validate()?;
        }
        Ok(())
    }
}

pub(crate) fn fetch(
    bundle: &Bundle,
    url: &str,
    id: &str,
    maximum: &str,
) -> Result<(Intent, Purchase)> {
    endpoint_url(url)?;
    request_id(id)?;
    amount(maximum)?;
    let response = transport()?
        .get(url)
        .header("Accept", "application/json")
        .header("User-Agent", format!("allowit-cli/{VERSION}"))
        .send()
        .map_err(|_| Error::config("MPP challenge request failed; no payment was authorized"))?;
    if response.status().as_u16() != 402 {
        return Err(Error::config(format!(
            "MPP endpoint returned HTTP {}; expected 402. No payment was authorized",
            response.status().as_u16()
        )));
    }
    let request = parse_challenge(
        single_header(response.headers(), "www-authenticate", MAX_CHALLENGE)?,
        url,
    )?;
    let parsed = PaymentChallenge::from_header(single_header(
        response.headers(),
        "www-authenticate",
        MAX_CHALLENGE,
    )?)
    .map_err(|_| Error::config("Invalid MPP challenge"))?;
    let body: Value = serde_json::from_slice(
        &mpp::base64url_decode(parsed.request.raw())
            .map_err(|_| Error::config("Invalid encoded MPP payment request"))?,
    )
    .map_err(|_| Error::config("Invalid MPP payment request JSON"))?;
    let units = body["amount"]
        .as_str()
        .ok_or_else(|| Error::config("MPP payment amount is missing"))?;
    if units.is_empty()
        || units.len() > 78
        || !units.bytes().all(|b| b.is_ascii_digit())
        || units.starts_with('0')
    {
        return Err(Error::config(
            "MPP requires a positive canonical base-unit amount",
        ));
    }
    let integer = num_bigint::BigUint::parse_bytes(units.as_bytes(), 10)
        .ok_or_else(|| Error::config("Invalid MPP amount"))?;
    let scale = num_bigint::BigUint::from(1_000_000u32);
    let quantity = format!(
        "{}.{:0>6}",
        &integer / &scale,
        (&integer % &scale).to_string()
    );
    amount(&quantity)?;
    if allowit_tempo::units(&quantity).map_err(|_| Error::config("Invalid MPP amount"))?
        > allowit_tempo::units(maximum).map_err(|_| Error::usage("Invalid --max-amount"))?
    {
        return Err(Error::config(
            "MPP charge exceeds --max-amount; no payment was authorized",
        ));
    }
    let endpoint = endpoint_url(url)?;
    let intent = Intent {
        id: id.into(),
        recipient: body["recipient"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        amount: quantity,
        action: format!("GET {url}"),
        merchant: endpoint.origin().ascii_serialization(),
        context: json!({}),
        mpp_request: Some(request),
    };
    validate_intent(bundle, &intent, now()?)?;
    Ok((intent, Purchase::new(maximum.into())))
}

pub(crate) fn credential(
    request: &MppPaymentRequest,
    chain: u64,
    vault: &str,
    hash: &str,
) -> Result<(String, String)> {
    let echo: mpp::ChallengeEcho = serde_json::from_value(request.challenge.clone())
        .map_err(|_| Error::config("Invalid saved MPP challenge"))?;
    // The vault is the actual TIP-20 transfer sender. Using the executor DID
    // would fail the merchant's real TransferWithMemo sender check.
    let value = PaymentCredential::with_source(
        echo,
        PaymentCredential::evm_did(chain, vault),
        PaymentPayload::hash(hash),
    );
    let header_name = request.challenge["header"]
        .as_str()
        .unwrap_or("Authorization");
    if !header_name.eq_ignore_ascii_case("Authorization")
        && !header_name.eq_ignore_ascii_case("Payment-Authorization")
    {
        return Err(Error::config("Unsupported MPP credential header"));
    }
    let header = mpp::format_authorization(&value)
        .map_err(|_| Error::config("Cannot format the MPP credential"))?;
    if header.len() > 32_768 {
        return Err(Error::config("MPP credential exceeds the supported bound"));
    }
    Ok((header_name.into(), header))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApiResponse {
    pub state: String,
    pub http_status: Option<u16>,
    pub receipt: Option<Value>,
    pub body: Option<String>,
    pub response_digest: Option<String>,
    pub response_bytes: Option<usize>,
}
impl ApiResponse {
    pub fn unavailable() -> Self {
        Self {
            state: "response_unavailable".into(),
            http_status: None,
            receipt: None,
            body: None,
            response_digest: None,
            response_bytes: None,
        }
    }
    fn validate(&self) -> Result<()> {
        if !["response_received", "response_unavailable"].contains(&self.state.as_str())
            || self.http_status.is_some_and(|s| !(200..=599).contains(&s))
            || self.body.as_ref().is_some_and(|b| b.len() > MAX_RESPONSE)
            || self.state == "response_received"
                && (self.receipt.is_none()
                    || self.body.is_none()
                    || self.response_digest.is_none()
                    || self.response_bytes.is_none()
                    || !self.http_status.is_some_and(|s| (200..300).contains(&s)))
        {
            return Err(Error::config("Invalid saved MPP response"));
        }
        if self.state == "response_unavailable"
            && (self.body.is_some()
                || self.receipt.is_some()
                || self.response_digest.is_some()
                || self.response_bytes.is_some())
        {
            return Err(Error::config(
                "Unavailable MPP response cannot claim a returned body or receipt",
            ));
        }
        if let Some(body) = &self.body
            && (self.response_bytes != Some(body.len())
                || self.response_digest.as_deref() != Some(&digest(body.as_bytes())))
        {
            return Err(Error::config("Saved MPP response differs from its digest"));
        }
        Ok(())
    }
    pub fn public_report(&self, challenge_digest: &str) -> Value {
        let mut result = json!({"status":if self.state == "response_received" {"response_reported"} else {"response_unavailable"}, "challengeDigest":challenge_digest});
        if let Some(status) = self.http_status {
            result["httpStatus"] = json!(status);
        }
        if let Some(receipt) = &self.receipt {
            result["receipt"] = receipt.clone();
        }
        if let Some(hash) = &self.response_digest {
            result["responseDigest"] = json!(hash);
        }
        if let Some(bytes) = &self.response_bytes {
            result["responseBytes"] = json!(bytes);
        }
        result
    }
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("0x{:x}", Sha256::digest(bytes))
}
pub(crate) fn checked_receipt_header(header: &str, hash: &str) -> Result<Value> {
    if header.len() > MAX_RECEIPT {
        return Err(Error::config("MPP receipt exceeds the supported bound"));
    }
    let receipt =
        Receipt::from_header(header).map_err(|_| Error::config("Invalid MPP Payment-Receipt"))?;
    if !receipt.is_success()
        || receipt.method.as_str() != "tempo"
        || !receipt.reference.eq_ignore_ascii_case(hash)
        || receipt.timestamp.len() > 40
        || time::OffsetDateTime::parse(
            &receipt.timestamp,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(Error::config(
            "MPP receipt does not acknowledge this exact payment",
        ));
    }
    Ok(
        json!({"status":"success","method":"tempo","timestamp":receipt.timestamp,"reference":hash.to_ascii_lowercase()}),
    )
}

/// Exactly one credential-bearing GET. The caller persists http_attempted before
/// invoking this method; timeouts/crashes may consume the proof and are not retried.
pub(crate) fn deliver(
    request: &MppPaymentRequest,
    chain: u64,
    vault: &str,
    hash: &str,
) -> ApiResponse {
    let send = || -> Result<reqwest::blocking::Response> {
        endpoint_url(&request.url)?;
        let (name, proof) = credential(request, chain, vault, hash)?;
        transport()?.get(&request.url).header("Accept", "application/json")
            .header("User-Agent", format!("allowit-cli/{VERSION}")).header(name, proof).send()
            .map_err(|_| Error::uncertain("MPP response unavailable after payment; the credential is not automatically retried"))
    };
    match send() {
        Ok(response) => receive_response(response, hash),
        Err(_) => ApiResponse::unavailable(),
    }
}
fn receive_response(mut response: reqwest::blocking::Response, hash: &str) -> ApiResponse {
    let status = response.status().as_u16();
    let mut unavailable = ApiResponse::unavailable();
    unavailable.http_status = Some(status);
    if !(200..300).contains(&status) {
        return unavailable;
    }
    let mut read = || -> Result<ApiResponse> {
        let receipt = checked_receipt_header(
            single_header(response.headers(), "payment-receipt", MAX_RECEIPT)?,
            hash,
        )?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut response)
            .take((MAX_RESPONSE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::uncertain("MPP response body is unavailable"))?;
        if bytes.len() > MAX_RESPONSE {
            return Err(Error::config("MPP response exceeds 64 KB"));
        }
        let body = String::from_utf8(bytes)
            .map_err(|_| Error::config("MPP supports UTF-8 response bodies only"))?;
        let mut result = ApiResponse::unavailable();
        result.http_status = Some(status);
        result.state = "response_received".into();
        result.receipt = Some(receipt);
        result.response_digest = Some(digest(body.as_bytes()));
        result.response_bytes = Some(body.len());
        result.body = Some(body);
        Ok(result)
    };
    read().unwrap_or(unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    const TOKEN: &str = "0x20c0000000000000000000000000000000000001";
    const RECIPIENT: &str = "0x2222222222222222222222222222222222222222";
    const VAULT: &str = "0x3333333333333333333333333333333333333333";
    const HASH: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
    fn request() -> MppPaymentRequest {
        let mut terms = json!({"amount":"250000","currency":TOKEN,"recipient":RECIPIENT,
            "methodDetails":{"chainId":42431,"feePayer":false,"supportedModes":["push"]}});
        terms.sort_all_objects();
        let challenge = PaymentChallenge::new(
            "charge-1",
            "merchant.example",
            "tempo",
            "charge",
            mpp::Base64UrlJson::from_value(&terms).unwrap(),
        );
        parse_challenge(
            &challenge.to_header().unwrap(),
            "https://merchant.example/paid",
        )
        .unwrap()
    }
    fn bundle() -> Bundle {
        Bundle::verification_context(
            json!({"chainId":42431}),
            json!({"token":TOKEN}),
            "https://allowit.example",
        )
    }
    fn intent(request: MppPaymentRequest) -> Intent {
        Intent {
            id: "mpp-call-0001".into(),
            recipient: RECIPIENT.into(),
            amount: "0.250000".into(),
            action: format!("GET {}", request.url),
            merchant: "https://merchant.example".into(),
            context: json!({}),
            mpp_request: Some(request),
        }
    }
    fn receipt() -> String {
        Receipt::success("tempo", HASH).to_header().unwrap()
    }
    fn response(
        status: u16,
        headers: String,
        body: Vec<u8>,
    ) -> (reqwest::blocking::Response, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/paid", listener.local_addr().unwrap());
        let test = listener.try_clone().unwrap();
        let join = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                stream.read_exact(&mut b).unwrap();
                head.push(b[0]);
            }
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: {}\r\n{}\r\n",
                body.len(),
                headers
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            String::from_utf8(head).unwrap()
        });
        let result = transport().unwrap().get(&endpoint).send().unwrap();
        let head = join.join().unwrap();
        test.set_nonblocking(true).unwrap();
        assert!(
            matches!(test.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "No redirect or second request is allowed"
        );
        (result, head)
    }

    #[test]
    fn explicit_call_id_and_cap_are_required_and_unknown_flags_rejected() {
        let args = [
            "https://merchant.example/paid",
            "--id",
            "mpp-call-0001",
            "--max-amount",
            "0.25",
            "--json",
        ]
        .map(str::to_string);
        let options = CallOptions::parse(&args).unwrap();
        assert_eq!(options.id, "mpp-call-0001");
        assert!(options.json_output);
        for args in [
            vec!["https://merchant.example/paid"],
            vec!["https://merchant.example/paid", "--id", "mpp-call-0001"],
            vec![
                "https://merchant.example/paid",
                "--id",
                "mpp-call-0001",
                "--max-amount",
                "0.0000001",
            ],
            vec![
                "https://merchant.example/paid",
                "--id",
                "mpp-call-0001",
                "--max-amount",
                "1",
                "--header",
                "secret",
            ],
        ] {
            assert!(
                CallOptions::parse(&args.into_iter().map(str::to_string).collect::<Vec<_>>())
                    .is_err()
            );
        }
    }
    #[test]
    fn only_exact_https_get_urls_can_receive_credentials() {
        for url in [
            "http://merchant.example/paid",
            "https://u:p@merchant.example/paid",
            "https://merchant.example/paid?token=secret",
            "https://merchant.example/paid#fragment",
            "https://Merchant.example/paid",
            "https://merchant.example:443/paid",
            "https://merchant.example",
            "https://merchant.example/a/../paid",
        ] {
            assert!(endpoint_url(url).is_err(), "{url}");
        }
        assert!(endpoint_url("https://merchant.example/paid").is_ok());
    }
    #[test]
    fn official_sdk_preserves_original_challenge_and_vault_source() {
        let request = request();
        let (name, header) = credential(&request, 42431, VAULT, HASH).unwrap();
        assert_eq!(name, "Authorization");
        let parsed = PaymentCredential::from_header(&header).unwrap();
        assert_eq!(
            serde_json::to_value(&parsed.challenge).unwrap(),
            request.challenge
        );
        assert_eq!(
            parsed.source.as_ref().unwrap(),
            &format!("did:pkh:eip155:42431:{VAULT}")
        );
        assert_eq!(parsed.charge_payload().unwrap().tx_hash(), Some(HASH));
        assert!(!header.contains("tempo-executor."));
        let mut changed = request.clone();
        changed.challenge["header"] = json!("Cookie");
        assert!(credential(&changed, 42431, VAULT, HASH).is_err());
    }
    #[test]
    fn duplicate_unknown_oversized_and_expired_challenges_fail_closed() {
        let terms = request().challenge["request"].as_str().unwrap().to_owned();
        let header = format!(
            "Payment id=\"a\", realm=\"merchant.example\", method=\"tempo\", intent=\"charge\", request=\"{terms}\""
        );
        assert!(parse_challenge(&header, "https://merchant.example/paid").is_ok());
        for suffix in [
            ", id=\"different\"",
            ", extension=\"unsupported\"",
            ", expires=\"1970-01-01T00:00:00Z\"",
            ", expires=\"invalid\"",
            ", header=\"Cookie\"",
            ", Payment id=\"other\"",
        ] {
            assert!(
                parse_challenge(&(header.clone() + suffix), "https://merchant.example/paid")
                    .is_err(),
                "{suffix}"
            );
        }
        assert!(
            parse_challenge(
                &(header + &" ".repeat(MAX_CHALLENGE)),
                "https://merchant.example/paid"
            )
            .is_err()
        );
    }
    #[test]
    fn tampered_terms_or_url_do_not_pass_existing_vault_scope() {
        let original = intent(request());
        validate_intent(&bundle(), &original, now().unwrap()).unwrap();
        for field in ["recipient", "amount", "action", "merchant"] {
            let mut changed = original.clone();
            match field {
                "recipient" => changed.recipient = VAULT.into(),
                "amount" => changed.amount = "0.5".into(),
                "action" => changed.action = "GET https://merchant.example/other".into(),
                _ => changed.merchant = "https://evil.example".into(),
            }
            assert!(
                validate_intent(&bundle(), &changed, now().unwrap()).is_err(),
                "{field}"
            );
        }
        let mut changed = bundle();
        changed.value["config"]["chainId"] = json!(4217);
        assert!(validate_intent(&changed, &original, now().unwrap()).is_err());
        let mut changed = original.clone();
        changed.mpp_request.as_mut().unwrap().challenge["header"] = json!("Cookie");
        assert!(validate_intent(&bundle(), &changed, now().unwrap()).is_err());
    }
    #[test]
    fn receipt_must_acknowledge_exact_hash_method_status_and_timestamp() {
        assert!(checked_receipt_header(&receipt(), HASH).is_ok());
        for field in ["reference", "method", "status", "timestamp"] {
            let mut value = json!({"status":"success","method":"tempo","timestamp":"2026-10-13T00:00:00Z","reference":HASH});
            value[field] = json!(match field {
                "reference" => VAULT,
                "method" => "stripe",
                "status" => "failed",
                _ => "invalid",
            });
            let header = mpp::base64url_encode(&serde_json::to_vec(&value).unwrap());
            assert!(checked_receipt_header(&header, HASH).is_err(), "{field}");
        }
        assert!(checked_receipt_header(&"A".repeat(MAX_RECEIPT + 1), HASH).is_err());
    }
    #[test]
    fn bounded_real_http_response_returns_useful_body_and_keeps_it_out_of_report() {
        let body = b"{\"answer\":42,\"text\":\"real API result\"}".to_vec();
        let (response, head) = response(
            200,
            format!("Payment-Receipt: {}\r\n", receipt()),
            body.clone(),
        );
        assert!(head.starts_with("GET /paid "));
        assert!(!head.to_ascii_lowercase().contains("authorization:"));
        let read = receive_response(response, HASH);
        read.validate().unwrap();
        assert_eq!(read.body.as_ref().unwrap().as_bytes(), body);
        assert_eq!(read.state, "response_received");
        let report = read.public_report(&digest(b"challenge"));
        assert!(report.get("body").is_none());
        assert!(!report.to_string().contains("real API result"));
        assert_eq!(report["responseBytes"], body.len());
    }
    #[test]
    fn redirect_second_challenge_binary_and_oversize_never_mean_response_received() {
        for (status, headers, body) in [
            (
                302,
                "Location: https://other.example/paid\r\n".into(),
                Vec::new(),
            ),
            (
                402,
                "WWW-Authenticate: Payment id=\"new\"\r\n".into(),
                Vec::new(),
            ),
            (200, String::new(), b"receipt missing".to_vec()),
            (
                200,
                format!(
                    "Payment-Receipt: {}\r\nPayment-Receipt: {}\r\n",
                    receipt(),
                    receipt()
                ),
                Vec::new(),
            ),
            (
                200,
                format!("Payment-Receipt: {}\r\n", receipt()),
                vec![0xff],
            ),
            (
                200,
                format!("Payment-Receipt: {}\r\n", receipt()),
                vec![b'X'; MAX_RESPONSE + 1],
            ),
        ] {
            let (response, _) = response(status, headers, body);
            let read = receive_response(response, HASH);
            assert_eq!(read.state, "response_unavailable");
            assert_eq!(read.http_status, Some(status));
            assert!(read.body.is_none());
            assert!(read.receipt.is_none());
        }
    }
}
