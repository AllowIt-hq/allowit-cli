//! Executor-only native signing and durable recovery. Owner operations stay on the website.
use crate::{
    config::env_value,
    error::{Error, Result},
    tempo::{Bundle, Intent, checked_plan, checked_receipt, prepare, request_id},
    tempo_rpc::{Chain, Finality, Rpc},
    tempo_store::Store,
    tempo_transaction::{NativeTransaction, SignedTransaction, executor_address},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    origin: String,
    config: Value,
    policy: Value,
    intent: Intent,
    preparation: Option<Value>,
    prepare_code: Option<i32>,
    native: Option<NativeTransaction>,
    signed: Option<SignedTransaction>,
    attempted: bool,
    finality: Option<Finality>,
    report: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purchase: Option<crate::tempo_mpp::Purchase>,
}
impl Record {
    fn new(bundle: &Bundle, intent: Intent) -> Self {
        Self {
            version: 1,
            origin: bundle.origin.clone(),
            config: bundle.value["config"].clone(),
            policy: bundle.value["policy"].clone(),
            intent,
            preparation: None,
            prepare_code: None,
            native: None,
            signed: None,
            attempted: false,
            finality: None,
            report: None,
            purchase: None,
        }
    }
    fn matches(&self, bundle: &Bundle) -> Result<()> {
        if self.version != 1
            || self.origin != bundle.origin
            || self.config != bundle.value["config"]
            || self.policy != bundle.value["policy"]
        {
            return Err(Error::config(
                "Saved Tempo request belongs to a different policy or configuration; preserve its original bundle",
            ));
        }
        request_id(&self.intent.id)?;
        if self.intent.mpp_request.is_some() != self.purchase.is_some() {
            return Err(Error::config(
                "MPP intent is missing its original private HTTP journal",
            ));
        }
        if let Some(purchase) = &self.purchase {
            purchase.matches(bundle, &self.intent)?;
            if purchase.http_attempted
                && (!self.finality.as_ref().is_some_and(|f| f.success)
                    || self
                        .report
                        .as_ref()
                        .is_none_or(|r| r["operation"]["status"] != "settled"))
            {
                return Err(Error::config(
                    "MPP response attempt is missing a finalized settled payment",
                ));
            }
            if let Some(receipt) = purchase.response.as_ref().and_then(|r| r.receipt.as_ref()) {
                let hash = self
                    .signed
                    .as_ref()
                    .map(|s| s.hash.as_str())
                    .unwrap_or_default();
                let header = mpp::format_receipt(
                    &serde_json::from_value(receipt.clone())
                        .map_err(|_| Error::config("Invalid saved MPP receipt"))?,
                )
                .map_err(|_| Error::config("Invalid saved MPP receipt"))?;
                crate::tempo_mpp::checked_receipt_header(&header, hash)?;
            }
        }
        if let Some(finality) = &self.finality {
            let h = &finality.block_hash;
            if h.len() != 66
                || !h.starts_with("0x")
                || !h[2..].bytes().all(|b| b.is_ascii_hexdigit())
                || self
                    .report
                    .as_ref()
                    .is_some_and(|r| r["operation"]["status"] == "settled" && !finality.success)
            {
                return Err(Error::config(
                    "Contradictory Tempo finality evidence; preserve the original journal",
                ));
            }
        }
        if self.native.is_some() != self.signed.is_some()
            || (self.attempted || self.finality.is_some() || self.report.is_some())
                && self.signed.is_none()
        {
            return Err(Error::config(
                "Incomplete Tempo journal; recover the original signed proof before paying",
            ));
        }
        if let Some(signed) = &self.signed {
            let native = self
                .native
                .as_ref()
                .ok_or_else(|| Error::config("Missing native proof"))?;
            let plan = checked_plan(
                bundle,
                &self.intent,
                self.preparation
                    .as_ref()
                    .ok_or_else(|| Error::config("Missing Tempo authorization"))?,
            )?;
            if self.prepare_code != Some(10)
                || native.chain_id != plan.chain_id
                || !native.to.eq_ignore_ascii_case(&plan.to)
                || !native.data.eq_ignore_ascii_case(&plan.data)
                || !native.fee_token.eq_ignore_ascii_case(&plan.fee_token)
                || !signed.from.eq_ignore_ascii_case(&plan.from)
            {
                return Err(Error::config(
                    "Saved native transaction differs from its exact authorized payment",
                ));
            }
            native.verify(signed)?;
        }
        Ok(())
    }
}
fn state_path(bundle: &Bundle) -> Result<PathBuf> {
    let explicit = env_value("ALLOWIT_TEMPO_STATE_DIR");
    let base = if explicit.is_empty() {
        let state = env_value("XDG_STATE_HOME");
        if state.is_empty() {
            let home = env_value("HOME");
            if home.is_empty() {
                return Err(Error::config(
                    "Set ALLOWIT_TEMPO_STATE_DIR to a private local POSIX directory",
                ));
            }
            PathBuf::from(home).join(".local/state/allowit/tempo")
        } else {
            PathBuf::from(state).join("allowit/tempo")
        }
    } else {
        PathBuf::from(explicit)
    };
    let chain = bundle.value["config"]["chainId"]
        .as_u64()
        .ok_or_else(|| Error::config("Invalid Tempo chain"))?;
    let executor = bundle.value["config"]["executor"]
        .as_str()
        .ok_or_else(|| Error::config("Invalid Tempo executor"))?;
    Ok(base.join(format!("{chain}-{}", executor.to_ascii_lowercase())))
}
fn read_key(path: &std::path::Path, expected: &str) -> Result<Zeroizing<[u8; 32]>> {
    allowit_native::journal::require_supported_platform().map_err(|_| {
        Error::config("Tempo signing requires Linux/WSL and private local POSIX key storage")
    })?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|_| Error::config("Cannot read the private Tempo executor key file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::config("Cannot inspect the Tempo executor key file"))?;
    if !metadata.is_file() {
        return Err(Error::config(
            "Tempo executor key must be a private regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::config(
                "Tempo executor key must be owned by the current user with mode 0600 and no hard links",
            ));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.by_ref()
        .take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::config("Cannot read the Tempo executor key"))?;
    if bytes.len() > 128 {
        return Err(Error::config(
            "Tempo executor key must contain one 32-byte hexadecimal secret",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::config("Invalid Tempo executor key encoding"))?
        .trim();
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::config(
            "Tempo executor key must contain one 32-byte hexadecimal secret",
        ));
    }
    let mut key = Zeroizing::new([0; 32]);
    for (i, value) in key.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .map_err(|_| Error::config("Invalid Tempo executor key"))?;
    }
    if !executor_address(&key)?.eq_ignore_ascii_case(expected) {
        return Err(Error::config(
            "Tempo signing key is not the policy's designated executor",
        ));
    }
    Ok(key)
}
fn wait_duration() -> Result<Duration> {
    let value = env_value("ALLOWIT_TEMPO_WAIT_SECONDS");
    let seconds = if value.is_empty() {
        120
    } else {
        value
            .parse::<u64>()
            .map_err(|_| Error::config("Invalid ALLOWIT_TEMPO_WAIT_SECONDS"))?
    };
    if seconds > 600 {
        return Err(Error::config(
            "Tempo confirmation wait must be between 0 and 600 seconds",
        ));
    }
    Ok(Duration::from_secs(seconds))
}
fn block_other_proof<C: Chain>(store: &Store, current: &Record, chain: &C) -> Result<()> {
    for record in store.entries::<Record>()? {
        record.matches(&Bundle::verification_context(
            record.config.clone(),
            record.policy.clone(),
            &record.origin,
        ))?;
        let named = store.load::<Record>(&record.intent.id)?.ok_or_else(|| {
            Error::config("Tempo request identity differs from its journal filename")
        })?;
        if serde_json::to_value(&named).map_err(|_| Error::config("Invalid Tempo journal"))?
            != serde_json::to_value(&record).map_err(|_| Error::config("Invalid Tempo journal"))?
        {
            return Err(Error::config(
                "Tempo request identity differs from its journal filename",
            ));
        }
        if record.version != 1
            || record.config["chainId"] != current.config["chainId"]
            || record.config["executor"].as_str().is_none_or(|s| {
                !s.eq_ignore_ascii_case(current.config["executor"].as_str().unwrap_or_default())
            })
            || record.signed.is_some() != record.native.is_some()
        {
            return Err(Error::config(
                "Inconsistent executor journal; recover the original records before paying",
            ));
        }
        if record.intent.id != current.intent.id
            && let Some(signed) = &record.signed
        {
            let finalized = if let Some(saved) = &record.finality {
                chain
                    .finalized(
                        record.native.as_ref().unwrap(),
                        signed,
                        &record.intent,
                        record.policy["token"].as_str().unwrap_or_default(),
                    )?
                    .is_some_and(|proof| {
                        proof.block_number == saved.block_number
                            && proof.block_hash.eq_ignore_ascii_case(&saved.block_hash)
                            && proof.success == saved.success
                    })
            } else {
                false
            };
            if !finalized {
                return Err(Error::uncertain(format!(
                    "Executor has an unresolved signed request {}. Run allowit tempo resume with its original bundle before making another payment",
                    record.intent.id
                )));
            }
        }
    }
    Ok(())
}
fn result(record: &Record, state: &str, code: i32, details: Option<Value>) -> Value {
    let mut value = json!({"requestId":record.intent.id,"policyId":record.policy["id"],
        "network":record.config["network"],"chainId":record.config["chainId"],"vault":record.policy["vault"],
        "recipient":record.intent.recipient,"amount":record.intent.amount,"token":record.policy["token"],
        "state":state,"exitCode":code});
    if let Some(signed) = &record.signed {
        value["transactionHash"] = json!(signed.hash);
    }
    if let Some(finality) = &record.finality {
        value["finality"] = json!(finality);
    }
    if let Some(request) = &record.intent.mpp_request {
        value["url"] = json!(request.url);
        value["httpMethod"] = json!(request.method);
    }
    if let Some(details) = details {
        value["result"] = details;
    }
    value
}
fn render(bundle: &Bundle, value: &Value, json_output: bool) -> String {
    let rendered = if json_output {
        let mut value = value.clone();
        value.sort_all_objects();
        serde_json::to_string_pretty(&value).unwrap() + "\n"
    } else {
        let mut text = format!(
            "Tempo request {}\nVault: {}\nAmount: {} (token {})\n",
            value["requestId"].as_str().unwrap_or_default(),
            value["vault"].as_str().unwrap_or_default(),
            value["amount"].as_str().unwrap_or_default(),
            value["token"].as_str().unwrap_or_default()
        );
        if let Some(hash) = value["transactionHash"].as_str() {
            text.push_str(&format!("Transaction: {hash}\n"));
        }
        if let Some(url) = value["url"].as_str() {
            text.push_str(&format!("API request: GET {url}\n"));
        }
        let status = match value["state"].as_str() {
            Some("settled") => "Payment confirmed (finalized)",
            Some("denied") => "Payment denied",
            Some("awaiting_input") => "Awaiting owner input",
            Some("replayed") => "Service reports an already settled request; no new payment sent",
            Some("failed") => "Transaction failed (finalized)",
            Some("submitted") => "Submitted; finality pending",
            _ => "Outcome uncertain; resume the same request",
        };
        text.push_str(status);
        text.push('\n');
        for field in ["decisionCode", "reason"] {
            if let Some(reason) = value["result"][field].as_str() {
                text.push_str(&format!(
                    "{field}: {}\n",
                    serde_json::to_string(reason).unwrap()
                ));
            }
        }
        if matches!(value["state"].as_str(), Some("submitted" | "uncertain")) {
            text.push_str(&format!(
                "Resume: allowit tempo resume {}\n",
                value["requestId"].as_str().unwrap_or_default()
            ));
        }
        if let Some(purchase) = value.get("purchase") {
            let received = purchase["state"] == "response_received";
            text.push_str(if received { "API response received\n" } else {
                "API response unavailable; payment remains confirmed. The HTTP credential is not retried.\n"
            });
            if let Some(status) = purchase["http_status"].as_u64() {
                text.push_str(&format!("HTTP status: {status}\n"));
            }
            if let Some(body) = purchase["body"].as_str() {
                // Escaped UTF-8 returns the useful API result without terminal controls.
                text.push_str(&format!(
                    "Response: {}\n",
                    serde_json::to_string(body).unwrap()
                ));
            }
            if value["deliveryReported"] == false {
                text.push_str("Site response report unavailable; the original result remains in the private journal.\n");
            }
        }
        text
    };
    bundle.clean(rendered)
}
fn render_record(bundle: &Bundle, record: &Record, value: &Value, json_output: bool) -> String {
    let mut value = value.clone();
    // Scrub reflected secrets in the raw body before JSON escaping changes
    // their spelling (for example an opaque JSON string containing quotes).
    if let Some(body) = value["purchase"]["body"].as_str() {
        let mut body = bundle.clean(body.to_string());
        if let Some(request) = &record.intent.mpp_request {
            if let Some(signed) = &record.signed
                && let Ok((_, credential)) = crate::tempo_mpp::credential(
                    request,
                    record.config["chainId"].as_u64().unwrap_or_default(),
                    record.policy["vault"].as_str().unwrap_or_default(),
                    &signed.hash,
                )
            {
                body = crate::output::clean(body, &credential);
            }
            if let Some(opaque) = request.challenge["opaque"].as_str() {
                body = crate::output::clean(body, opaque);
            }
        }
        value["purchase"]["body"] = json!(body);
    }
    let mut text = render(bundle, &value, json_output);
    if let Some(request) = &record.intent.mpp_request {
        // A response may reflect request headers. Preserve its raw bounded body
        // privately, but never print an executable Payment credential or opaque.
        if let Some(signed) = &record.signed
            && let Ok((_, credential)) = crate::tempo_mpp::credential(
                request,
                record.config["chainId"].as_u64().unwrap_or_default(),
                record.policy["vault"].as_str().unwrap_or_default(),
                &signed.hash,
            )
        {
            text = crate::output::clean(text, &credential);
        }
        if let Some(opaque) = request.challenge["opaque"].as_str() {
            text = crate::output::clean(text, opaque);
        }
    }
    text
}
fn reconcile<C: Chain, F: Fn(&str) -> Result<Value>>(
    bundle: &Bundle,
    store: &Store,
    record: &mut Record,
    chain: &C,
    report: F,
    wait: Duration,
) -> Result<(Value, i32)> {
    record.matches(bundle)?;
    let signed = record
        .signed
        .as_ref()
        .ok_or_else(|| {
            Error::config(
                "No saved signed Tempo transaction; rerun pay with the original exact intent",
            )
        })?
        .clone();
    let native = record
        .native
        .as_ref()
        .ok_or_else(|| Error::config("Missing native transaction"))?
        .clone();
    let first = match chain.finalized(
        &native,
        &signed,
        &record.intent,
        record.policy["token"].as_str().unwrap_or_default(),
    ) {
        Ok(proof) => proof,
        Err(_) => return Ok((result(record, "uncertain", 5, None), 5)),
    };
    if first.is_none() {
        let known = match chain.known(&native, &signed) {
            Ok(known) => known,
            Err(_) => return Ok((result(record, "uncertain", 5, None), 5)),
        };
        if !known {
            // Persist before any send. Recovery can rebroadcast only these exact saved bytes:
            // the same sender/account nonce/hash cannot create a second payment.
            record.attempted = true;
            store.save(&record.intent.id, record)?;
            if chain.send(&signed).is_err() {
                return Ok((result(record, "uncertain", 5, None), 5));
            }
        }
    }
    let deadline = Instant::now() + wait;
    let mut initial = first;
    let finality = loop {
        if let Some(proof) = initial.take() {
            break proof;
        }
        match chain.finalized(
            &native,
            &signed,
            &record.intent,
            record.policy["token"].as_str().unwrap_or_default(),
        ) {
            Ok(Some(proof)) => break proof,
            Err(_) => return Ok((result(record, "uncertain", 5, None), 5)),
            Ok(None) if Instant::now() >= deadline => {
                return Ok((result(record, "submitted", 12, None), 12));
            }
            Ok(None) => std::thread::sleep(
                Duration::from_secs(2).min(deadline.saturating_duration_since(Instant::now())),
            ),
        }
    };
    let replay = record
        .report
        .as_ref()
        .is_some_and(|r| r["operation"]["status"] == "settled");
    record.finality = Some(finality.clone());
    store.save(&record.intent.id, record)?;
    let reported = match report(&signed.hash) {
        Ok(value) => value,
        Err(_) => {
            return Ok((
                result(
                    record,
                    if finality.success {
                        "uncertain"
                    } else {
                        "failed"
                    },
                    if finality.success { 5 } else { 20 },
                    None,
                ),
                if finality.success { 5 } else { 20 },
            ));
        }
    };
    checked_receipt(
        &reported,
        record.policy["id"].as_str().unwrap_or_default(),
        &record.intent.id,
        Some(&signed.hash),
    )?;
    if reported
        .get("receipt")
        .is_some_and(|receipt| !report_receipt_matches(receipt, &signed, &finality))
    {
        return Ok((result(record, "uncertain", 5, None), 5));
    }
    if finality.success && reported["operation"]["status"] != "settled" {
        return Ok((result(record, "uncertain", 5, None), 5));
    }
    if !finality.success && reported["operation"]["status"] != "failed" {
        return Ok((result(record, "uncertain", 5, None), 5));
    }
    record.report = Some(reported.clone());
    store.save(&record.intent.id, record)?;
    let code = if !finality.success {
        20
    } else if replay {
        6
    } else {
        0
    };
    Ok((
        result(
            record,
            if finality.success {
                "settled"
            } else {
                "failed"
            },
            code,
            Some(reported),
        ),
        code,
    ))
}
fn report_receipt_matches(
    receipt: &Value,
    signed: &SignedTransaction,
    finality: &Finality,
) -> bool {
    let block_number = receipt["blockNumber"].as_u64().or_else(|| {
        receipt["blockNumber"].as_str().and_then(|number| {
            if number.is_empty()
                || number.len() > 20
                || !number.bytes().all(|byte| byte.is_ascii_digit())
            {
                None
            } else {
                number.parse::<u64>().ok()
            }
        })
    });
    receipt["verified"] == true
        && block_number == Some(finality.block_number)
        && receipt["transactionHash"]
            .as_str()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&signed.hash))
        && receipt["blockHash"]
            .as_str()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&finality.block_hash))
}
fn authorize<
    C: Chain,
    P: FnMut(&Intent) -> Result<(Value, i32)>,
    S: FnMut(&NativeTransaction, &str) -> Result<SignedTransaction>,
>(
    bundle: &Bundle,
    store: &Store,
    record: &mut Record,
    chain: &C,
    mut prepare_request: P,
    mut sign: S,
) -> Result<Option<(Value, i32)>> {
    if record.signed.is_some() {
        return Err(Error::config(
            "A signed Tempo request must be resumed, never authorized again",
        ));
    }
    record.matches(bundle)?;
    block_other_proof(store, record, chain)?;
    store.save(&record.intent.id, record)?;
    let (prepared, code) = if matches!(record.prepare_code, Some(20 | 6)) {
        (
            record
                .preparation
                .clone()
                .ok_or_else(|| Error::config("Missing saved Tempo decision"))?,
            record.prepare_code.unwrap(),
        )
    } else {
        prepare_request(&record.intent)?
    };
    record.preparation = Some(prepared.clone());
    record.prepare_code = Some(code);
    store.save(&record.intent.id, record)?;
    if code != 10 {
        let state = match code {
            20 => "denied",
            11 => "awaiting_input",
            6 => "replayed",
            _ => return Err(Error::uncertain("Unknown Tempo authorization decision")),
        };
        return Ok(Some((result(record, state, code, Some(prepared)), code)));
    }
    let plan = checked_plan(bundle, &record.intent, &prepared)?;
    check_expiry(&plan)?;
    if record.intent.mpp_request.is_some() {
        crate::tempo_mpp::validate_intent(bundle, &record.intent, crate::tempo_mpp::now()?)?;
    }
    let native = chain.build(&plan)?;
    check_expiry(&plan)?;
    if record.intent.mpp_request.is_some() {
        crate::tempo_mpp::validate_intent(bundle, &record.intent, crate::tempo_mpp::now()?)?;
    }
    let signed = sign(&native, &plan.from)?;
    record.native = Some(native);
    record.signed = Some(signed);
    record.matches(bundle)?;
    store.save(&record.intent.id, record)?;
    Ok(None)
}
fn check_expiry(plan: &allowit_tempo::Transaction) -> Result<()> {
    let data = allowit_tempo::unhex(&plan.data)
        .map_err(|_| Error::config("Invalid Tempo authorization"))?;
    let expiry = u64::from_be_bytes(
        data.get(4 + 10 * 32 + 24..4 + 11 * 32)
            .ok_or_else(|| Error::config("Invalid Tempo authorization expiry"))?
            .try_into()
            .map_err(|_| Error::config("Invalid Tempo authorization expiry"))?,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::config("Cannot determine Tempo authorization validity"))?
        .as_secs();
    if expiry <= now {
        return Err(Error::config(
            "Unsigned Tempo authorization has expired; no transaction is signed. Preserve this request ID for owner review",
        ));
    }
    Ok(())
}
fn load_record(store: &Store, id: &str) -> Result<Option<Record>> {
    let record = store.load::<Record>(id)?;
    if record.as_ref().is_some_and(|record| record.intent.id != id) {
        return Err(Error::config(
            "Tempo request identity differs from its journal filename",
        ));
    }
    Ok(record)
}
fn load_call_record<F>(
    bundle: &Bundle,
    store: &Store,
    url: &str,
    id: &str,
    maximum: &str,
    fetch: F,
) -> Result<Record>
where
    F: FnOnce() -> Result<(Intent, crate::tempo_mpp::Purchase)>,
{
    request_id(id)?;
    crate::tempo_mpp::endpoint_url(url)?;
    crate::tempo::amount(maximum)?;
    if let Some(record) = load_record(store, id)? {
        record.matches(bundle)?;
        if record
            .intent
            .mpp_request
            .as_ref()
            .is_none_or(|r| r.url != url)
            || record
                .purchase
                .as_ref()
                .is_none_or(|p| p.max_amount != maximum)
        {
            return Err(Error::config(
                "Request ID already binds another original URL or maximum amount; resume it",
            ));
        }
        return Ok(record);
    }
    let (intent, purchase) = fetch()?;
    if intent.id != id
        || intent.mpp_request.as_ref().is_none_or(|m| m.url != url)
        || purchase.max_amount != maximum
    {
        return Err(Error::config(
            "MPP challenge fetch changed the original call",
        ));
    }
    let mut record = Record::new(bundle, intent);
    record.purchase = Some(purchase);
    record.matches(bundle)?;
    // The original HTTP request and challenge precede policy authorization/RPC.
    store.save(id, &record)?;
    Ok(record)
}

fn finish_purchase<D, R>(
    bundle: &Bundle,
    store: &Store,
    record: &mut Record,
    mut payment: Value,
    payment_code: i32,
    deliver: D,
    report_delivery: R,
) -> Result<(Value, i32)>
where
    D: FnOnce(&allowit_tempo::MppPaymentRequest, &str) -> crate::tempo_mpp::ApiResponse,
    R: FnOnce(Value) -> Result<Value>,
{
    record.matches(bundle)?;
    if record.purchase.is_none() || payment["state"] != "settled" {
        return Ok((payment, payment_code));
    }
    if !record.finality.as_ref().is_some_and(|f| f.success)
        || record
            .report
            .as_ref()
            .is_none_or(|r| r["operation"]["status"] != "settled")
    {
        return Err(Error::config(
            "MPP HTTP submission requires a finalized, backend-settled payment",
        ));
    }
    let request = record.intent.mpp_request.as_ref().unwrap().clone();
    let hash = record
        .signed
        .as_ref()
        .ok_or_else(|| Error::config("Missing MPP transaction proof"))?
        .hash
        .clone();
    let was_attempted = record.purchase.as_ref().unwrap().http_attempted;
    if !was_attempted {
        record.purchase.as_mut().unwrap().http_attempted = true;
        // A merchant may consume the credential before a timeout/crash. Persist
        // this one-attempt marker before GET, independently of payment recovery.
        store.save(&record.intent.id, record)?;
        let response = deliver(&request, &hash);
        record.purchase.as_mut().unwrap().response = Some(response);
        store.save(&record.intent.id, record)?;
    }
    let response = record
        .purchase
        .as_ref()
        .unwrap()
        .response
        .clone()
        .unwrap_or_else(crate::tempo_mpp::ApiResponse::unavailable);
    let bound = allowit_tempo::validate_mpp_request(
        &request,
        record.config["chainId"].as_u64().unwrap_or_default(),
        record.policy["token"].as_str().unwrap_or_default(),
        &record.intent.recipient,
        &record.intent.amount,
        0,
    )
    .map_err(|_| Error::config("Invalid original MPP request"))?;
    if !record.purchase.as_ref().unwrap().delivery_reported {
        let body = json!({"policyId":record.policy["id"],"requestId":record.intent.id,
            "transactionHash":hash,"delivery":response.public_report(&bound.challenge_digest)});
        if report_delivery(body.clone())
            .is_ok_and(|reply| checked_delivery_report(&reply, &body, &bound))
        {
            record.purchase.as_mut().unwrap().delivery_reported = true;
            store.save(&record.intent.id, record)?;
        }
    }
    let code = if response.state == "response_received" {
        if was_attempted { 6 } else { 0 }
    } else {
        5
    };
    payment["purchase"] = json!(response);
    payment["deliveryReported"] = json!(record.purchase.as_ref().unwrap().delivery_reported);
    payment["exitCode"] = json!(code);
    Ok((payment, code))
}
fn checked_delivery_report(
    reply: &Value,
    sent: &Value,
    purchase: &allowit_tempo::MppPurchase,
) -> bool {
    let hash = sent["transactionHash"].as_str().unwrap_or_default();
    let operation = &reply["operation"];
    if checked_receipt(
        reply,
        sent["policyId"].as_str().unwrap_or_default(),
        sent["requestId"].as_str().unwrap_or_default(),
        Some(hash),
    )
    .is_err()
        || operation["status"] != "settled"
        || operation["purchase"] != json!(purchase)
    {
        return false;
    }
    let mut delivery = operation["delivery"].clone();
    if delivery["reportedBy"] != "executor"
        || delivery["transactionHash"] != hash
        || delivery["reportedAt"].as_str().is_none_or(|t| {
            time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339).is_err()
        })
    {
        return false;
    }
    let Some(object) = delivery.as_object_mut() else {
        return false;
    };
    for field in ["reportedBy", "transactionHash", "reportedAt"] {
        object.remove(field);
    }
    delivery == sent["delivery"]
}
pub(crate) fn run(
    bundle: &Bundle,
    command: &str,
    pos: &[&str],
    json_output: bool,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<i32> {
    allowit_native::journal::require_supported_platform().map_err(|_| {
        Error::config(
            "Tempo pay/resume requires Linux/WSL with journal and keys in its Linux filesystem",
        )
    })?;
    let wait = wait_duration()?;
    let store = Store::open(&state_path(bundle)?)?;
    let (id, intent) = if command == "pay" {
        let intent = Intent::read(pos[0], pos[1])?;
        (intent.id.clone(), Some(intent))
    } else if command == "call" {
        request_id(pos[1])?;
        crate::tempo_mpp::endpoint_url(pos[0])?;
        crate::tempo::amount(pos[2])?;
        (pos[1].to_owned(), None)
    } else {
        request_id(pos[0])?;
        (pos[0].to_owned(), None)
    };
    let mut record = if command == "call" {
        load_call_record(bundle, &store, pos[0], &id, pos[2], || {
            crate::tempo_mpp::fetch(bundle, pos[0], &id, pos[2])
        })?
    } else {
        match load_record(&store, &id)? {
            Some(record) => record,
            None => Record::new(
                bundle,
                intent.clone().ok_or_else(|| {
                    Error::config(
                        "No saved Tempo request for this ID; preserve the original journal",
                    )
                })?,
            ),
        }
    };
    record.matches(bundle)?;
    if command == "call"
        && (record
            .intent
            .mpp_request
            .as_ref()
            .is_none_or(|r| r.url != pos[0])
            || record
                .purchase
                .as_ref()
                .is_none_or(|p| p.max_amount != pos[2]))
    {
        return Err(Error::config(
            "Request ID already binds another original URL or maximum amount; resume it",
        ));
    }
    if intent.as_ref().is_some_and(|i| i != &record.intent) {
        return Err(Error::config(
            "Request ID already binds another exact intent; resume the original request",
        ));
    }
    if command == "call" {
        stderr.push_str(&format!(
            "MPP GET {}\nOriginal Tempo charge: {}; maximum: {}\n",
            pos[0], record.intent.amount, pos[2]
        ));
        crate::flush_stderr(stderr);
    }
    if matches!(command, "pay" | "call") && record.signed.is_none() {
        stderr.push_str(&format!(
            "Tempo request {id}: evaluating the vault policy\n"
        ));
        crate::flush_stderr(stderr);
        let chain = Rpc::new(bundle)?;
        if let Some((value, code)) = authorize(
            bundle,
            &store,
            &mut record,
            &chain,
            |intent| prepare(bundle, intent),
            |native, from| {
                let key_path = env_value("ALLOWIT_TEMPO_EXECUTOR_KEY_FILE");
                if key_path.is_empty() {
                    return Err(Error::config(
                        "Set ALLOWIT_TEMPO_EXECUTOR_KEY_FILE to the designated executor's private 0600 hex key file",
                    ));
                }
                let key = read_key(std::path::Path::new(&key_path), from)?;
                native.sign(&key)
            },
        )? {
            stdout.push_str(&render_record(bundle, &record, &value, json_output));
            return Ok(code);
        }
    }
    record.matches(bundle)?;
    let signed=record.signed.as_ref().ok_or_else(||Error::config(if record.purchase.is_some() {
        "No saved signed transaction. After owner input, rerun the original tempo call with the same URL, --id and --max-amount"
    } else {
        "No saved signed transaction. Rerun pay with the same request ID and exact intent after owner input"
    }))?;
    stderr.push_str(&format!(
        "Tempo request {id}\nTransaction: {}\nRecovery: allowit tempo resume {id}\n",
        signed.hash
    ));
    crate::flush_stderr(stderr);
    let chain = Rpc::new(bundle)?;
    let policy_id = record.policy["id"].as_str().unwrap_or_default().to_owned();
    let (value, code) = reconcile(
        bundle,
        &store,
        &mut record,
        &chain,
        |hash| {
            bundle.call(
                "report",
                json!({"policyId":policy_id,"requestId":id,"transactionHash":hash}),
            )
        },
        wait,
    )?;
    let (value, code) = finish_purchase(
        bundle,
        &store,
        &mut record,
        value,
        code,
        |request, hash| {
            crate::tempo_mpp::deliver(
                request,
                bundle.value["config"]["chainId"]
                    .as_u64()
                    .unwrap_or_default(),
                bundle.value["policy"]["vault"].as_str().unwrap_or_default(),
                hash,
            )
        },
        |body| bundle.call("delivery", body),
    )?;
    stdout.push_str(&render_record(bundle, &record, &value, json_output));
    Ok(code)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use std::{
        cell::{Cell, RefCell},
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Fixture {
        config: Value,
        policy: Value,
        intent: Intent,
        preparation: Value,
        native: NativeTransaction,
        signed: SignedTransaction,
    }
    fn word(value: u64) -> [u8; 32] {
        let mut word = [0; 32];
        word[24..].copy_from_slice(&value.to_be_bytes());
        word
    }
    fn account(value: &str) -> [u8; 32] {
        let mut word = [0; 32];
        word[12..].copy_from_slice(&allowit_tempo::unhex(value).unwrap());
        word
    }
    fn digest(value: &str) -> [u8; 32] {
        allowit_tempo::unhex(&format!("0x{}", value.trim_start_matches("0x")))
            .unwrap()
            .try_into()
            .unwrap()
    }
    impl Fixture {
        fn new(id: &str, vault_seed: u8) -> Self {
            Self::with_expiry(id, vault_seed, 4_000_000_000)
        }
        fn with_expiry(id: &str, vault_seed: u8, expires_at: u64) -> Self {
            // Public, deterministic unit-test keys; never loaded from live configuration.
            let executor = executor_address(&[6; 32]).unwrap();
            let authority = executor_address(&[7; 32]).unwrap();
            let config = json!({
                "network":"tempo:localnet", "chainId":31337, "rpcUrl":"http://127.0.0.1:1",
                "factory":allowit_tempo::hex(&[11;20]), "factoryCodeHash":allowit_tempo::hex(&[12;32]),
                "token":allowit_tempo::hex(&[13;20]), "executor":executor, "authority":authority,
                "feeToken":allowit_tempo::hex(&[14;20])
            });
            let policy = json!({
                "id":format!("{:064x}",u64::from(vault_seed)), "profile":"tempo-native-v1",
                "network":config["network"], "chainId":config["chainId"], "owner":executor_address(&[5;32]).unwrap(),
                "token":config["token"], "executor":config["executor"], "authority":config["authority"],
                "factory":config["factory"], "vault":allowit_tempo::hex(&[vault_seed;20]),
                "policyDigest":allowit_tempo::hex(&[17;32]), "requirementsDigest":allowit_tempo::hex(&[18;32]),
                "semanticRequired":true, "prompt":"Pay for approved research", "dailyLimit":"5",
                "actionLimit":"1", "totalLimit":"20", "expiresAt":"18446744073709551615",
                "recipient":allowit_tempo::ZERO
            });
            let intent = Intent {
                id: id.into(),
                recipient: allowit_tempo::hex(&[19; 20]),
                amount: "0.25".into(),
                action: "buy research".into(),
                merchant: "research".into(),
                context: json!({"purpose":"research"}),
                mpp_request: None,
            };
            let context = serde_json::to_string(&intent.context).unwrap();
            let mut identity = json!({"policyId":policy["id"], "amount":intent.amount,
                "recipient":intent.recipient, "action":intent.action, "merchant":intent.merchant, "context":context});
            identity.sort_all_objects();
            let input_hash = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&identity).unwrap())
            );
            let request_hash: [u8; 32] =
                Sha256::digest(format!("{id}:{input_hash}").as_bytes()).into();
            let memo: [u8; 32] = Sha256::digest(id.as_bytes()).into();
            let vault = policy["vault"].as_str().unwrap();
            let mut words = vec![
                word(31337),
                account(vault),
                account(config["token"].as_str().unwrap()),
                digest(policy["id"].as_str().unwrap()),
                digest(policy["policyDigest"].as_str().unwrap()),
                digest(policy["requirementsDigest"].as_str().unwrap()),
                word(1),
                word(1),
                account(&intent.recipient),
                word(250_000),
                word(expires_at),
                request_hash,
                [20; 32],
                memo,
            ];
            let signer = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
            let (signature, recovery) = signer
                .sign_prehash_recoverable(
                    &allowit_tempo::execution_digest(31337, vault, &words).unwrap(),
                )
                .unwrap();
            words.extend([word(480), word(65)]);
            let mut data =
                allowit_tempo::keccak(format!("execute({},bytes)", allowit_tempo::EXECUTION))[..4]
                    .to_vec();
            data.extend(words.concat());
            data.extend(signature.to_bytes());
            data.push(27 + recovery.to_byte());
            data.resize(4 + 19 * 32, 0);
            let plan = allowit_tempo::Transaction {
                chain_id: 31337,
                from: executor,
                to: vault.into(),
                data: allowit_tempo::hex(&data),
                value: "0x0".into(),
                fee_token: config["feeToken"].as_str().unwrap().into(),
            };
            let preparation = json!({"decision":"allow","transaction":plan,
                "operation":{"id":id,"policyId":policy["id"],"method":"execute","status":"prepared"}});
            let native = NativeTransaction {
                chain_id: 31337,
                max_priority_fee_per_gas: 0,
                max_fee_per_gas: 20,
                gas_limit: 50_000,
                nonce: 7,
                to: plan.to,
                data: plan.data,
                fee_token: plan.fee_token,
            };
            let signed = native.sign(&[6; 32]).unwrap();
            Self {
                config,
                policy,
                intent,
                preparation,
                native,
                signed,
            }
        }
        fn bundle(&self) -> Bundle {
            Bundle::verification_context(
                self.config.clone(),
                self.policy.clone(),
                "http://127.0.0.1:1",
            )
        }
        fn with_mpp(id: &str, vault_seed: u8) -> Self {
            let mut fixture = Self::new(id, vault_seed);
            fixture.config["network"] = json!("tempo:testnet");
            fixture.config["chainId"] = json!(42431);
            fixture.policy["network"] = json!("tempo:testnet");
            fixture.policy["chainId"] = json!(42431);
            let mut terms = json!({"amount":"250000","currency":fixture.config["token"],"recipient":fixture.intent.recipient,
                "methodDetails":{"chainId":42431,"feePayer":false,"supportedModes":["push"]}});
            terms.sort_all_objects();
            let challenge = mpp::PaymentChallenge::new(
                "original-charge",
                "merchant.example",
                "tempo",
                "charge",
                mpp::Base64UrlJson::from_value(&terms).unwrap(),
            )
            .with_opaque(
                mpp::Base64UrlJson::from_value(&json!({"private":"merchant-original"})).unwrap(),
            );
            fixture.intent.action = "GET https://merchant.example/paid".into();
            fixture.intent.merchant = "https://merchant.example".into();
            fixture.intent.context = json!({});
            fixture.intent.mpp_request = Some(
                crate::tempo_mpp::parse_challenge(
                    &challenge.to_header().unwrap(),
                    "https://merchant.example/paid",
                )
                .unwrap(),
            );
            let mut data = allowit_tempo::unhex(&fixture.native.data).unwrap();
            data[4..36].copy_from_slice(&word(42431));
            let identity = allowit_tempo::execution_request_identity(
                fixture.policy["id"].as_str().unwrap(),
                &fixture.intent.recipient,
                &fixture.intent.amount,
                &fixture.intent.action,
                &fixture.intent.merchant,
                Some("{}"),
                fixture.intent.mpp_request.as_ref(),
            )
            .unwrap();
            let input = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&identity).unwrap())
            );
            data[4 + 11 * 32..4 + 12 * 32]
                .copy_from_slice(&Sha256::digest(format!("{id}:{input}")));
            data[4 + 13 * 32..4 + 14 * 32].copy_from_slice(
                &allowit_tempo::unhex(
                    &allowit_tempo::mpp_memo(
                        &fixture.intent.mpp_request.as_ref().unwrap().challenge,
                    )
                    .unwrap(),
                )
                .unwrap(),
            );
            let words = data[4..4 + 14 * 32].as_chunks::<32>().0.to_vec();
            let signer = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
            let (signature, recovery) = signer
                .sign_prehash_recoverable(
                    &allowit_tempo::execution_digest(
                        42431,
                        fixture.policy["vault"].as_str().unwrap(),
                        &words,
                    )
                    .unwrap(),
                )
                .unwrap();
            data[4 + 16 * 32..4 + 16 * 32 + 64].copy_from_slice(&signature.to_bytes());
            data[4 + 16 * 32 + 64] = 27 + recovery.to_byte();
            fixture.native.chain_id = 42431;
            fixture.native.data = allowit_tempo::hex(&data);
            fixture.preparation["transaction"]["chainId"] = json!(42431);
            fixture.preparation["transaction"]["data"] = json!(fixture.native.data);
            fixture.signed = fixture.native.sign(&[6; 32]).unwrap();
            fixture
        }
        fn record(&self) -> Record {
            let mut record = Record::new(&self.bundle(), self.intent.clone());
            record.preparation = Some(self.preparation.clone());
            record.prepare_code = Some(10);
            record.native = Some(self.native.clone());
            record.signed = Some(self.signed.clone());
            if self.intent.mpp_request.is_some() {
                record.purchase = Some(crate::tempo_mpp::Purchase::new("1".into()));
            }
            record
        }
        fn report(&self, success: bool) -> Value {
            json!({"operation":{"id":self.intent.id,"policyId":self.policy["id"],"method":"execute",
                "status":if success {"settled"} else {"failed"},"transactionHash":self.signed.hash},
                "receipt":{"verified":true,"blockNumber":10,"blockHash":allowit_tempo::hex(&[23;32]),
                "transactionHash":self.signed.hash}})
        }
        fn delivery_reply(&self, sent: &Value) -> Value {
            let purchase = allowit_tempo::validate_mpp_request(
                self.intent.mpp_request.as_ref().unwrap(),
                42431,
                self.policy["token"].as_str().unwrap(),
                &self.intent.recipient,
                &self.intent.amount,
                0,
            )
            .unwrap();
            let mut reply = self.report(true);
            reply["operation"]["purchase"] = json!(purchase);
            reply["operation"]["delivery"] = sent["delivery"].clone();
            reply["operation"]["delivery"]["reportedBy"] = json!("executor");
            reply["operation"]["delivery"]["transactionHash"] = json!(self.signed.hash);
            reply["operation"]["delivery"]["reportedAt"] = json!("2026-10-13T00:00:00Z");
            reply
        }
    }

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let count = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "allowit-tempo-pay-test-{}-{time}-{count}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn file(&self, id: &str) -> PathBuf {
            self.0
                .join(format!("request-{:x}.json", Sha256::digest(id.as_bytes())))
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn private_key_file(path: &Path, key: &[u8; 32]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        write!(file, "{}", allowit_tempo::hex(key)).unwrap();
    }

    struct MockChain {
        native: NativeTransaction,
        signed: SignedTransaction,
        store_file: PathBuf,
        sends: RefCell<Vec<String>>,
        builds: Cell<usize>,
        known_calls: Cell<usize>,
        finality_calls: Cell<usize>,
        known: Cell<bool>,
        finality: Cell<Option<bool>>,
        send_error: Cell<bool>,
        accept_on_error: Cell<bool>,
    }
    impl MockChain {
        fn new(fixture: &Fixture, directory: &TestDirectory) -> Self {
            Self {
                native: fixture.native.clone(),
                signed: fixture.signed.clone(),
                store_file: directory.file(&fixture.intent.id),
                sends: RefCell::new(Vec::new()),
                builds: Cell::new(0),
                known_calls: Cell::new(0),
                finality_calls: Cell::new(0),
                known: Cell::new(false),
                finality: Cell::new(None),
                send_error: Cell::new(false),
                accept_on_error: Cell::new(false),
            }
        }
    }
    impl Chain for MockChain {
        fn build(&self, _: &allowit_tempo::Transaction) -> Result<NativeTransaction> {
            self.builds.set(self.builds.get() + 1);
            Ok(self.native.clone())
        }
        fn send(&self, signed: &SignedTransaction) -> Result<()> {
            assert!(signed == &self.signed);
            let saved: Record =
                serde_json::from_slice(&fs::read(&self.store_file).unwrap()).unwrap();
            assert!(saved.attempted);
            assert!(saved.signed.as_ref() == Some(signed));
            assert!(saved.native.as_ref() == Some(&self.native));
            self.sends.borrow_mut().push(signed.raw.clone());
            let failed = self.send_error.replace(false);
            if !failed || self.accept_on_error.get() {
                self.known.set(true);
            }
            if failed {
                Err(Error::uncertain("Synthetic lost send response"))
            } else {
                Ok(())
            }
        }
        fn known(&self, native: &NativeTransaction, signed: &SignedTransaction) -> Result<bool> {
            assert!(native == &self.native);
            assert!(signed == &self.signed);
            self.known_calls.set(self.known_calls.get() + 1);
            Ok(self.known.get())
        }
        fn finalized(
            &self,
            native: &NativeTransaction,
            signed: &SignedTransaction,
            _: &Intent,
            _: &str,
        ) -> Result<Option<Finality>> {
            assert!(native == &self.native);
            assert!(signed == &self.signed);
            self.finality_calls.set(self.finality_calls.get() + 1);
            Ok(self.finality.get().map(|success| Finality {
                block_number: 10,
                block_hash: allowit_tempo::hex(&[23; 32]),
                success,
            }))
        }
    }

    fn finality(success: bool) -> Finality {
        Finality {
            block_number: 10,
            block_hash: allowit_tempo::hex(&[23; 32]),
            success,
        }
    }
    #[test]
    fn authorization_preserves_intent_then_signs_and_persists_exactly_once() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = Record::new(&bundle, fixture.intent.clone());
        let preparations = Cell::new(0);
        let signatures = Cell::new(0);
        assert!(
            authorize(
                &bundle,
                &store,
                &mut record,
                &chain,
                |intent| {
                    preparations.set(preparations.get() + 1);
                    let saved = load_record(&store, &intent.id).unwrap().unwrap();
                    assert!(saved.intent == *intent);
                    assert!(saved.preparation.is_none());
                    assert!(saved.signed.is_none());
                    Ok((fixture.preparation.clone(), 10))
                },
                |native, from| {
                    signatures.set(signatures.get() + 1);
                    let saved = load_record(&store, &fixture.intent.id).unwrap().unwrap();
                    assert_eq!(saved.prepare_code, Some(10));
                    assert!(saved.signed.is_none());
                    assert_eq!(from, fixture.signed.from);
                    native.sign(&[6; 32])
                }
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(preparations.get(), 1);
        assert_eq!(signatures.get(), 1);
        assert_eq!(chain.builds.get(), 1);
        assert!(chain.sends.borrow().is_empty());
        let saved = load_record(&store, &fixture.intent.id).unwrap().unwrap();
        assert!(saved.signed.as_ref() == Some(&fixture.signed));
        assert!(saved.native.as_ref() == Some(&fixture.native));
        assert!(!saved.attempted);
        assert!(
            authorize(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| panic!("must not reauthorize signed proof"),
                |_, _| panic!("must not sign twice")
            )
            .is_err()
        );
        assert_eq!(preparations.get(), 1);
        assert_eq!(signatures.get(), 1);
        assert_eq!(chain.builds.get(), 1);
    }
    #[test]
    fn denied_and_owner_waiting_requests_do_not_build_sign_or_send() {
        for code in [20, 11, 6] {
            let fixture = Fixture::new("payment-one", 16);
            let bundle = fixture.bundle();
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            let chain = MockChain::new(&fixture, &directory);
            let mut record = Record::new(&bundle, fixture.intent.clone());
            let decision = json!({"decision":match code {20=>"deny",11=>"awaiting_input",_=>"settled"},
                "requestId":fixture.intent.id,"policyId":fixture.policy["id"]});
            let (value, exit) = authorize(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| Ok((decision.clone(), code)),
                |_, _| panic!("denied/waiting/replayed request must never sign"),
            )
            .unwrap()
            .unwrap();
            assert_eq!(exit, code);
            assert_eq!(value["exitCode"], code);
            assert_eq!(chain.builds.get(), 0);
            assert!(chain.sends.borrow().is_empty());
            assert!(record.signed.is_none());
            assert!(
                load_record(&store, &fixture.intent.id)
                    .unwrap()
                    .unwrap()
                    .signed
                    .is_none()
            );
        }
    }
    #[test]
    fn signed_proof_persistence_failure_prevents_broadcast() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = Record::new(&bundle, fixture.intent.clone());
        let failure = authorize(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| Ok((fixture.preparation.clone(), 10)),
            |native, _| {
                let signed = native.sign(&[6; 32])?;
                // A changed directory mode makes the final durable write fail closed.
                fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o500)).unwrap();
                Ok(signed)
            },
        );
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failure.is_err());
        assert!(chain.sends.borrow().is_empty());
        let saved = load_record(&store, &fixture.intent.id).unwrap().unwrap();
        assert_eq!(saved.prepare_code, Some(10));
        assert!(saved.signed.is_none());
    }
    #[test]
    fn expired_unsigned_authorization_never_requests_a_signature() {
        let fixture = Fixture::with_expiry("payment-one", 16, 1);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = Record::new(&bundle, fixture.intent.clone());
        let failure = authorize(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| Ok((fixture.preparation.clone(), 10)),
            |_, _| panic!("expired approval must not sign"),
        );
        assert!(failure.is_err());
        assert_eq!(chain.builds.get(), 0);
        assert!(chain.sends.borrow().is_empty());
        assert!(
            load_record(&store, &fixture.intent.id)
                .unwrap()
                .unwrap()
                .signed
                .is_none()
        );
    }
    #[test]
    fn crash_after_attempted_flag_before_send_resumes_the_exact_saved_bytes() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = fixture.record();
        record.attempted = true;
        store.save(&record.intent.id, &record).unwrap();
        let original = record.signed.clone().unwrap();
        let (value, code) = reconcile(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| panic!("pending proof cannot report settled"),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(code, 12);
        assert_eq!(value["transactionHash"], original.hash);
        assert_eq!(chain.builds.get(), 0);
        assert_eq!(chain.sends.borrow().as_slice(), &[original.raw]);
        assert!(
            load_record(&store, &record.intent.id)
                .unwrap()
                .unwrap()
                .signed
                == record.signed
        );
    }
    #[test]
    fn accepted_send_with_lost_response_reconciles_without_new_payment() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = fixture.record();
        store.save(&record.intent.id, &record).unwrap();
        chain.send_error.set(true);
        chain.accept_on_error.set(true);
        let (_, code) = reconcile(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| panic!("unknown send must retain proof"),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(code, 5);
        assert_eq!(chain.sends.borrow().len(), 1);
        assert!(
            load_record(&store, &record.intent.id)
                .unwrap()
                .unwrap()
                .attempted
        );
        chain.finality.set(Some(true));
        let calls = Cell::new(0);
        let (value, code) = reconcile(
            &bundle,
            &store,
            &mut record,
            &chain,
            |hash| {
                assert_eq!(hash, fixture.signed.hash);
                calls.set(calls.get() + 1);
                Ok(fixture.report(true))
            },
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(value["state"], "settled");
        assert_eq!(calls.get(), 1);
        assert_eq!(chain.sends.borrow().len(), 1);
        assert_eq!(chain.builds.get(), 0);
    }
    #[test]
    fn unknown_send_retry_rebroadcasts_only_identical_raw_hash_and_nonce() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = fixture.record();
        store.save(&record.intent.id, &record).unwrap();
        chain.send_error.set(true);
        assert_eq!(
            reconcile(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| panic!(),
                Duration::ZERO
            )
            .unwrap()
            .1,
            5
        );
        assert_eq!(
            reconcile(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| panic!(),
                Duration::ZERO
            )
            .unwrap()
            .1,
            12
        );
        assert_eq!(
            chain.sends.borrow().as_slice(),
            &[fixture.signed.raw.clone(), fixture.signed.raw.clone()]
        );
        assert_eq!(chain.builds.get(), 0);
        assert!(record.native.as_ref() == Some(&fixture.native));
        assert!(record.signed.as_ref() == Some(&fixture.signed));
    }
    #[test]
    fn known_pending_transaction_is_observed_without_rebroadcast_or_signing() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = fixture.record();
        store.save(&record.intent.id, &record).unwrap();
        chain.known.set(true);
        let (_, code) = reconcile(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| panic!(),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(code, 12);
        assert!(chain.sends.borrow().is_empty());
        assert_eq!(chain.builds.get(), 0);
        assert!(record.finality.is_none());
    }
    #[test]
    fn canonical_settlement_and_replay_never_send_again() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = fixture.record();
        store.save(&record.intent.id, &record).unwrap();
        chain.finality.set(Some(true));
        assert_eq!(
            reconcile(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| Ok(fixture.report(true)),
                Duration::ZERO
            )
            .unwrap()
            .1,
            0
        );
        assert_eq!(
            reconcile(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| Ok(fixture.report(true)),
                Duration::ZERO
            )
            .unwrap()
            .1,
            6
        );
        assert!(chain.sends.borrow().is_empty());
        assert_eq!(chain.builds.get(), 0);
        assert_eq!(chain.known_calls.get(), 0);
    }
    #[test]
    fn report_failure_preserves_finality_and_recovers_original_hash() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = fixture.record();
        store.save(&record.intent.id, &record).unwrap();
        chain.finality.set(Some(true));
        let (value, code) = reconcile(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| Err(Error::uncertain("Synthetic report failure")),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(code, 5);
        assert_eq!(value["state"], "uncertain");
        let saved = load_record(&store, &record.intent.id).unwrap().unwrap();
        assert!(saved.finality.is_some());
        assert!(saved.report.is_none());
        assert!(saved.signed == record.signed);
        assert_eq!(
            reconcile(
                &bundle,
                &store,
                &mut record,
                &chain,
                |hash| {
                    assert_eq!(hash, fixture.signed.hash);
                    Ok(fixture.report(true))
                },
                Duration::ZERO
            )
            .unwrap()
            .1,
            0
        );
        assert!(chain.sends.borrow().is_empty());
        assert_eq!(chain.builds.get(), 0);
    }
    #[test]
    fn failed_receipt_and_contradictory_backend_status_are_kept_distinct() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = fixture.record();
        store.save(&record.intent.id, &record).unwrap();
        chain.finality.set(Some(false));
        let (value, code) = reconcile(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| Ok(fixture.report(true)),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(code, 5);
        assert_eq!(value["state"], "uncertain");
        assert!(record.report.is_none());
        let (value, code) = reconcile(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| Ok(fixture.report(false)),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(code, 20);
        assert_eq!(value["state"], "failed");
        assert!(chain.sends.borrow().is_empty());
    }
    #[test]
    fn mismatched_report_identity_never_becomes_payment_confirmed() {
        for field in ["id", "policyId", "transactionHash", "method"] {
            let fixture = Fixture::new("payment-one", 16);
            let bundle = fixture.bundle();
            let directory = TestDirectory::new();
            let store = Store::open(&directory.0).unwrap();
            let chain = MockChain::new(&fixture, &directory);
            let mut record = fixture.record();
            store.save(&record.intent.id, &record).unwrap();
            chain.finality.set(Some(true));
            let mut report = fixture.report(true);
            report["operation"][field] = json!("substituted");
            assert!(
                reconcile(
                    &bundle,
                    &store,
                    &mut record,
                    &chain,
                    |_| Ok(report.clone()),
                    Duration::ZERO
                )
                .is_err()
            );
            assert!(record.report.is_none());
            assert!(record.signed.as_ref() == Some(&fixture.signed));
        }
    }
    #[test]
    fn substituted_backend_receipt_never_becomes_a_confirmed_or_failed_result() {
        for success in [true, false] {
            for (field, replacement) in [
                ("transactionHash", json!(allowit_tempo::hex(&[24; 32]))),
                ("blockHash", json!(allowit_tempo::hex(&[25; 32]))),
                ("blockNumber", json!(11)),
                ("blockNumber", json!("11")),
                ("blockNumber", json!("0xa")),
                ("blockNumber", json!("18446744073709551616")),
                ("verified", json!(false)),
            ] {
                let fixture = Fixture::new("payment-one", 16);
                let bundle = fixture.bundle();
                let directory = TestDirectory::new();
                let store = Store::open(&directory.0).unwrap();
                let chain = MockChain::new(&fixture, &directory);
                let mut record = fixture.record();
                store.save(&record.intent.id, &record).unwrap();
                chain.finality.set(Some(success));
                let mut report = fixture.report(success);
                report["receipt"][field] = replacement;
                let (value, code) = reconcile(
                    &bundle,
                    &store,
                    &mut record,
                    &chain,
                    |_| Ok(report.clone()),
                    Duration::ZERO,
                )
                .unwrap();
                assert_eq!(code, 5);
                assert_eq!(value["state"], "uncertain");
                assert!(record.report.is_none());
                assert!(
                    load_record(&store, &record.intent.id)
                        .unwrap()
                        .unwrap()
                        .report
                        .is_none()
                );
                assert!(chain.sends.borrow().is_empty());
            }
        }
    }
    #[test]
    fn matching_decimal_receipt_and_receiptless_settled_replay_are_supported() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = fixture.record();
        store.save(&record.intent.id, &record).unwrap();
        chain.finality.set(Some(true));
        let mut report = fixture.report(true);
        report["receipt"]["blockNumber"] = json!("10");
        assert_eq!(
            reconcile(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| Ok(report.clone()),
                Duration::ZERO,
            )
            .unwrap()
            .1,
            0
        );
        report.as_object_mut().unwrap().remove("receipt");
        assert_eq!(
            reconcile(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| Ok(report.clone()),
                Duration::ZERO,
            )
            .unwrap()
            .1,
            6
        );
        assert!(chain.sends.borrow().is_empty());
        assert_eq!(chain.builds.get(), 0);
    }
    #[test]
    fn stored_authorization_context_and_envelope_substitutions_are_rejected() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        assert!(fixture.record().matches(&bundle).is_ok());
        let mut record = fixture.record();
        record.intent.context = json!({"purpose":"other"});
        assert!(record.matches(&bundle).is_err());
        let mut record = fixture.record();
        record.intent.amount = "0.5".into();
        assert!(record.matches(&bundle).is_err());
        let mut record = fixture.record();
        record.intent.id = "different-id".into();
        assert!(record.matches(&bundle).is_err());
        let mut record = fixture.record();
        record.native.as_mut().unwrap().nonce += 1;
        assert!(record.matches(&bundle).is_err());
        let mut record = fixture.record();
        record.native.as_mut().unwrap().fee_token = allowit_tempo::hex(&[21; 20]);
        assert!(record.matches(&bundle).is_err());
        let mut record = fixture.record();
        record.signed.as_mut().unwrap().hash = allowit_tempo::hex(&[22; 32]);
        assert!(record.matches(&bundle).is_err());
    }
    #[test]
    fn filename_identity_substitution_is_rejected_on_load_and_scan() {
        let fixture = Fixture::new("payment-one", 16);
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        store.save("different-id", &fixture.record()).unwrap();
        assert!(load_record(&store, "different-id").is_err());
        let current = Fixture::new("payment-two", 17).record();
        let chain = MockChain::new(&fixture, &directory);
        assert!(block_other_proof(&store, &current, &chain).is_err());
        assert!(chain.sends.borrow().is_empty());
    }
    #[test]
    fn pending_proof_on_another_vault_blocks_a_new_signature() {
        let previous = Fixture::new("payment-one", 16);
        let current = Fixture::new("payment-two", 17);
        let bundle = current.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        store.save(&previous.intent.id, &previous.record()).unwrap();
        let chain = MockChain::new(&previous, &directory);
        let mut record = Record::new(&bundle, current.intent.clone());
        assert!(
            authorize(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| panic!("pending executor proof blocks preparation"),
                |_, _| panic!("pending executor proof blocks signing")
            )
            .is_err()
        );
        assert_eq!(chain.builds.get(), 0);
        assert!(chain.sends.borrow().is_empty());
        assert!(load_record(&store, &current.intent.id).unwrap().is_none());
    }
    #[test]
    fn other_vault_finality_must_still_match_the_canonical_chain() {
        let previous = Fixture::new("payment-one", 16);
        let current = Fixture::new("payment-two", 17);
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let mut old = previous.record();
        old.finality = Some(finality(true));
        store.save(&old.intent.id, &old).unwrap();
        let chain = MockChain::new(&previous, &directory);
        let current = current.record();
        assert!(block_other_proof(&store, &current, &chain).is_err()); // local finality alone is insufficient
        chain.finality.set(Some(false));
        assert!(block_other_proof(&store, &current, &chain).is_err());
        chain.finality.set(Some(true));
        assert!(block_other_proof(&store, &current, &chain).is_ok());
        old.signed.as_mut().unwrap().hash = allowit_tempo::hex(&[22; 32]);
        store.save(&old.intent.id, &old).unwrap();
        assert!(block_other_proof(&store, &current, &chain).is_err());
        assert!(chain.sends.borrow().is_empty());
    }
    #[test]
    fn executor_key_files_require_private_mode_exact_role_and_no_links() {
        let fixture = Fixture::new("payment-one", 16);
        let directory = TestDirectory::new();
        let key = directory.0.join("executor.hex");
        private_key_file(&key, &[6; 32]);
        assert!(read_key(&key, &fixture.signed.from).is_ok());
        assert!(read_key(&key, &executor_address(&[5; 32]).unwrap()).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o4600)).unwrap();
        assert!(read_key(&key, &fixture.signed.from).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_key(&key, &fixture.signed.from).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&key, directory.0.join("alias.hex")).unwrap();
        assert!(read_key(&directory.0.join("alias.hex"), &fixture.signed.from).is_err());
        fs::hard_link(&key, directory.0.join("hard.hex")).unwrap();
        assert!(read_key(&key, &fixture.signed.from).is_err());
    }
    #[test]
    fn public_output_has_hash_without_executable_bytes_or_unverified_confirmation() {
        let fixture = Fixture::new("payment-one", 16);
        let bundle = fixture.bundle();
        let record = fixture.record();
        let pending = render(&bundle, &result(&record, "submitted", 12, None), false);
        assert!(pending.contains(&fixture.signed.hash));
        assert!(!pending.contains(&fixture.signed.raw));
        assert!(!pending.contains("Payment confirmed"));
        assert!(pending.contains("resume payment-one"));
        let replay = render(
            &bundle,
            &result(
                &Record::new(&bundle, fixture.intent.clone()),
                "replayed",
                6,
                None,
            ),
            false,
        );
        assert!(replay.contains("Service reports"));
        assert!(!replay.contains("Payment confirmed"));
        let encoded = render(&bundle, &result(&record, "uncertain", 5, None), true);
        assert!(!encoded.contains(&fixture.signed.raw));
        assert_eq!(
            serde_json::from_str::<Value>(&encoded).unwrap()["state"],
            "uncertain"
        );
    }

    #[test]
    fn native_v1_journal_without_optional_mpp_fields_remains_readable() {
        let fixture = Fixture::new("native-old-v1", 16);
        let mut value = serde_json::to_value(fixture.record()).unwrap();
        value.as_object_mut().unwrap().remove("purchase");
        value["intent"]
            .as_object_mut()
            .unwrap()
            .remove("mpp_request");
        let record: Record = serde_json::from_value(value).unwrap();
        assert!(record.purchase.is_none());
        assert!(record.intent.mpp_request.is_none());
        record.matches(&fixture.bundle()).unwrap();
    }
    #[test]
    fn original_http_challenge_is_saved_before_authorization_and_signed_proof_before_broadcast() {
        let fixture = Fixture::with_mpp("mpp-durable-001", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        let mut record = Record::new(&bundle, fixture.intent.clone());
        record.purchase = Some(crate::tempo_mpp::Purchase::new("1".into()));
        assert!(
            authorize(
                &bundle,
                &store,
                &mut record,
                &chain,
                |intent| {
                    let saved = load_record(&store, &intent.id).unwrap().unwrap();
                    assert_eq!(saved.intent.mpp_request, intent.mpp_request);
                    assert!(!saved.purchase.unwrap().http_attempted);
                    assert!(saved.signed.is_none());
                    Ok((fixture.preparation.clone(), 10))
                },
                |native, _| native.sign(&[6; 32])
            )
            .unwrap()
            .is_none()
        );
        let saved = load_record(&store, &fixture.intent.id).unwrap().unwrap();
        assert_eq!(saved.signed.unwrap().hash, fixture.signed.hash);
        assert!(chain.sends.borrow().is_empty());
    }
    #[test]
    fn same_signed_mpp_record_recovers_same_hash_without_authorizing_or_signing() {
        let fixture = Fixture::with_mpp("mpp-recovery-001", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        chain.finality.set(Some(true));
        let mut record = fixture.record();
        store.save(&fixture.intent.id, &record).unwrap();
        let (value, code) = reconcile(
            &bundle,
            &store,
            &mut record,
            &chain,
            |_| Ok(fixture.report(true)),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(value["transactionHash"], fixture.signed.hash);
        assert_eq!(chain.builds.get(), 0);
        assert!(chain.sends.borrow().is_empty());
        assert!(
            authorize(
                &bundle,
                &store,
                &mut record,
                &chain,
                |_| panic!("No new authorization on recovery"),
                |_, _| panic!("No replacement signature on recovery")
            )
            .is_err()
        );
    }
    #[test]
    fn mpp_http_attempt_is_durable_and_response_body_never_uploaded_to_backend() {
        let fixture = Fixture::with_mpp("mpp-http-once-001", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let mut record = fixture.record();
        record.finality = Some(finality(true));
        record.report = Some(fixture.report(true));
        store.save(&fixture.intent.id, &record).unwrap();
        let payment = result(&record, "settled", 0, None);
        let body = "{\"answer\":42}".to_owned();
        let (value,code)=finish_purchase(&bundle,&store,&mut record,payment,0, |original,hash| {
            let saved=load_record(&store,&fixture.intent.id).unwrap().unwrap();
            assert!(saved.purchase.unwrap().http_attempted);
            assert_eq!(original,fixture.intent.mpp_request.as_ref().unwrap()); assert_eq!(hash,fixture.signed.hash);
            crate::tempo_mpp::ApiResponse{state:"response_received".into(),http_status:Some(200),
                receipt:Some(json!({"status":"success","method":"tempo","timestamp":"2026-10-13T00:00:00Z","reference":hash})),
                response_digest:Some(crate::tempo_mpp::digest(body.as_bytes())),response_bytes:Some(body.len()),body:Some(body.clone())}
        }, |report| {
            assert!(report["delivery"].get("body").is_none()); assert!(!report.to_string().contains("answer"));
            Ok(fixture.delivery_reply(&report))
        }).unwrap();
        assert_eq!(code, 0);
        assert_eq!(value["purchase"]["body"], body);
        let payment = result(&record, "settled", 6, None);
        let (value, code) = finish_purchase(
            &bundle,
            &store,
            &mut record,
            payment,
            6,
            |_, _| panic!("A consumed HTTP credential must not be resent"),
            |_| panic!("Saved report must not be resent"),
        )
        .unwrap();
        assert_eq!(code, 6);
        assert_eq!(value["purchase"]["body"], body);
    }
    #[test]
    fn interrupted_http_submission_reports_unavailable_without_resend_or_new_payment() {
        let fixture = Fixture::with_mpp("mpp-http-crash-001", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let mut record = fixture.record();
        record.finality = Some(finality(true));
        record.report = Some(fixture.report(true));
        record.purchase.as_mut().unwrap().http_attempted = true;
        store.save(&fixture.intent.id, &record).unwrap();
        let payment = result(&record, "settled", 6, None);
        let (value, code) = finish_purchase(
            &bundle,
            &store,
            &mut record,
            payment,
            6,
            |_, _| panic!("Unknown HTTP outcome cannot safely replay credential"),
            |report| {
                assert_eq!(report["delivery"]["status"], "response_unavailable");
                Ok(fixture.delivery_reply(&report))
            },
        )
        .unwrap();
        assert_eq!(code, 5);
        assert_eq!(value["state"], "settled");
        assert_eq!(value["transactionHash"], fixture.signed.hash);
        assert_eq!(value["purchase"]["state"], "response_unavailable");
    }
    #[test]
    fn tampered_challenge_or_underfunded_maximum_never_reaches_authorization() {
        let fixture = Fixture::with_mpp("mpp-tampered-001", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let chain = MockChain::new(&fixture, &directory);
        for field in ["realm", "id", "url", "max"] {
            let mut record = fixture.record();
            record.native = None;
            record.signed = None;
            match field {
                "realm" => {
                    record.intent.mpp_request.as_mut().unwrap().challenge["realm"] =
                        json!("other.example")
                }
                "id" => {
                    record.intent.mpp_request.as_mut().unwrap().challenge["id"] =
                        json!("other-charge")
                }
                "url" => {
                    record.intent.mpp_request.as_mut().unwrap().url =
                        "https://other.example/paid".into()
                }
                _ => record.purchase.as_mut().unwrap().max_amount = "0.1".into(),
            }
            // Realm/ID changes are detected by authority-signed plan verification;
            // URL/max changes fail even before obtaining a plan.
            assert!(
                authorize(
                    &bundle,
                    &store,
                    &mut record,
                    &chain,
                    |_| Ok((fixture.preparation.clone(), 10)),
                    |_, _| panic!("Tampered request must never be signed")
                )
                .is_err(),
                "{field}"
            );
        }
        assert_eq!(chain.builds.get(), 0);
        assert!(chain.sends.borrow().is_empty());
    }
    #[test]
    fn repeated_call_reuses_original_challenge_and_rejects_new_url_or_cap_without_fetching() {
        let fixture = Fixture::with_mpp("mpp-original-001", 16);
        let bundle = fixture.bundle();
        let directory = TestDirectory::new();
        let store = Store::open(&directory.0).unwrap();
        let record = fixture.record();
        store.save(&fixture.intent.id, &record).unwrap();
        let read = load_call_record(
            &bundle,
            &store,
            "https://merchant.example/paid",
            &fixture.intent.id,
            "1",
            || panic!("A saved request must never fetch a replacement challenge"),
        )
        .unwrap();
        assert_eq!(read.signed.unwrap().hash, fixture.signed.hash);
        for (url, maximum) in [
            ("https://merchant.example/other", "1"),
            ("https://merchant.example/paid", "2"),
        ] {
            assert!(
                load_call_record(
                    &bundle,
                    &store,
                    url,
                    &fixture.intent.id,
                    maximum,
                    || panic!("Changed intent must not fetch or authorize")
                )
                .is_err()
            );
        }
    }
    #[test]
    fn backend_delivery_acknowledgement_cannot_substitute_payment_or_challenge() {
        let fixture = Fixture::with_mpp("mpp-report-001", 16);
        let bound = allowit_tempo::validate_mpp_request(
            fixture.intent.mpp_request.as_ref().unwrap(),
            42431,
            fixture.policy["token"].as_str().unwrap(),
            &fixture.intent.recipient,
            &fixture.intent.amount,
            0,
        )
        .unwrap();
        let sent = json!({"policyId":fixture.policy["id"],"requestId":fixture.intent.id,"transactionHash":fixture.signed.hash,
            "delivery":{"status":"response_unavailable","challengeDigest":bound.challenge_digest}});
        let reply = fixture.delivery_reply(&sent);
        assert!(checked_delivery_report(&reply, &sent, &bound));
        for field in [
            "id",
            "policyId",
            "transactionHash",
            "purchase",
            "reportedBy",
            "challengeDigest",
        ] {
            let mut changed = reply.clone();
            match field {
                "purchase" => changed["operation"]["purchase"]["challengeDigest"] = json!("other"),
                "reportedBy" | "challengeDigest" => {
                    changed["operation"]["delivery"][field] = json!("other")
                }
                _ => changed["operation"][field] = json!("other"),
            }
            assert!(!checked_delivery_report(&changed, &sent, &bound), "{field}");
        }
        assert!(!checked_delivery_report(&json!({}), &sent, &bound));
    }
    #[test]
    fn reflected_payment_credential_opaque_and_terminal_controls_are_not_printed() {
        let fixture = Fixture::with_mpp("mpp-private-001", 16);
        let bundle = fixture.bundle();
        let record = fixture.record();
        let request = fixture.intent.mpp_request.as_ref().unwrap();
        let (_, credential) = crate::tempo_mpp::credential(
            request,
            42431,
            fixture.policy["vault"].as_str().unwrap(),
            &fixture.signed.hash,
        )
        .unwrap();
        let opaque = request.challenge["opaque"].as_str().unwrap();
        let mut value = result(&record, "settled", 0, None);
        value["purchase"] = json!({"state":"response_received","http_status":200,
            "body":format!("{credential} {opaque} \u{1b}[31mAPIresult")});
        for json in [true, false] {
            let text = render_record(&bundle, &record, &value, json);
            assert!(!text.contains(&credential));
            assert!(!text.contains(opaque));
            assert!(!text.contains('\u{1b}'));
            assert!(text.contains("APIresult"));
        }
    }
    #[test]
    fn legacy_tempo_json_keeps_sorted_presentation() {
        let bundle = Fixture::new("native-json-output", 16).bundle();
        let value: Value =
            serde_json::from_str(r#"{"state":"settled","result":{"z":1,"a":2},"amount":"1"}"#)
                .unwrap();
        assert_eq!(
            render(&bundle, &value, true),
            "{\n  \"amount\": \"1\",\n  \"result\": {\n    \"a\": 2,\n    \"z\": 1\n  },\n  \"state\": \"settled\"\n}\n"
        );
    }
}
