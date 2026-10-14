//! Native contract-backed Stellar x402 purchases with explicit operator approval.
use crate::{
    config::env_value,
    error::{Error, Result},
    stellar_http,
    stellar_rpc::Rpc,
    stellar_store::Store,
};
use allowit_stellar::{
    Config, DetachedApproval, PaymentRequest, PreparedPayment, SettlementReceipt, SignedPayment,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const USAGE: &str = include_str!("stellar-usage.txt");
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    id: String,
    url: String,
    max_amount: String,
    prepared: PreparedPayment,
    signed: Option<SignedPayment>,
    attempted: bool,
    delivery: Option<stellar_http::Delivery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settlement: Option<SettlementReceipt>,
    verified: bool,
}

fn checked<T>(value: std::result::Result<T, String>) -> Result<T> {
    value.map_err(|_| {
        Error::config("Stellar exact payment validation failed; retain the original journal")
    })
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| Error::config("Cannot determine Stellar payment validity"))
}
fn state_path() -> Result<PathBuf> {
    let explicit = env_value("ALLOWIT_STELLAR_STATE_DIR");
    if !explicit.is_empty() {
        return Ok(explicit.into());
    }
    let xdg = env_value("XDG_STATE_HOME");
    if !xdg.is_empty() {
        return Ok(PathBuf::from(xdg).join("allowit/stellar"));
    }
    let home = env_value("HOME");
    if !home.is_empty() {
        return Ok(PathBuf::from(home).join(".local/state/allowit/stellar"));
    }
    Err(Error::config(
        "Set ALLOWIT_STELLAR_STATE_DIR to private local POSIX storage",
    ))
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = File::open(path)
        .map_err(|_| Error::config("Cannot read Stellar configuration or approval file"))?;
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::config("Cannot read Stellar input"))?;
    if bytes.len() > 65_536 {
        return Err(Error::config("Stellar input exceeds 64 KiB"));
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::config("Invalid Stellar input JSON"))
}
fn same<T: Serialize>(a: &T, b: &T) -> Result<bool> {
    Ok(
        serde_json::to_value(a).map_err(|_| Error::config("Invalid Stellar binding"))?
            == serde_json::to_value(b).map_err(|_| Error::config("Invalid Stellar binding"))?,
    )
}

struct Options {
    pos: Vec<String>,
    id: Option<String>,
    max: Option<String>,
    approval: Option<PathBuf>,
    transaction: Option<String>,
    json: bool,
}
impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut result = Self {
            pos: Vec::new(),
            id: None,
            max: None,
            approval: None,
            transaction: None,
            json: false,
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--json" if !result.json => result.json = true,
                "--id" if result.id.is_none() => {
                    result.id = Some(
                        args.next()
                            .ok_or_else(|| Error::usage("Missing --id value"))?
                            .clone(),
                    )
                }
                "--max-amount" if result.max.is_none() => {
                    result.max = Some(
                        args.next()
                            .ok_or_else(|| Error::usage("Missing --max-amount value"))?
                            .clone(),
                    )
                }
                "--approval" if result.approval.is_none() => {
                    result.approval = Some(
                        args.next()
                            .ok_or_else(|| Error::usage("Missing --approval file"))?
                            .into(),
                    )
                }
                "--transaction" if result.transaction.is_none() => {
                    let hash = args
                        .next()
                        .ok_or_else(|| Error::usage("Missing --transaction hash"))?;
                    if hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
                        return Err(Error::usage("Use a 64-character Stellar transaction hash"));
                    }
                    result.transaction = Some(hash.to_ascii_lowercase());
                }
                _ if !arg.starts_with('-') => result.pos.push(arg.clone()),
                _ => return Err(Error::usage("Unknown or repeated Stellar option")),
            }
        }
        Ok(result)
    }
    fn purchase(&self) -> Result<(&str, &str, &str)> {
        if self.pos.len() != 1 || self.transaction.is_some() {
            return Err(Error::usage("A Stellar purchase requires one HTTPS URL"));
        }
        let id = self
            .id
            .as_deref()
            .ok_or_else(|| Error::usage("Use --id REQUEST_ID"))?;
        request_id(id)?;
        let max = self
            .max
            .as_deref()
            .ok_or_else(|| Error::usage("Use --max-amount AMOUNT"))?;
        maximum(max)?;
        stellar_http::endpoint(&self.pos[0])?;
        Ok((&self.pos[0], id, max))
    }
    fn operation(&self) -> Result<&str> {
        if self.pos.len() != 1 || self.id.is_some() || self.max.is_some() || self.approval.is_some()
        {
            return Err(Error::usage("Use one original Stellar request ID"));
        }
        request_id(&self.pos[0])?;
        Ok(&self.pos[0])
    }
}
fn request_id(value: &str) -> Result<()> {
    if !(8..=100).contains(&value.len())
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
    {
        return Err(Error::usage(
            "Request ID must be 8 to 100 characters from A-Z a-z 0-9 . _ : -",
        ));
    }
    Ok(())
}
fn maximum(value: &str) -> Result<u64> {
    allowit_tempo::units(value)
        .map_err(|_| Error::usage("Use an exact positive maximum with at most six decimal places"))?
        .checked_mul(10)
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::usage("Stellar maximum is zero or overflows native units"))
}
fn seed(env: &str) -> Result<Zeroizing<[u8; 32]>> {
    let path = env_value(env);
    if path.is_empty() {
        return Err(Error::config(format!(
            "Set {env} to a private 0600 executor or trusted operator seed file"
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(&path)
        .map_err(|_| Error::config("Cannot read designated Stellar signing key"))?;
    let meta = file
        .metadata()
        .map_err(|_| Error::config("Cannot inspect designated Stellar key"))?;
    if !meta.is_file() {
        return Err(Error::config(
            "Stellar signing key must be a private regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
        {
            return Err(Error::config(
                "Stellar signing key must be owned by the executor and have mode 0600",
            ));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(257)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::config("Cannot read Stellar key"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::config("Use a 32-byte hex Stellar seed file"))?
        .trim();
    if text.len() != 64 || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::config(
            "Use a 32-byte hex Stellar seed file; never pass keys as command arguments",
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::config("Invalid Stellar key"))?;
    }
    Ok(key)
}

fn validate_record(config: &Config, record: &Record) -> Result<()> {
    request_id(&record.id)?;
    stellar_http::endpoint(&record.url)?;
    if record.version != 1
        || record.prepared.request.url != record.url
        || record.prepared.request.method != "GET"
        || !record.prepared.request.body.is_empty()
        || !same(config, &record.prepared.config)?
        || (record.attempted || record.delivery.is_some() || record.verified)
            && record.signed.is_none()
        || record.delivery.is_some() && !record.attempted
        || record.verified && record.delivery.is_none() && record.settlement.is_none()
        || record.settlement.is_some() && (!record.attempted || record.signed.is_none())
    {
        return Err(Error::config(
            "Contradictory Stellar journal; preserve the original request",
        ));
    }
    let selected = checked(allowit_stellar::select_offer(
        &record.prepared.request.payment_required,
        &config.network,
        maximum(&record.max_amount)?,
    ))?;
    if selected != record.prepared.request.selected_offer {
        return Err(Error::config(
            "Saved Stellar quote differs from its exact maximum",
        ));
    }
    checked(allowit_stellar::validate_prepared(
        config,
        &record.prepared,
        record.prepared.created_at,
    ))?;
    if let Some(signed) = &record.signed {
        checked(allowit_stellar::validate_signed(
            config,
            &record.prepared,
            signed,
        ))?;
    }
    Ok(())
}
fn prepare(config: &Config, url: &str, id: &str, max: &str) -> Result<Record> {
    let required = stellar_http::quote(url)?;
    let selected = checked(allowit_stellar::select_offer(
        &required,
        &config.network,
        maximum(max)?,
    ))?;
    let rpc = Rpc::new(config)?;
    let (state, ledger) = rpc.live(config)?;
    let transaction = checked(allowit_stellar::transfer_transaction(config, &selected))?;
    let simulation = rpc.simulate(&transaction)?;
    let auth = simulation["results"][0]["auth"]
        .as_array()
        .filter(|v| v.len() == 1)
        .and_then(|v| v[0].as_str())
        .ok_or_else(|| {
            Error::config("A Stellar x402 quote must produce exactly one vault authorization")
        })?;
    let timeout = selected["maxTimeoutSeconds"]
        .as_u64()
        .ok_or_else(|| Error::config("Missing Stellar quote lifetime"))?;
    let expiry = ledger
        .checked_add(
            u32::try_from(timeout.min(60).div_ceil(5))
                .map_err(|_| Error::config("Invalid Stellar quote lifetime"))?,
        )
        .ok_or_else(|| Error::config("Stellar ledger expiration overflow"))?;
    let current = now()?;
    let request = PaymentRequest {
        method: "GET".into(),
        url: url.into(),
        body: vec![],
        resource: required["resource"].clone(),
        payment_required: required,
        selected_offer: selected,
    };
    let mut prepared = checked(allowit_stellar::prepare_payment(
        config,
        &state,
        request,
        auth,
        expiry,
        current + timeout.min(120),
        current,
    ))?;
    let data = simulation["transactionData"]
        .as_str()
        .ok_or_else(|| Error::config("Stellar simulation omitted resource data"))?;
    let fee = simulation["minResourceFee"]
        .as_str()
        .ok_or_else(|| Error::config("Stellar simulation omitted resource fee"))?;
    prepared.transaction_xdr = checked(allowit_stellar::attach_simulation_data(
        &prepared.transaction_xdr,
        data,
        fee,
    ))?;
    Ok(Record {
        version: 1,
        id: id.into(),
        url: url.into(),
        max_amount: max.into(),
        prepared,
        signed: None,
        attempted: false,
        delivery: None,
        settlement: None,
        verified: false,
    })
}

fn validate_live(config: &Config, record: &Record) -> Result<Rpc> {
    checked(allowit_stellar::validate_prepared(
        config,
        &record.prepared,
        now()?,
    ))?;
    let rpc = Rpc::new(config)?;
    let (state, ledger) = rpc.live(config)?;
    if !same(&state, &record.prepared.state)?
        || ledger >= record.prepared.signature_expiration_ledger
    {
        return Err(Error::config(
            "Stellar vault state changed or authorization expired; no signature was made",
        ));
    }
    // Contract/pin reads can consume most of a short quote lifetime. Recheck
    // both clocks at the final signing boundary instead of using their first read.
    checked(allowit_stellar::validate_prepared(
        config,
        &record.prepared,
        now()?,
    ))?;
    let fresh_ledger = rpc.read("getLatestLedger", json!({}))?["sequence"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::config("Invalid final Stellar ledger sequence"))?;
    if fresh_ledger >= record.prepared.signature_expiration_ledger {
        return Err(Error::config(
            "Stellar authorization expired before signing; no new signature was made",
        ));
    }
    Ok(rpc)
}
fn ensure_executor_available(store: &Store, except: &str) -> Result<()> {
    for saved in store.entries::<Record>()? {
        if saved.id != except && saved.signed.is_some() && !saved.verified {
            return Err(Error::uncertain(format!(
                "Executor has an unresolved signed Stellar request {}; resume its original journal before preparing or signing another purchase",
                serde_json::to_string(&saved.id)
                    .map_err(|_| Error::config("Invalid saved request ID"))?
            )));
        }
    }
    Ok(())
}
fn output(record: &Record, json_output: bool, stdout: &mut String) -> Result<i32> {
    let delivered = record.verified
        && record
            .delivery
            .as_ref()
            .is_some_and(|d| (200..300).contains(&d.status) && d.body.is_some());
    let status = if record.verified {
        "settled"
    } else if record.attempted {
        "uncertain"
    } else if record.signed.is_some() {
        "signed"
    } else {
        "prepared"
    };
    let code = if delivered {
        0
    } else if record.attempted || record.verified {
        5
    } else {
        10
    };
    if json_output {
        *stdout += &format!(
            "{}\n",
            json!({"requestId":record.id,"status":status,"paymentVerified":record.verified,"deliveryAvailable":delivered,"settlement":if record.verified {serde_json::to_value(&record.settlement).map_err(|_|Error::config("Invalid settled receipt"))?}else{Value::Null},"requestHash":record.prepared.request_hash,"authorizationDigest":record.prepared.authorization_digest,"prepared":if record.attempted {Value::Null}else{serde_json::to_value(&record.prepared).map_err(|_|Error::config("Invalid Stellar plan"))?},"response":if record.verified {record.delivery.as_ref().map(|d|json!({"httpStatus":d.status,"body":d.body,"receipt":d.receipt})).unwrap_or(Value::Null)} else {Value::Null}})
        );
    } else {
        *stdout += &format!("Stellar request {}: {status}\n", record.id);
        if record.verified
            && let Some(delivery) = &record.delivery
        {
            *stdout += &format!(
                "HTTP {}\n{}\n",
                delivery.status,
                serde_json::to_string(&delivery.body)
                    .map_err(|_| Error::config("Invalid response"))?
            );
        }
    }
    Ok(code)
}

fn settlement(
    config: &Config,
    record: &Record,
    supplied: Option<&str>,
) -> Result<Option<SettlementReceipt>> {
    let mut provider = record
        .delivery
        .as_ref()
        .map(|delivery| {
            checked(allowit_stellar::parse_payment_response(
                &delivery.receipt_header,
                config,
            ))
        })
        .transpose()?;
    if let Some(receipt) = provider.as_mut() {
        receipt.transaction = allowit_stellar::hex(&checked(allowit_stellar::unhex::<32>(
            &receipt.transaction,
        ))?);
    }
    if let (Some(saved), Some(provider)) = (&record.settlement, &provider)
        && !same(saved, provider)?
    {
        return Err(Error::config(
            "Saved Stellar settlement differs from the original provider receipt",
        ));
    }
    let existing = provider.or_else(|| record.settlement.clone());
    if let (Some(existing), Some(hash)) = (&existing, supplied)
        && existing.transaction != hash
    {
        return Err(Error::config(
            "The supplied transaction differs from this original Stellar settlement",
        ));
    }
    if let Some(existing) = existing {
        return Ok(Some(existing));
    }
    Ok(supplied.map(|hash| SettlementReceipt {
        transaction: hash.into(),
        payer: config.vault.clone(),
        network: config.network.clone(),
    }))
}
fn reconcile(config: &Config, record: &mut Record) -> Result<()> {
    let Some(receipt) = record.settlement.as_ref() else {
        return Ok(());
    };
    let rpc = Rpc::new(config)?;
    // Historical exact receipts remain verifiable after revocation or policy
    // changes. A new live vault state cannot replace the saved authorization.
    rpc.network(config)?;
    let transaction = rpc.read("getTransaction", json!({"hash":receipt.transaction}))?;
    if matches!(
        transaction["status"].as_str(),
        Some("NOT_FOUND" | "PENDING")
    ) {
        record.verified = false;
        return Ok(());
    }
    checked(allowit_stellar::validate_receipt(
        config,
        &record.prepared,
        record
            .signed
            .as_ref()
            .ok_or_else(|| Error::config("Missing saved credential"))?,
        receipt,
        &transaction,
    ))?;
    record.verified = true;
    Ok(())
}

pub(crate) fn run(args: &[String], stdout: &mut String, _stderr: &mut String) -> Result<i32> {
    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        stdout.push_str(USAGE);
        return Ok(0);
    }
    let command = args[0].as_str();
    if !["import", "prepare", "authorize", "call", "resume", "status"].contains(&command) {
        return Err(Error::usage("Unknown Stellar command"));
    }
    let options = Options::parse(&args[1..])?;
    if options.transaction.is_some() && command != "resume" {
        return Err(Error::usage(
            "--transaction is supported only for recovery of an original Stellar request",
        ));
    }
    let base = state_path()?;
    let configuration = Store::open(&base.join("configuration"))?;
    if command == "import" {
        if options.pos.len() != 1
            || options.id.is_some()
            || options.max.is_some()
            || options.approval.is_some()
            || options.transaction.is_some()
        {
            return Err(Error::usage("Use allowit stellar import CONFIG_JSON"));
        }
        let config: Config = read_json(Path::new(&options.pos[0]))?;
        checked(allowit_stellar::validate_config(&config))?;
        if let Some(old) = configuration.load::<Config>("configuration")?
            && !same(&old, &config)?
        {
            return Err(Error::config(
                "Use a separate state directory for a different Stellar configuration; preserve existing recovery data",
            ));
        }
        configuration.save("configuration", &config)?;
        *stdout += if options.json {
            "{\"status\":\"imported\",\"executed\":false}\n"
        } else {
            "Stellar configuration imported. No funds moved.\n"
        };
        return Ok(0);
    }
    let config = configuration
        .load::<Config>("configuration")?
        .ok_or_else(|| Error::config("Import the pinned Stellar configuration first"))?;
    let store = Store::open(&base.join("operations"))?;
    let mut record = if matches!(command, "prepare" | "call") {
        let (url, id, max) = options.purchase()?;
        if command == "prepare" && options.approval.is_some() {
            return Err(Error::usage(
                "Prepare does not accept an approval or read signing keys",
            ));
        }
        match store.load::<Record>(id)? {
            Some(record) => {
                if record.id != id || record.url != url || record.max_amount != max {
                    return Err(Error::config(
                        "Request ID already binds another URL or maximum; resume the original operation",
                    ));
                }
                record
            }
            None if command == "call" => {
                return Err(Error::config(
                    "Prepare this exact Stellar call first and obtain its explicit trusted operator approval",
                ));
            }
            None => {
                ensure_executor_available(&store, id)?;
                let record = prepare(&config, url, id, max)?;
                store.save(id, &record)?;
                record
            }
        }
    } else {
        let id = options.operation()?;
        let record = store.load::<Record>(id)?.ok_or_else(|| {
            Error::config("No saved Stellar request; preserve its original state directory")
        })?;
        if record.id != id {
            return Err(Error::config("Saved Stellar request ID mismatch"));
        }
        record
    };
    validate_record(&config, &record)?;
    if command == "authorize" {
        if record.signed.is_some() || record.attempted {
            return Err(Error::config(
                "A signed Stellar request cannot be authorized again",
            ));
        }
        ensure_executor_available(&store, &record.id)?;
        let _ = validate_live(&config, &record)?;
        let key = seed("ALLOWIT_STELLAR_AUTHORITY_KEY_FILE")?;
        let approval = checked(allowit_stellar::authority_sign(
            &config,
            &record.prepared,
            &key,
        ))?;
        *stdout += &format!(
            "{}\n",
            serde_json::to_string(&approval)
                .map_err(|_| Error::config("Cannot encode detached operator approval"))?
        );
        return Ok(0);
    }
    if command == "call" && !record.attempted {
        ensure_executor_available(&store, &record.id)?;
        let _ = validate_live(&config, &record)?;
        if record.signed.is_none() {
            let approval: DetachedApproval =
                read_json(options.approval.as_deref().ok_or_else(|| {
                    Error::usage("Call requires --approval FILE for this exact prepared plan")
                })?)?;
            checked(allowit_stellar::verify_approval(
                &config,
                &record.prepared,
                &approval,
            ))?;
            let key = seed("ALLOWIT_STELLAR_EXECUTOR_KEY_FILE")?;
            record.signed = Some(checked(allowit_stellar::sign_payment(
                &config,
                &record.prepared,
                &key,
                &approval,
            ))?);
            store.save(&record.id, &record)?;
        }
        // These exact persisted bytes are the only credential ever sent for this ID.
        record.attempted = true;
        store.save(&record.id, &record)?;
        record.delivery = Some(stellar_http::deliver(
            &record.url,
            &record.signed.as_ref().unwrap().payment_signature,
            &record.id,
        )?);
        store.save(&record.id, &record)?;
    }
    if options.transaction.is_some() && (!record.attempted || record.signed.is_none()) {
        return Err(Error::config(
            "Transaction-hash recovery requires the original saved signed and attempted Stellar purchase",
        ));
    }
    if matches!(command, "call" | "resume" | "status") {
        let saved = record.settlement.clone();
        record.settlement = settlement(&config, &record, options.transaction.as_deref())?;
        let reconciled = reconcile(&config, &mut record);
        // A user-supplied hash is only a lookup hint until exact chain proof.
        // An incorrect hint must not replace or freeze the original purchase.
        if !record.verified {
            record.settlement = saved;
        }
        store.save(&record.id, &record)?;
        reconciled?;
    }
    output(&record, options.json, stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn amounts_are_checked_policy_to_native_units() {
        assert_eq!(maximum("0.000001").unwrap(), 10);
        assert_eq!(maximum("1.25").unwrap(), 12_500_000);
        for value in ["0", "0.0000001", "1e2", "-1", "01", "18446744073709551615"] {
            assert!(maximum(value).is_err());
        }
    }
    #[test]
    fn explicit_immutable_identity_and_option_values_are_required() {
        let args = vec![
            "https://agent402.tools/api?city=Almaty".into(),
            "--id".into(),
            "purchase-01".into(),
            "--max-amount".into(),
            "1".into(),
        ];
        let opts = Options::parse(&args).unwrap();
        assert_eq!(opts.purchase().unwrap().1, "purchase-01");
        assert!(Options::parse(&["--id".into()]).is_err());
        assert!(Options::parse(&["--json".into(), "--json".into()]).is_err());
        assert!(request_id("../request").is_err());
    }
}
