use crate::{
    config::Config,
    error::{Error, Result, quoted},
    skill::{Skill, describe_rails, text},
};
use base64::Engine;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    io::Read,
};
#[derive(Default)]
pub(crate) struct Flags(pub BTreeMap<String, String>);
impl Flags {
    pub fn get(&self, k: &str) -> &str {
        self.0.get(k).map(String::as_str).unwrap_or_default()
    }
}
#[derive(Serialize)]
pub(crate) struct Body {
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub amount: String,
    pub token: String,
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub merchant: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub recipient: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<Plan>,
}
#[derive(Serialize)]
pub(crate) struct Plan {
    pub rail: String,
    pub asset: String,
    pub quantity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub memo: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub data: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub before: Vec<Call>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub after: Vec<Call>,
}
#[derive(Serialize)]
pub(crate) struct Call {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub contract: String,
    #[serde(default)]
    pub method: String,
    pub args: Option<Box<RawValue>>,
    #[serde(rename = "maxCostUSDC", default)]
    pub max_cost: String,
}
impl<'de> Deserialize<'de> for Call {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Call;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an execution call object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Call, M::Error> {
                let mut call = Call {
                    kind: String::new(),
                    contract: String::new(),
                    method: String::new(),
                    args: None,
                    max_cost: String::new(),
                };
                while let Some(name) = map.next_key::<String>()? {
                    let slot = match name.to_ascii_lowercase().as_str() {
                        "type" => &mut call.kind,
                        "contract" => &mut call.contract,
                        "method" => &mut call.method,
                        "maxcostusdc" => &mut call.max_cost,
                        "args" => {
                            call.args = Some(map.next_value()?);
                            continue;
                        }
                        _ => return Err(serde::de::Error::custom("unknown execution call field")),
                    };
                    // Go's string fields retain their preceding value on JSON
                    // null; repeated recognized fields use the last value.
                    if let Some(value) = map.next_value::<Option<String>>()? {
                        *slot = value;
                    }
                }
                Ok(call)
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
pub(crate) fn matches(s: &str, pattern: &str) -> bool {
    regex::Regex::new(pattern).unwrap().is_match(s)
}
pub(crate) fn request_id_valid(s: &str) -> bool {
    matches(s, r"^[A-Za-z0-9._:-]{8,100}$")
}
pub(crate) fn solana_address(s: &str) -> bool {
    (32..=44).contains(&s.len()) && bs58::decode(s).into_vec().is_ok_and(|b| b.len() == 32)
}
fn rail_address(rail: &str, s: &str, contract: bool) -> bool {
    match rail {
        "solana" => solana_address(s),
        "stellar" => {
            let Ok(b) = data_encoding::BASE32_NOPAD.decode(s.as_bytes()) else {
                return false;
            };
            if data_encoding::BASE32_NOPAD.encode(&b) != s
                || !((b.len() == 35 && (b[0] == 16 || !contract && b[0] == 48))
                    || !contract && b.len() == 43 && b[0] == 96)
            {
                return false;
            }
            let mut crc = 0u16;
            for octet in &b[..b.len() - 2] {
                crc ^= (*octet as u16) << 8;
                for _ in 0..8 {
                    crc = if crc & 0x8000 != 0 {
                        (crc << 1) ^ 0x1021
                    } else {
                        crc << 1
                    };
                }
            }
            u16::from_le_bytes([b[b.len() - 2], b[b.len() - 1]]) == crc
        }
        _ => false,
    }
}
pub(crate) fn usdc_units(s: &str) -> Result<BigUint> {
    if !matches(s, r"^(0|[1-9][0-9]{0,6})(\.[0-9]{1,6})?$") {
        return Err(Error::usage(format!(
            "{} is not a USDC amount (positive decimal, at most 6 places, no exponent)",
            quoted(s)
        )));
    }
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    let n = format!("{w}{f}{}", "0".repeat(6 - f.len()))
        .parse::<BigUint>()
        .unwrap();
    if n.is_zero() || n > BigUint::from(1_000_000_000_000u64) {
        return Err(Error::usage(format!(
            "{} must be greater than 0 and at most 1000000 USDC",
            quoted(s)
        )));
    }
    Ok(n)
}
fn rational(s: &str) -> (BigUint, BigUint) {
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    (
        format!("{w}{f}").parse().unwrap(),
        BigUint::from(10u32).pow(f.len() as u32),
    )
}
fn charge(
    qty: &str,
    rate: &str,
    decimals: i64,
    calls: impl Iterator<Item = String>,
) -> Result<String> {
    if !matches(qty, r"^(0|[1-9][0-9]{0,6})(\.[0-9]{1,9})?$") {
        return Err(Error::usage(format!(
            "{} is not a quantity (positive decimal, no exponent)",
            quoted(qty)
        )));
    }
    if qty
        .split_once('.')
        .is_some_and(|(_, f)| f.len() as i64 > decimals)
    {
        return Err(Error::usage(format!(
            "{} has more than {decimals} decimal places for this asset",
            quoted(qty)
        )));
    }
    if !matches(rate, r"^(0|[1-9][0-9]{0,11})(\.[0-9]{1,18})?$") {
        return Err(Error::usage("the service published an invalid rate"));
    }
    let (q, qd) = rational(qty);
    if q.is_zero() {
        return Err(Error::usage("quantity must be greater than 0"));
    }
    let (r, rd) = rational(rate);
    let n = q * r * BigUint::from(1_000_000u32);
    let d = qd * rd;
    let mut cost = (&n + &d - BigUint::one()) / &d;
    for (i, c) in calls.enumerate() {
        if c == "0" {
            continue;
        }
        cost += usdc_units(&c).map_err(|e| Error::usage(format!("call {i} maxCostUSDC: {e}")))?;
    }
    if cost.is_zero() || cost > BigUint::from(1_000_000_000_000u64) {
        return Err(Error::usage(
            "the budget charge must be greater than 0 and at most 1000000 USDC",
        ));
    }
    let s = format!("{cost:0>7}");
    let split = s.len() - 6;
    let f = s[split..].trim_end_matches('0');
    Ok(if f.is_empty() {
        s[..split].into()
    } else {
        format!("{}.{}", &s[..split], f)
    })
}
fn prefix(e: Error, p: &str) -> Error {
    Error::usage(format!("{p}: {e}"))
}
pub(crate) fn build_body(kind: &str, f: &Flags, s: &Skill, stdin: &mut dyn Read) -> Result<Body> {
    let mut b = Body {
        request_id: String::new(),
        amount: String::new(),
        token: "USDC".into(),
        action: f.get("action").into(),
        merchant: f.get("merchant").into(),
        recipient: String::new(),
        context: None,
        execution: None,
    };
    if b.action.is_empty() {
        return Err(Error::usage(
            "--action is required: it is the action the policy evaluates (e.g. --action transfer or --action research); --op only selects the transfer. To retry a request sent without --action by allowit 0.1.1, add --action with its --op value (e.g. --action transferUSDC) and keep every other flag: that is the same request and request ID",
        ));
    }
    if b.action.len() > 100 || b.merchant.len() > 200 {
        return Err(Error::usage(
            "--action is limited to 100 bytes and --merchant to 200 bytes",
        ));
    }
    if !f.get("context").is_empty() {
        let raw =
            read_value(f.get("context"), stdin, 16 << 10).map_err(|e| prefix(e, "--context"))?;
        b.context = Some(runtime_context(&raw).map_err(|e| prefix(e, "--context"))?);
    }
    let amount = f.get("amount");
    let rail = f.get("rail");
    let op = f.get("op");
    if amount.is_empty() {
        return Err(Error::usage("--amount is required"));
    }
    if rail.is_empty() != op.is_empty() {
        return Err(Error::usage(
            "--rail and --op are used together; omit both to send --amount as a plain USDC amount",
        ));
    }
    let plan_only = ["memo", "data", "before", "after"]
        .iter()
        .any(|k| !f.get(k).is_empty());
    if rail.is_empty() {
        if plan_only {
            return Err(Error::usage(
                "--memo, --data, --before and --after need --rail and --op",
            ));
        }
        usdc_units(amount).map_err(|e| prefix(e, "--amount"))?;
        b.amount = amount.into();
        b.recipient = f.get("addr").into();
        check_wallet(kind, &b, s)?;
        return Ok(b);
    }
    if !matches(op, r"^transfer([A-Z]{2,10})$") {
        return Err(Error::usage(
            "--op must look like transferSOL, transferXLM or transferUSDC",
        ));
    }
    let asset = &op[8..];
    let rails = s.rails();
    if rails.is_empty() {
        return Err(Error::usage(
            "AllowIt published no rails for this policy; send a plain USDC request with --amount and --action, without --rail and --op",
        ));
    }
    let assets = rails.get(rail).ok_or_else(|| {
        Error::usage(format!(
            "--rail {} is not available for this policy ({})",
            quoted(rail),
            describe_rails(&rails)
        ))
    })?;
    if !assets.iter().any(|a| a == asset) {
        return Err(Error::usage(format!(
            "{asset} is not available on {rail} ({})",
            assets.join(", ")
        )));
    }
    if !s.local() {
        if plan_only {
            return Err(Error::usage(
                "--memo, --data, --before and --after are available only for Local dev policies",
            ));
        }
        if rail != "solana" || asset != "USDC" {
            return Err(Error::usage(
                "wallet policies accept only --rail solana --op transferUSDC",
            ));
        }
        usdc_units(amount).map_err(|e| prefix(e, "--amount"))?;
        b.amount = amount.into();
        b.recipient = f.get("addr").into();
        check_wallet(kind, &b, s)?;
        return Ok(b);
    }
    s.plan_support(
        !f.get("memo").is_empty() || !f.get("data").is_empty(),
        !f.get("before").is_empty() || !f.get("after").is_empty(),
    )?;
    if f.get("addr").is_empty() {
        return Err(Error::usage("--addr is required with --rail"));
    }
    if !rail_address(rail, f.get("addr"), false) {
        return Err(Error::usage(format!(
            "--addr is not a valid {rail} address"
        )));
    }
    let mut p = Plan {
        rail: rail.into(),
        asset: asset.into(),
        quantity: amount.into(),
        memo: f.get("memo").into(),
        data: String::new(),
        before: Vec::new(),
        after: Vec::new(),
    };
    if p.memo.len() > 256 {
        return Err(Error::usage("--memo is limited to 256 bytes"));
    }
    if !f.get("data").is_empty() {
        p.data = base64::engine::general_purpose::STANDARD
            .encode(read_value(f.get("data"), stdin, 1024).map_err(|e| prefix(e, "--data"))?);
    }
    p.before = read_calls("--before", f.get("before"), rail, stdin)?;
    p.after = read_calls("--after", f.get("after"), rail, stdin)?;
    let (rates, decimals) = s.rates();
    let rate = rates
        .get(asset)
        .map(text)
        .ok_or_else(|| Error::usage(format!("the service did not publish a rate for {asset}")))?;
    let precision = decimals
        .get(asset)
        .map(|v| v.as_i64().unwrap_or_default())
        .unwrap_or(match asset {
            "SOL" => 9,
            "XLM" => 7,
            "USDC" => 6,
            _ => 0,
        });
    b.amount = charge(
        amount,
        rate,
        precision,
        p.before.iter().chain(&p.after).map(|c| c.max_cost.clone()),
    )
    .map_err(|e| prefix(e, "--amount"))?;
    b.recipient = f.get("addr").into();
    b.execution = Some(p);
    Ok(b)
}
fn check_wallet(kind: &str, b: &Body, s: &Skill) -> Result<()> {
    if !(s.local() || b.recipient.is_empty() && kind == "eval" || solana_address(&b.recipient)) {
        return Err(Error::usage(
            "--addr must be the recipient's Solana address",
        ));
    }
    Ok(())
}
fn read_calls(name: &str, value: &str, rail: &str, stdin: &mut dyn Read) -> Result<Vec<Call>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let raw = read_value(value, stdin, 32 << 10).map_err(|e| prefix(e, name))?;
    let mut calls: Vec<Call> = if std::str::from_utf8(&raw).unwrap_or_default().trim() == "null" {
        Vec::new()
    } else {
        serde_json::from_slice(&raw).map_err(|_| {
            Error::usage(format!(
                "{name} must be a JSON array of {{type, contract, method, args, maxCostUSDC}}"
            ))
        })?
    };
    if calls.len() > 8 {
        return Err(Error::usage(format!("{name} allows at most 8 calls")));
    }
    for (i, c) in calls.iter_mut().enumerate() {
        if c.kind != "contract_call"
            || !rail_address(rail, &c.contract, true)
            || !matches(&c.method, r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
        {
            return Err(Error::usage(format!(
                "{name}[{i}] needs type contract_call, a valid {rail} contract and a method name"
            )));
        }
        let args = c
            .args
            .as_ref()
            .map(|a| a.get().as_bytes())
            .unwrap_or_default();
        if json_object(args).is_err() || args.len() > 2048 {
            return Err(Error::usage(format!(
                "{name}[{i}].args must be a JSON object of at most 2048 bytes"
            )));
        }
        if c.max_cost.is_empty() {
            return Err(Error::usage(format!(
                "{name}[{i}] needs maxCostUSDC (use \"0\" for none)"
            )));
        }
        c.args = Some(json_object(args)?);
    }
    Ok(calls)
}
fn read_value(value: &str, stdin: &mut dyn Read, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if value == "-" {
        stdin
            .take(limit as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| Error::usage("cannot read input"))?;
    } else if let Some(path) = value.strip_prefix('@') {
        std::fs::File::open(path)
            .map_err(|_| Error::usage("cannot read file"))?
            .take(limit as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|_| Error::usage("cannot read input"))?;
    } else {
        out = value.as_bytes().to_vec();
    }
    if out.len() > limit {
        return Err(Error::usage(format!("larger than {limit} bytes")));
    }
    Ok(out)
}
fn compact(raw: &[u8]) -> String {
    let mut out = Vec::new();
    let mut string = false;
    let mut escape = false;
    for &c in raw {
        if string || !c.is_ascii_whitespace() {
            out.push(c);
        }
        if escape {
            escape = false;
        } else if string && c == b'\\' {
            escape = true;
        } else if c == b'"' {
            string = !string;
        }
    }
    String::from_utf8(out).unwrap()
}
fn json_object(raw: &[u8]) -> Result<Box<RawValue>> {
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let value =
        Value::deserialize(&mut decoder).map_err(|_| Error::usage("must be a JSON object"))?;
    if !value.is_object() {
        return Err(Error::usage("must be a JSON object"));
    }
    decoder
        .end()
        .map_err(|_| Error::usage("must contain exactly one JSON object"))?;
    RawValue::from_string(compact(raw)).map_err(|_| Error::usage("must be a JSON object"))
}
fn runtime_context(raw: &[u8]) -> Result<Box<RawValue>> {
    let ctx = json_object(raw)?;
    if ctx.get().len() > 16 << 10 {
        return Err(Error::usage("must be at most 16 KB"));
    }
    let mut count = 0;

    Scan {
        depth: 1,
        top: true,
        count: &mut count,
    }
    .scan(ctx.get())
    .map_err(|e| {
        let msg = e.to_string();
        let clean = msg.split(" at line ").next().unwrap_or(&msg);
        Error::usage(clean)
    })?;
    Ok(ctx)
}
struct Scan<'a> {
    depth: usize,
    top: bool,
    count: &'a mut usize,
}
impl Scan<'_> {
    fn scan(self, raw: &str) -> std::result::Result<(), serde_json::Error> {
        if self.depth > 9 {
            return Err(<serde_json::Error as de::Error>::custom(
                "is nested more than 8 levels deep",
            ));
        }
        let mut decoder = serde_json::Deserializer::from_str(raw);
        match raw.trim_start().as_bytes().first() {
            Some(b'{') => de::Deserializer::deserialize_map(&mut decoder, self),
            Some(b'[') => de::Deserializer::deserialize_seq(&mut decoder, self),
            _ => Ok(()),
        }
    }
}
impl<'de> Visitor<'de> for Scan<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON object or array")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "repeats the field {}",
                    quoted(&key)
                )));
            }
            if self.top && key == "allowitExecution" {
                return Err(de::Error::custom(
                    "must not contain allowitExecution; AllowIt supplies it",
                ));
            }
            *self.count += 1;
            if *self.count > 128 {
                return Err(de::Error::custom("has more than 128 values"));
            }
            let value = map.next_value::<Box<RawValue>>()?;
            Scan {
                depth: self.depth + 1,
                top: false,
                count: self.count,
            }
            .scan(value.get())
            .map_err(de::Error::custom)?;
        }
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        while let Some(value) = seq.next_element::<Box<RawValue>>()? {
            *self.count += 1;
            if *self.count > 128 {
                return Err(de::Error::custom("has more than 128 values"));
            }
            Scan {
                depth: self.depth + 1,
                top: false,
                count: self.count,
            }
            .scan(value.get())
            .map_err(de::Error::custom)?;
        }
        Ok(())
    }
}
pub(crate) fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_string(value)
        .unwrap()
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        .into_bytes()
}
pub(crate) fn derive_id(kind: &str, cfg: &Config, b: &mut Body) -> String {
    let amount = if b.execution.is_some() {
        std::mem::take(&mut b.amount)
    } else {
        b.amount.clone()
    };
    let mut h = Sha256::new();
    h.update(format!(
        "allowit-cli/v2\n{}\n{}\n{kind}\n",
        cfg.owner, cfg.policy
    ));
    h.update(encode(b));
    if b.execution.is_some() {
        b.amount = amount;
    }
    format!("cli-{kind}-{:x}", h.finalize())[..(5 + kind.len() + 40)].into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_money_and_ceiling() {
        assert_eq!(
            charge("0.000000001", "0.000001", 9, std::iter::empty()).unwrap(),
            "0.000001"
        );
        assert_eq!(
            charge("0.01", "100", 9, ["0.25".into(), "0".into()].into_iter()).unwrap(),
            "1.25"
        );
        for s in ["0", "01", "1e1", "1000000.000001", "0.0000001"] {
            assert!(usdc_units(s).is_err(), "{s}");
        }
    }
    #[test]
    fn context_preserves_integer_text_order_and_limits() {
        let raw = br#"{ "z": 18446744073709551615, "a":1.2300, "b":1e5 }"#;
        assert_eq!(
            runtime_context(raw).unwrap().get(),
            r#"{"z":18446744073709551615,"a":1.2300,"b":1e5}"#
        );
        for raw in [
            r#"{"a":1,"a":2}"#,
            r#"{"x":{"y":1,"y":2}}"#,
            r#"{"allowitExecution":{}}"#,
        ] {
            assert!(runtime_context(raw.as_bytes()).is_err());
        }
        let huge = format!(
            "{{{}}}",
            (0..129)
                .map(|i| format!("\"{i}\":{i}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(runtime_context(huge.as_bytes()).is_err());
    }
    #[test]
    fn address_checks() {
        assert!(solana_address("11111111111111111111111111111111"));
        assert!(!solana_address("00000000000000000000000000000000"));
        assert!(rail_address(
            "stellar",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            false
        ));
        assert!(!rail_address(
            "stellar",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            true
        ));
        assert!(rail_address(
            "stellar",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            true
        ));
    }
}
