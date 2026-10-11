use crate::{
    client::Client,
    config::Config,
    error::{Error, Result, quoted},
    output::short,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Network {
    Unknown,
    Local,
    Wallet,
}
pub(crate) struct Skill(pub Value);
pub(crate) fn text(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}
fn field<'a>(v: &'a Value, p: &str) -> &'a Value {
    v.pointer(p).unwrap_or(&Value::Null)
}
impl Skill {
    pub fn read(c: &mut Client) -> Result<Self> {
        let s = Self(c.call("GET", "skill", None)?);
        s.check(&c.cfg)?;
        Ok(s)
    }
    pub fn get(&self, key: &str) -> &str {
        text(&self.0[key])
    }
    pub fn net(&self) -> Network {
        match self.get("network") {
            "local:dev" => Network::Local,
            "solana:devnet" | "solana:testnet" | "solana:mainnet" => Network::Wallet,
            _ => Network::Unknown,
        }
    }
    pub fn local(&self) -> bool {
        self.net() == Network::Local
    }
    pub fn contract(&self) -> Option<&Value> {
        self.0.get("contract").filter(|v| !v.is_null())
    }
    fn check(&self, cfg: &Config) -> Result<()> {
        validate_schema(&self.0).map_err(|e| {
            Error::unsupported(format!(
                "AllowIt returned a policy description this CLI cannot read: {e}"
            ))
        })?;
        let owner = self.get("owner");
        let policy = self.get("policyId");
        if !owner.is_empty() && owner != cfg.owner || !policy.is_empty() && policy != cfg.policy {
            return Err(Error::config(format!(
                "AllowIt described policy {} of owner {}, not the policy in ALLOWIT_TOKEN",
                unset(policy),
                unset(owner)
            )));
        }
        for action in ["judge", "transactions", "status", "skill"] {
            if let Some(v) = self.0["endpoints"].get(action) {
                let raw = text(v);
                if !cfg.is_route(action, raw) {
                    return Err(Error::config(format!(
                        "AllowIt reported the {action} endpoint {}, which is not {}; check ALLOWIT_URL",
                        quoted(raw),
                        cfg.route(action)
                    )));
                }
            }
        }
        let network = self.get("network");
        if network.is_empty() {
            return Err(Error::unsupported(
                "AllowIt did not report the policy's network",
            ));
        }
        let net = self.net();
        if net == Network::Unknown {
            return Err(Error::unsupported(format!(
                "AllowIt reports network {}, which this CLI does not support",
                quoted(network)
            )));
        }
        let mut labels = vec![
            (
                "executionMode",
                self.get("executionMode"),
                "local",
                "owner_signed",
            ),
            (
                "capabilities.mode",
                text(field(&self.0, "/capabilities/mode")),
                "mock",
                "owner_signed",
            ),
            (
                "capabilities.execution",
                text(field(&self.0, "/capabilities/execution")),
                "mock",
                "owner_signed",
            ),
        ];
        if let Some(c) = self.contract() {
            let version = c["version"].as_i64().unwrap_or_default();
            if version != 1 {
                return Err(Error::unsupported(format!(
                    "AllowIt published skill contract version {version}; this CLI supports version 1"
                )));
            }
            let bound = text(&c["binding"]["sourceHash"]);
            if !bound.is_empty()
                && !self.get("sourceHash").is_empty()
                && bound != self.get("sourceHash")
            {
                return Err(Error::unsupported(format!(
                    "AllowIt published a contract bound to source {} for policy source {}",
                    short(bound),
                    short(self.get("sourceHash"))
                )));
            }
            labels.push((
                "contract.profile",
                text(&c["profile"]),
                "local_dev",
                "solana_owner_signed",
            ));
            labels.push((
                "contract.capabilities.execution",
                text(&c["capabilities"]["execution"]),
                "mock",
                "owner_signed",
            ));
        }
        for (name, value, local, wallet) in labels {
            if !value.is_empty() && value != if net == Network::Local { local } else { wallet } {
                return Err(Error::unsupported(format!(
                    "AllowIt reports {name} {} for network {}, which this CLI does not support",
                    quoted(value),
                    quoted(network)
                )));
            }
        }
        Ok(())
    }
    pub fn rails(&self) -> BTreeMap<String, Vec<String>> {
        for p in ["/contract/capabilities/rails", "/capabilities/rails"] {
            if let Some(m) = field(&self.0, p).as_object().filter(|m| !m.is_empty()) {
                return m
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            v.as_array()
                                .map(|a| a.iter().map(|x| text(x).to_string()).collect())
                                .unwrap_or_default(),
                        )
                    })
                    .collect();
            }
        }
        let rail = text(&self.0["capabilities"]["rail"]);
        if !rail.is_empty() {
            return [(
                rail.into(),
                self.0["capabilities"]["assets"]
                    .as_array()
                    .map(|a| a.iter().map(|x| text(x).into()).collect())
                    .unwrap_or_default(),
            )]
            .into();
        }
        if self.net() == Network::Wallet {
            return [("solana".into(), vec!["USDC".into()])].into();
        }
        BTreeMap::new()
    }
    pub fn rates(&self) -> (&Value, &Value) {
        if field(&self.0, "/contract/capabilities/fixedTestRatesUSDC")
            .as_object()
            .is_some_and(|m| !m.is_empty())
        {
            (
                field(&self.0, "/contract/capabilities/fixedTestRatesUSDC"),
                field(&self.0, "/contract/capabilities/assetDecimals"),
            )
        } else {
            (
                field(&self.0, "/capabilities/fixedTestRatesUSDC"),
                field(&self.0, "/capabilities/assetDecimals"),
            )
        }
    }
    pub fn calls_need_owner(&self) -> bool {
        field(&self.0, "/capabilities/callsRequireOwnerApproval") == &Value::Bool(true)
            || field(
                &self.0,
                "/contract/capabilities/ownerAnswerRequiredForCalls",
            ) == &Value::Bool(true)
    }
    pub fn plan_support(&self, memo: bool, calls: bool) -> Result<()> {
        if let Some(c) = self.contract() {
            let caps = &c["capabilities"];
            let msg = if caps["executionPlans"] != true {
                "AllowIt does not accept execution plans for this policy; send a plain request with --amount and --action"
            } else if memo && caps["memoData"] != true {
                "AllowIt does not accept --memo or --data for this policy"
            } else if calls && caps["contractCalls"] != true {
                "AllowIt does not accept --before or --after contract calls for this policy"
            } else {
                return Ok(());
            };
            return Err(Error::usage(msg));
        }
        Ok(())
    }
    pub fn title(&self) -> &str {
        if !self.get("title").is_empty() {
            self.get("title")
        } else {
            let n = self
                .get("name")
                .strip_prefix("AllowIt policy ")
                .unwrap_or(self.get("name"));
            if n.is_empty() { "(untitled)" } else { n }
        }
    }
    pub fn show(&self, policy: &str, source: bool) -> String {
        let mut out = format!("AllowIt policy: {}\n", self.title());
        let revision = self.0["revision"].as_i64().unwrap_or_default();
        let hash = self.get("sourceHash");
        let id = self.get("policyId");
        if id.is_empty() {
            out += &format!(
                "Policy:     {policy} (from ALLOWIT_TOKEN; AllowIt did not report the policy ID)\n"
            );
        } else if revision > 0 || !hash.is_empty() {
            out += &format!(
                "Policy:     {id} (revision {revision}, source {})\n",
                short(hash)
            );
        } else {
            out += &format!("Policy:     {id}\n");
        }
        if let Some(c) = self.contract()
            && !text(&c["binding"]["irHash"]).is_empty()
        {
            out += &format!(
                "Binding:    IR {}, registry {}\n",
                short(text(&c["binding"]["irHash"])),
                text(&c["binding"]["registryVersion"])
            );
        }
        out += &format!(
            "Network:    {} ({})\n",
            self.get("network"),
            if self.local() {
                "mock execution; no wallet, no funds move"
            } else {
                "every transfer needs the owner's wallet signature"
            }
        );
        if !self.get("status").is_empty() {
            out += &format!("Status:     {}\n", self.get("status"));
        }
        if !self.get("expiresAt").is_empty() {
            out += &format!("Access:     expires {}\n", self.get("expiresAt"));
        }
        if !self.0["budget"].is_null() {
            out += &format!(
                "Budget:     {} USDC allocated, {} USDC spent\n",
                text(&self.0["budget"]["allocation"]),
                text(&self.0["budget"]["spent"])
            );
        } else if !self.0["allocation"].is_null() {
            out += &format!(
                "Budget:     {} USDC allocated\n",
                text(&self.0["allocation"]["amount"])
            );
        }
        let rails = self.rails();
        if !rails.is_empty() {
            out += &format!("Rails:      {}\n", describe_rails(&rails));
        } else {
            out += "Rails:      none published (plain USDC requests with --amount and --action only)\n";
        }
        let (rates, _) = self.rates();
        if self.local() && rates.as_object().is_some_and(|m| !m.is_empty()) {
            out += &format!(
                "Test rates: {} (USDC per unit; fixed, not market prices)\n",
                rates
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| format!("{k}={}", text(v)))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        if self.local() && self.calls_need_owner() {
            out +=
                "Calls:      contract calls in --before/--after always need the owner's approval\n";
        }
        if let Some(keys) = field(&self.0, "/contract/contextU64Keys")
            .as_array()
            .filter(|a| !a.is_empty())
        {
            out += &format!(
                "Context:    the policy may read these --context fields as non-negative integers: {}\n",
                keys.iter()
                    .map(|k| quoted(text(k)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if let Some(steps) = self.0["workflow"].as_array().filter(|a| !a.is_empty()) {
            out += "Checks:\n";
            for (i, s) in steps.iter().enumerate() {
                let label = text(&s["label"]);
                let desc = text(&s["description"]);
                out += &format!(
                    "  {}. {}{}\n",
                    i + 1,
                    label,
                    if !desc.is_empty() && desc != label {
                        format!(" — {desc}")
                    } else {
                        String::new()
                    }
                );
            }
        }
        let intent = self.get("originalIntent").trim();
        if !intent.is_empty() {
            out += "Original request:\n";
            for l in intent.split('\n') {
                out += &format!("  {l}\n");
            }
        }
        if source {
            out += &format!(
                "\nPolicy source ({}):\n{}\n",
                self.get("language"),
                self.get("policy")
            );
        }
        out
    }
}
fn unset(v: &str) -> &str {
    if v.is_empty() { "(unset)" } else { v }
}
pub(crate) fn describe_rails(m: &BTreeMap<String, Vec<String>>) -> String {
    m.iter()
        .map(|(k, v)| format!("{k} ({})", v.join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}
// Match the Go skill decoder's typed known fields, while allowing omitted/null
// fields and forward-compatible unknown metadata.
fn validate_schema(v: &Value) -> std::result::Result<(), String> {
    fn obj<'a>(
        v: &'a Value,
        name: &str,
    ) -> std::result::Result<Option<&'a Map<String, Value>>, String> {
        if v.is_null() {
            return Ok(None);
        }
        v.as_object()
            .map(Some)
            .ok_or_else(|| format!("invalid {name}"))
    }
    fn scalar(v: &Value, kind: &str, name: &str) -> std::result::Result<(), String> {
        if v.is_null() {
            return Ok(());
        }
        let good = match kind {
            "string" => v.is_string(),
            "integer" => v.as_i64().is_some(),
            "boolean" => v.is_boolean(),
            _ => false,
        };
        if good {
            Ok(())
        } else {
            Err(format!("invalid {name}"))
        }
    }
    fn fields(v: &Value, names: &[&str], kind: &str) -> std::result::Result<(), String> {
        for n in names {
            scalar(&v[n], kind, n)?;
        }
        Ok(())
    }
    obj(v, "skill")?;
    fields(
        v,
        &[
            "title",
            "name",
            "owner",
            "policyId",
            "status",
            "network",
            "sourceHash",
            "language",
            "originalIntent",
            "executionMode",
            "expiresAt",
            "policy",
        ],
        "string",
    )?;
    fields(v, &["revision"], "integer")?;
    for key in ["endpoints", "budget", "allocation"] {
        if let Some(m) = obj(&v[key], key)? {
            for (k, value) in m {
                if key == "endpoints"
                    || key == "budget" && ["allocation", "spent"].contains(&k.as_str())
                    || key == "allocation" && k == "amount"
                {
                    scalar(value, "string", k)?;
                }
            }
        }
    }
    for p in ["/capabilities", "/contract/capabilities"] {
        let x = field(v, p);
        obj(x, p)?;
        fields(x, &["mode", "execution", "rail"], "string")?;
        fields(
            x,
            &[
                "executionPlans",
                "memoData",
                "contractCalls",
                "callsRequireOwnerApproval",
                "ownerAnswerRequiredForCalls",
            ],
            "boolean",
        )?;
        strings(&x["assets"])?;
        for key in ["rails", "fixedTestRatesUSDC", "assetDecimals"] {
            if let Some(m) = obj(&x[key], key)? {
                for (k, val) in m {
                    if key == "rails" {
                        strings(val)?;
                    } else {
                        scalar(
                            val,
                            if key == "assetDecimals" {
                                "integer"
                            } else {
                                "string"
                            },
                            k,
                        )?;
                    }
                }
            }
        }
    }
    let c = &v["contract"];
    obj(c, "contract")?;
    fields(c, &["version"], "integer")?;
    fields(c, &["profile"], "string")?;
    obj(&c["binding"], "binding")?;
    fields(
        &c["binding"],
        &["sourceHash", "irHash", "registryVersion"],
        "string",
    )?;
    strings(&c["contextU64Keys"])?;
    if !v["workflow"].is_null() {
        for item in v["workflow"].as_array().ok_or("invalid workflow")? {
            obj(item, "workflow")?;
            fields(item, &["kind", "label", "description"], "string")?;
        }
    }
    Ok(())
}
fn strings(v: &Value) -> std::result::Result<(), String> {
    if v.is_null() {
        return Ok(());
    }
    if v.as_array()
        .is_some_and(|a| a.iter().all(|v| v.is_string() || v.is_null()))
    {
        Ok(())
    } else {
        Err("invalid string array".into())
    }
}
pub(crate) fn status_network(c: &mut Client, stderr: &mut String) -> Result<Network> {
    match Skill::read(c) {
        Ok(s) => Ok(s.net()),
        Err(e) => {
            if e.config || matches!(e.status, Some(401 | 403)) {
                return Err(e);
            }
            *stderr += &format!(
                "allowit: the policy description is unavailable ({e}); reading the status without the policy's network\n"
            );
            Ok(Network::Unknown)
        }
    }
}
