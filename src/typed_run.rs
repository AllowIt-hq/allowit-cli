//! Typed `exec --request-file` ingress with canonical SDK request types.
//!
//! The file is decoded directly into the canonical `ExecutionRequest` or `CurlRequest`.
//! Caller-supplied outcomes and validation results have no representation here. A typed
//! run is POSTed once; every unknown outcome is recovered by status with the same ID.
//!
//! Activation stays unavailable until AllowIt publishes the typed owner authorization
//! mode contract. `activate` is the single gate.
use crate::{
    args::Args,
    client::Client,
    config::Config,
    error::{Error, Result},
    flush_stderr,
    request::request_id_valid,
    skill::Skill,
    typed_request::{decode_bytes, operation_nonce, read_request_file},
};
use allowit_policy_sdk::typed_workflow::{CurlRequest, ExecutionRequest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use std::path::Path;

pub(crate) const OPERATION_DOMAIN: &str = "allowit-workflow-operation-v1";
const OPERATION_ENCODING: &str = "nul-separated-utf8-sha256";
const UNAVAILABLE: &str = "typed request execution is not available: AllowIt has not published the typed owner authorization mode for this CLI. Nothing was sent";
/// Set only with the genuine backend typed owner authorization mode contract and fixture.
const TYPED_ACTIVATION: bool = false;
/// Scalar request flags. A request file is the complete request, so none can combine with it.
const SCALAR_FLAGS: &[&str] = &[
    "rail", "op", "addr", "amount", "action", "merchant", "context", "memo", "data", "before",
    "after", "budget",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Kind {
    #[serde(rename = "execution-request")]
    Execution,
    #[serde(rename = "curl-request")]
    Curl,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(rename = "requestId")]
    request_id: String,
    input: RawInput,
}
/// Keep the request as original bytes so field order cannot force a buffered value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInput {
    kind: Kind,
    request: Box<RawValue>,
}
#[derive(Debug, PartialEq)]
pub(crate) enum TypedInput {
    Execution(ExecutionRequest),
    Curl(CurlRequest),
}
#[derive(Debug, PartialEq)]
pub(crate) struct TypedRequest {
    pub request_id: String,
    pub input: TypedInput,
}
#[derive(Serialize)]
struct Wire<'a> {
    #[serde(rename = "requestId")]
    request_id: &'a str,
    input: WireInput<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", content = "request")]
enum WireInput<'a> {
    #[serde(rename = "execution-request")]
    Execution(&'a ExecutionRequest),
    #[serde(rename = "curl-request")]
    Curl(&'a CurlRequest),
}
impl TypedRequest {
    pub fn kind(&self) -> Kind {
        match self.input {
            TypedInput::Execution(_) => Kind::Execution,
            TypedInput::Curl(_) => Kind::Curl,
        }
    }
    /// Canonical serialization of the validated values, not the caller's original bytes.
    fn wire(&self) -> Result<Vec<u8>> {
        let input = match &self.input {
            TypedInput::Execution(r) => WireInput::Execution(r),
            TypedInput::Curl(r) => WireInput::Curl(r),
        };
        serde_json::to_vec(&Wire {
            request_id: &self.request_id,
            input,
        })
        .map_err(|_| Error::usage("The typed request cannot be encoded."))
    }
}

pub(crate) fn read_typed_file(path: &Path) -> Result<TypedRequest> {
    resolve(read_request_file(path)?)
}
#[cfg(test)]
fn decode_typed(bytes: &[u8]) -> Result<TypedRequest> {
    resolve(decode_bytes(bytes)?)
}
fn resolve(raw: RawFile) -> Result<TypedRequest> {
    // Reject; never trim, change case or generate an ID.
    if !request_id_valid(&raw.request_id) {
        return Err(Error::usage(
            "The request file requestId must be 8 to 100 characters from A-Z a-z 0-9 . _ : -",
        ));
    }
    let bytes = raw.input.request.get().as_bytes();
    let input = match raw.input.kind {
        Kind::Execution => TypedInput::Execution(decode_bytes(bytes)?),
        Kind::Curl => {
            let request: CurlRequest = decode_bytes(bytes)?;
            check_curl(&request)?;
            TypedInput::Curl(request)
        }
    };
    Ok(TypedRequest {
        request_id: raw.request_id,
        input,
    })
}
/// The CLI never dereferences a path or a local resource named inside the request file.
fn check_curl(request: &CurlRequest) -> Result<()> {
    if request.body_file.is_some() {
        return Err(Error::usage(
            "curl-request body_file is not accepted: embed the body. The CLI does not read paths named in the request file.",
        ));
    }
    match url::Url::parse(&request.url) {
        Ok(u) if matches!(u.scheme(), "https" | "http") && u.has_host() => Ok(()),
        _ => Err(Error::usage(
            "curl-request url must be an absolute http or https URL.",
        )),
    }
}

/// Additive skill descriptor `typedIngress`, version 1. Its routes are the standard
/// top-level skill `urls`, never a nested copy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TypedIngress {
    version: u8,
    kinds: Vec<Kind>,
    operation_binding: OperationBinding,
    input_schema: Value,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OperationBinding {
    version: u8,
    /// Authoritative installed policy instance. Never derived from the policy ID.
    policy_instance: [u8; 32],
    nonce_domain: String,
    encoding: String,
}
/// Top-level skill `urls`; other standard route names stay with the skill check.
#[derive(Debug, Deserialize)]
struct Urls {
    runs: String,
    status: String,
}
pub(crate) fn parse_ingress(skill: &Skill, cfg: &Config) -> Result<TypedIngress> {
    let raw = skill
        .0
        .get("typedIngress")
        .filter(|v| !v.is_null())
        .ok_or_else(|| Error::unsupported(UNAVAILABLE))?;
    let bad = |what: &str| {
        Error::unsupported(format!(
            "AllowIt published a typed request description this CLI cannot read ({what})"
        ))
    };
    let ingress = TypedIngress::deserialize(raw).map_err(|_| bad("schema"))?;
    if ingress.version != 1 || ingress.operation_binding.version != 1 {
        return Err(bad("version"));
    }
    let kinds = &ingress.kinds;
    if kinds.is_empty()
        || kinds
            .iter()
            .enumerate()
            .any(|(i, k)| kinds[..i].contains(k))
    {
        return Err(bad("kinds"));
    }
    if ingress.operation_binding.nonce_domain != OPERATION_DOMAIN
        || ingress.operation_binding.encoding != OPERATION_ENCODING
    {
        return Err(bad("operation binding"));
    }
    if !ingress.input_schema.is_object() {
        return Err(bad("input schema"));
    }
    let urls = skill
        .0
        .get("urls")
        // Serde also reads a struct from a sequence; only the named object form is accepted.
        .filter(|v| v.is_object())
        .and_then(|v| Urls::deserialize(v).ok())
        .ok_or_else(|| bad("urls"))?;
    if !cfg.is_route("runs", &urls.runs) || !cfg.is_route("status", &urls.status) {
        return Err(Error::config(
            "AllowIt reported typed request endpoints outside this policy's harness routes; check ALLOWIT_URL",
        ));
    }
    Ok(ingress)
}

/// Proof that typed execution was activated for the installed policy.
pub(crate) struct Activated {
    ingress: TypedIngress,
}
/// The only constructor outside tests. The normal `Skill::check` has already run.
pub(crate) fn activate(skill: &Skill, cfg: &Config) -> Result<Activated> {
    let ingress = parse_ingress(skill, cfg)?;
    if !TYPED_ACTIVATION {
        return Err(Error::unsupported(UNAVAILABLE));
    }
    Ok(Activated { ingress })
}
impl Activated {
    #[cfg(test)]
    pub fn synthetic_for_tests(ingress: TypedIngress) -> Self {
        Self { ingress }
    }
    /// Bind the request to the installed identity. `policy_id` is the unchanged policy ID.
    fn bind(&self, request: &TypedRequest, policy_id: &str) -> Result<()> {
        if !self.ingress.kinds.contains(&request.kind()) {
            return Err(Error::usage(
                "AllowIt does not accept this typed request kind for this policy",
            ));
        }
        // CurlRequest has no OperationRef; AllowIt binds its wrapper digest to the installation.
        if let TypedInput::Execution(r) = &request.input {
            if r.operation.policy_instance != self.ingress.operation_binding.policy_instance {
                return Err(Error::usage(
                    "operation.policy_instance does not match the installed policy instance",
                ));
            }
            if r.operation.nonce != operation_nonce(policy_id, &request.request_id) {
                return Err(Error::usage(
                    "operation.nonce is not the version 1 nonce for this policy ID and requestId",
                ));
            }
        }
        Ok(())
    }
}

/// `allowit exec POLICY --request-file PATH [--request-id ID] [--json] [--wait D]`.
pub(crate) fn exec(command: &str, parsed: &Args, stderr: &mut String) -> Result<i32> {
    let request = prepare(command, parsed)?;
    // No configuration, skill read or other network request while typed execution is off.
    if !TYPED_ACTIVATION {
        return Err(Error::unsupported(UNAVAILABLE));
    }
    let policy = &parsed.pos[0];
    let mut c = Client::new(Config::load(policy)?)?;
    let skill = Skill::read(&mut c)?;
    let activated = activate(&skill, &c.cfg)?;
    submit(&mut c, &activated, &request, policy, stderr)
}
/// All local checks; nothing leaves the process.
fn prepare(command: &str, parsed: &Args) -> Result<TypedRequest> {
    if command != "exec" {
        return Err(Error::usage("--request-file is accepted only by exec"));
    }
    if let Some(name) = parsed
        .flags
        .0
        .keys()
        .find(|k| SCALAR_FLAGS.contains(&k.as_str()))
    {
        return Err(Error::usage(format!(
            "--{name} cannot be combined with --request-file"
        )));
    }
    let path = parsed.flags.get("request-file");
    if path.is_empty() {
        return Err(Error::usage("--request-file needs a local file path"));
    }
    let request = read_typed_file(Path::new(path))?;
    let flag = parsed.flags.get("request-id");
    if !flag.is_empty() && flag != request.request_id {
        return Err(Error::usage(
            "--request-id does not exactly match the requestId in the request file",
        ));
    }
    Ok(request)
}
fn submit(
    c: &mut Client,
    activated: &Activated,
    request: &TypedRequest,
    policy: &str,
    stderr: &mut String,
) -> Result<i32> {
    activated.bind(request, &c.cfg.policy)?;
    let body = request.wire()?;
    let id = &request.request_id;
    let check = format!("allowit status --wait 0s -- {policy} {id}");
    *stderr += &format!(
        "allowit: exec typed request {id}\nallowit: if the result is unknown, do not resend; check it only with: {check}\n"
    );
    // Recovery instructions leave the process before the POST.
    flush_stderr(stderr);
    let reply = c
        .post_once("runs", &body)
        .map_err(|e| recovery(e, id, &check))?;
    decode_reply(&reply, id, &check)
}
fn recovery(e: Error, id: &str, check: &str) -> Error {
    if e.code != 5 {
        return e;
    }
    Error::uncertain(format!(
        "{e}\nTyped request {id} may have reached AllowIt. Do not resend it and do not use a new requestId. Check it with: {check}"
    ))
}
/// The typed `{request: PolicyRequest}` reply contract is pending its backend fixture. Until
/// then no reply is classified: settlement and delivery are never inferred from it.
fn decode_reply(_reply: &Value, id: &str, check: &str) -> Result<i32> {
    Err(Error::uncertain(format!(
        "AllowIt answered typed request {id}, but this CLI cannot read typed results yet. Do not resend it. Check it with: {check}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::tests::{Reply, serve};
    use serde_json::json;

    const ENVELOPE: &str = include_str!("../tests/fixtures/typed/execution-envelope-v1.json");
    const VECTOR: &str = include_str!("../tests/fixtures/typed/operation-vector-v1.json");
    const POLICY: &str = "owner-policy_Example-A";
    const ID: &str = "cli-native-transfer-01";

    fn envelope() -> Value {
        serde_json::from_str(ENVELOPE).unwrap()
    }
    fn decode(v: &Value) -> Result<TypedRequest> {
        decode_typed(v.to_string().as_bytes())
    }
    fn execution(r: &TypedRequest) -> &ExecutionRequest {
        match &r.input {
            TypedInput::Execution(e) => e,
            TypedInput::Curl(_) => panic!("expected execution"),
        }
    }
    fn curl(request: Value) -> Value {
        json!({"requestId": ID, "input": {"kind": "curl-request", "request": request}})
    }
    fn instance() -> Vec<u8> {
        (0..32).collect()
    }
    fn ingress_json() -> Value {
        json!({
            "version": 1,
            "kinds": ["execution-request", "curl-request"],
            "operationBinding": {
                "version": 1,
                "policyInstance": instance(),
                "nonceDomain": OPERATION_DOMAIN,
                "encoding": OPERATION_ENCODING
            },
            "inputSchema": {"synthetic": "transport fixture only"}
        })
    }
    fn cfg(policy: &str) -> Config {
        Config {
            origin: "https://allowit.example".into(),
            owner: "owner-1".into(),
            policy: policy.into(),
            token: format!("owner-1.{policy}.secret"),
            ca_file: String::new(),
        }
    }
    /// SYNTHETIC transport skill fixture, not a backend mode contract.
    fn synthetic_skill(c: &Config) -> Skill {
        let route = |action| format!("/api/harness/{}/{}/{action}", c.owner, c.policy);
        Skill(json!({
            "owner": c.owner, "policyId": c.policy, "network": "local:dev",
            "urls": {"runs": route("runs"), "status": route("status")},
            "typedIngress": ingress_json()
        }))
    }
    fn synthetic_activated(c: &Config) -> Activated {
        Activated::synthetic_for_tests(parse_ingress(&synthetic_skill(c), c).unwrap())
    }
    fn args(argv: &[&str]) -> Result<Args> {
        crate::args::parse(
            "exec",
            &argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }
    fn temp(name: &str, body: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("allowit-typed-{name}-{}.json", std::process::id()));
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn canonical_execution_envelope_decodes_and_binds() {
        let request = decode_typed(ENVELOPE.as_bytes()).unwrap();
        assert_eq!(request.request_id, ID);
        let vector: Value = serde_json::from_str(VECTOR).unwrap();
        let nonce: Vec<u8> = serde_json::from_value(vector["nonce"].clone()).unwrap();
        assert_eq!(execution(&request).operation.nonce.to_vec(), nonce);
        assert_eq!(operation_nonce(POLICY, ID).to_vec(), nonce);
        let c = cfg(POLICY);
        synthetic_activated(&c).bind(&request, POLICY).unwrap();
    }
    #[test]
    fn amount256_bytes_survive_canonical_wire_encoding() {
        let request = decode_typed(ENVELOPE.as_bytes()).unwrap();
        let bound = &execution(&request).effect_bounds[0];
        let mut expected = [0u8; 32];
        expected[30..].copy_from_slice(&1000u16.to_be_bytes());
        assert_eq!(bound.max_debit.0, expected);
        let wire: Value = serde_json::from_slice(&request.wire().unwrap()).unwrap();
        // Typed values re-encode to exactly the canonical envelope.
        assert_eq!(wire, envelope());
        assert_eq!(decode_typed(&request.wire().unwrap()).unwrap(), request);
    }
    #[test]
    fn rejects_duplicate_fields_at_every_level() {
        let compact = envelope().to_string();
        for (from, to) in [
            (
                r#""requestId":"cli-native-transfer-01""#,
                r#""requestId":"cli-native-transfer-01","requestId":"cli-native-transfer-02""#,
            ),
            (
                r#""kind":"execution-request""#,
                r#""kind":"execution-request","kind":"curl-request""#,
            ),
            (r#""lamports":1000"#, r#""lamports":1000,"lamports":1"#),
            (r#""evidence":[]"#, r#""evidence":[],"evidence":[]"#),
        ] {
            let raw = compact.replacen(from, to, 1);
            assert_ne!(raw, compact);
            assert!(decode_typed(raw.as_bytes()).is_err(), "{to}");
        }
    }
    #[test]
    fn request_before_kind_still_decodes_without_value_collapse() {
        let e = envelope();
        let raw = format!(
            r#"{{"input":{{"request":{},"kind":"execution-request"}},"requestId":"{ID}"}}"#,
            e["input"]["request"]
        );
        assert_eq!(decode_typed(raw.as_bytes()).unwrap().request_id, ID);
    }
    #[test]
    fn rejects_unknown_fields_and_caller_outcomes() {
        let mut e = envelope();
        e["outcome"] = json!("private-sentinel");
        let error = decode(&e).unwrap_err();
        assert!(!error.message.contains("private-sentinel"));
        let mut e = envelope();
        e["input"]["validated"] = json!(true);
        assert!(decode(&e).is_err());
        let mut e = envelope();
        e["input"]["request"]["request_digest"] = json!(vec![0; 32]);
        assert!(decode(&e).is_err());
        for kind in [
            "curl-outcome",
            "validated-execution-request",
            "Execution",
            "",
        ] {
            let mut e = envelope();
            e["input"]["kind"] = json!(kind);
            assert!(decode(&e).is_err(), "{kind}");
        }
        // A caller-manufactured CurlOutcome is not a CurlRequest.
        let outcome =
            json!({"Complete": {"status": 200, "body": [], "receipt_digest": vec![0; 32]}});
        assert!(decode(&curl(outcome)).is_err());
        // Missing explicit requestId is never generated.
        let mut e = envelope();
        e.as_object_mut().unwrap().remove("requestId");
        assert!(decode(&e).is_err());
    }
    #[test]
    fn request_id_is_rejected_not_normalized() {
        for id in [
            "short",
            " cli-native-transfer-01",
            "cli native transfer",
            "",
        ] {
            let mut e = envelope();
            e["requestId"] = json!(id);
            assert!(decode(&e).is_err(), "{id:?}");
        }
        let mut e = envelope();
        e["requestId"] = json!(7);
        assert!(decode(&e).is_err());
    }
    #[test]
    fn curl_request_never_names_a_file_or_local_resource() {
        let secret = temp("curl-body", "private-file-sentinel");
        let path = secret.to_string_lossy().to_string();
        let error = decode(&curl(json!({
            "url": "https://api.example/pay", "method": null, "headers": null,
            "body": null, "body_file": path
        })))
        .unwrap_err();
        assert!(!error.message.contains("private-file-sentinel"));
        assert!(!error.message.contains(&path));
        std::fs::remove_file(secret).unwrap();
        for url in [
            "file:///etc/passwd",
            "/etc/passwd",
            "data:,x",
            "ftp://api.example/x",
        ] {
            let request = json!({"url": url, "method": null, "headers": null, "body": null, "body_file": null});
            assert!(decode(&curl(request)).is_err(), "{url}");
        }
        let ok = decode(&curl(json!({
            "url": "https://api.example/pay", "method": "POST",
            "headers": [{"name": "accept", "value": "application/json"}],
            "body": {"JsonBytes": [123, 125]}, "body_file": null
        })))
        .unwrap();
        assert_eq!(ok.kind(), Kind::Curl);
    }
    #[test]
    fn file_bounds_apply_before_typed_decode() {
        let mut e = envelope();
        e["input"]["request"]["evidence"] = json!(vec![0; 4096]);
        assert!(decode(&e).unwrap_err().message.contains("entries"));
        let nested = format!(
            r#"{{"requestId":"{ID}","input":{{"kind":"curl-request","request":{}{}}}}}"#,
            "[".repeat(48),
            "]".repeat(48)
        );
        assert!(
            decode_typed(nested.as_bytes())
                .unwrap_err()
                .message
                .contains("nesting")
        );
        let big = curl(
            json!({"url": format!("https://a.example/{}", "x".repeat(65_536)),
            "method": null, "headers": null, "body": null, "body_file": null}),
        );
        assert!(decode(&big).unwrap_err().message.contains("65536"));
    }
    #[test]
    fn binding_requires_installed_instance_and_exact_nonce() {
        let c = cfg(POLICY);
        let activated = synthetic_activated(&c);
        let mut wrong_instance = decode_typed(ENVELOPE.as_bytes()).unwrap();
        if let TypedInput::Execution(r) = &mut wrong_instance.input {
            r.operation.policy_instance[0] ^= 1;
        }
        assert!(
            activated
                .bind(&wrong_instance, POLICY)
                .unwrap_err()
                .message
                .contains("policy_instance")
        );
        let request = decode_typed(ENVELOPE.as_bytes()).unwrap();
        for policy in ["owner-policy_example-a", "owner-policy_Example-A "] {
            assert!(
                activated
                    .bind(&request, policy)
                    .unwrap_err()
                    .message
                    .contains("nonce")
            );
        }
        let mut other_id = envelope();
        other_id["requestId"] = json!("cli-native-transfer-02");
        assert!(activated.bind(&decode(&other_id).unwrap(), POLICY).is_err());
    }
    #[test]
    fn ingress_descriptor_is_strict() {
        let c = cfg(POLICY);
        let good = synthetic_skill(&c).0;
        let parse = |v: &Value| parse_ingress(&Skill(v.clone()), &c).map(|_| ());
        parse(&good).unwrap();
        let mut cases = Vec::new();
        for (pointer, value, why) in [
            ("/version", json!(2), "version"),
            ("/version", json!(0), "version"),
            ("/version", json!("1"), "schema"),
            ("/version", json!(null), "schema"),
            ("/kinds", json!([]), "kinds"),
            (
                "/kinds",
                json!(["execution-request", "execution-request"]),
                "kinds",
            ),
            ("/kinds", json!(["curl-outcome"]), "schema"),
            ("/kinds", json!(["Execution"]), "schema"),
            (
                "/kinds",
                json!(["execution-request", "unknown-request"]),
                "schema",
            ),
            ("/kinds", json!("execution-request"), "schema"),
            ("/kinds", json!(null), "schema"),
            ("/operationBinding/version", json!(2), "version"),
            ("/operationBinding/version", json!(null), "schema"),
            (
                "/operationBinding/nonceDomain",
                json!("allowit-workflow-operation-v2"),
                "operation binding",
            ),
            (
                "/operationBinding/nonceDomain",
                json!("Allowit-workflow-operation-v1"),
                "operation binding",
            ),
            (
                "/operationBinding/nonceDomain",
                json!("allowit-workflow-operation-v1 "),
                "operation binding",
            ),
            (
                "/operationBinding/nonceDomain",
                json!(""),
                "operation binding",
            ),
            (
                "/operationBinding/encoding",
                json!("hex"),
                "operation binding",
            ),
            (
                "/operationBinding/policyInstance",
                json!(vec![0; 31]),
                "schema",
            ),
            (
                "/operationBinding/policyInstance",
                json!(vec![0; 33]),
                "schema",
            ),
            (
                "/operationBinding/policyInstance",
                json!("00".repeat(32)),
                "schema",
            ),
            ("/operationBinding/policyInstance", json!(null), "schema"),
            (
                "/operationBinding/policyInstance",
                json!([vec![0; 32]]),
                "schema",
            ),
            ("/inputSchema", json!("any"), "input schema"),
        ] {
            let mut v = good.clone();
            *v["typedIngress"].pointer_mut(pointer).unwrap() = value;
            cases.push((v, why));
        }
        for byte in [json!(256), json!(-1)] {
            let mut v = good.clone();
            v["typedIngress"]["operationBinding"]["policyInstance"][5] = byte;
            cases.push((v, "schema"));
        }
        for (parent, key) in [
            ("", "version"),
            ("", "kinds"),
            ("", "operationBinding"),
            ("", "inputSchema"),
            ("/operationBinding", "version"),
            ("/operationBinding", "policyInstance"),
            ("/operationBinding", "nonceDomain"),
            ("/operationBinding", "encoding"),
        ] {
            let mut v = good.clone();
            let p = format!("/typedIngress{parent}");
            v.pointer_mut(&p)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key)
                .unwrap();
            cases.push((v, "schema"));
        }
        // Behavior the backend has not published is never invented or tolerated.
        for (key, value) in [
            ("ownerAuthorization", json!("invented")),
            ("executionMode", json!("owner_signed")),
            ("capabilities", json!({})),
            ("resultPhases", json!([])),
        ] {
            let mut v = good.clone();
            v["typedIngress"][key] = value;
            cases.push((v, "schema"));
        }
        for (v, why) in cases {
            let e = parse(&v).unwrap_err();
            assert_eq!(e.code, 3, "{v}");
            assert!(e.message.ends_with(&format!("({why})")), "{why}: {v}");
        }
        let mut absent = good.clone();
        absent.as_object_mut().unwrap().remove("typedIngress");
        for v in [absent, json!({"typedIngress": null, "urls": good["urls"]})] {
            assert!(parse(&v).unwrap_err().message.contains("not available"));
        }
    }
    #[test]
    fn ingress_routes_are_the_top_level_skill_urls() {
        let c = cfg(POLICY);
        let good = synthetic_skill(&c).0;
        let parse = |v: &Value| parse_ingress(&Skill(v.clone()), &c).map(|_| ());
        let routes = json!({"runs": c.route("runs"), "status": c.route("status")});
        // Absolute and relative forms both resolve through the exact standard check.
        let mut absolute = good.clone();
        absolute["urls"] = routes.clone();
        parse(&absolute).unwrap();
        let mut extra = good.clone();
        extra["urls"]["skill"] = json!(c.route("skill"));
        parse(&extra).unwrap();
        // Nested routes are not part of typedIngress, with or without top-level urls.
        let mut nested_only = good.clone();
        nested_only.as_object_mut().unwrap().remove("urls");
        nested_only["typedIngress"]["urls"] = routes.clone();
        let mut nested_too = good.clone();
        nested_too["typedIngress"]["urls"] = routes.clone();
        for v in [nested_only, nested_too] {
            assert!(parse(&v).unwrap_err().message.ends_with("(schema)"), "{v}");
        }
        // Missing or malformed top-level routes: unreadable, nothing is guessed.
        let mut unreadable = Vec::new();
        for urls in [
            json!(null),
            json!({}),
            json!({"runs": c.route("runs")}),
            json!({"status": c.route("status")}),
            json!({"runs": null, "status": c.route("status")}),
            json!({"runs": 1, "status": c.route("status")}),
            json!([c.route("runs"), c.route("status")]),
            json!(c.route("runs")),
        ] {
            let mut v = good.clone();
            v["urls"] = urls;
            unreadable.push(v);
        }
        let mut no_urls = good.clone();
        no_urls.as_object_mut().unwrap().remove("urls");
        unreadable.push(no_urls);
        for v in unreadable {
            let e = parse(&v).unwrap_err();
            assert_eq!(e.code, 3, "{v}");
            assert!(e.message.ends_with("(urls)"), "{v}");
        }
        // Foreign, redirected or swapped routes fail closed as configuration errors.
        let other = format!("/api/harness/{}/other-policy/runs", c.owner);
        let foreign_runs = [
            "https://elsewhere.example/api/harness/owner-1/owner-policy_Example-A/runs",
            "//elsewhere.example/api/harness/owner-1/owner-policy_Example-A/runs",
            "http://allowit.example/api/harness/owner-1/owner-policy_Example-A/runs",
            "https://user@allowit.example/api/harness/owner-1/owner-policy_Example-A/runs",
            "https://allowit.example:8443/api/harness/owner-1/owner-policy_Example-A/runs",
            "/api/harness/owner-1/owner-policy_Example-A/runs?next=https://elsewhere.example",
            "/api/harness/owner-1/owner-policy_Example-A/runs#x",
            "/api/harness/owner-1/owner-policy_Example-A/runs/",
            "/api/harness/owner-1/owner-policy_Example-A/status",
            "/api/harness/owner-1/owner-policy_Example-A/skill",
            "/api/harness/owner-1/owner-policy_example-a/runs",
            "\\elsewhere.example/runs",
            "runs/../../other-policy/runs",
            &other,
            "",
        ];
        let mut misrouted = Vec::new();
        for raw in foreign_runs {
            let mut v = good.clone();
            v["urls"]["runs"] = json!(raw);
            misrouted.push(v);
        }
        for raw in [c.route("runs"), c.route("skill"), String::new()] {
            let mut v = good.clone();
            v["urls"]["status"] = json!(raw);
            misrouted.push(v);
        }
        let other = cfg("other-policy");
        let mut v = good.clone();
        v["urls"] = json!({"runs": other.route("runs"), "status": other.route("status")});
        misrouted.push(v);
        for v in misrouted {
            let e = parse(&v).unwrap_err();
            assert!(e.config, "{v}");
            assert!(
                e.message.contains("outside this policy's harness routes"),
                "{v}"
            );
        }
    }
    #[test]
    fn activation_is_unavailable_even_with_a_complete_descriptor() {
        let c = cfg(POLICY);
        let e = activate(&synthetic_skill(&c), &c).err().unwrap();
        assert_eq!(e.code, 3);
        assert!(e.message.contains("not available"));
        let e = activate(&Skill(json!({})), &c).err().unwrap();
        assert!(e.message.contains("not available"));
    }
    #[test]
    fn flags_conflict_with_request_file_and_eval_is_rejected() {
        let path = temp("flags", ENVELOPE);
        let p = path.to_string_lossy().to_string();
        for flag in SCALAR_FLAGS {
            let parsed = args(&[POLICY, "--request-file", &p, &format!("--{flag}"), "x"]).unwrap();
            assert!(
                prepare("exec", &parsed)
                    .unwrap_err()
                    .message
                    .contains("cannot be combined"),
                "{flag}"
            );
        }
        let parsed = args(&[POLICY, "--request-file", &p]).unwrap();
        assert!(
            prepare("eval", &parsed)
                .unwrap_err()
                .message
                .contains("only by exec")
        );
        assert_eq!(prepare("exec", &parsed).unwrap().request_id, ID);
        let parsed = args(&[POLICY, "--request-file", &p, "--request-id", ID, "--json"]).unwrap();
        assert!(prepare("exec", &parsed).is_ok());
        for id in ["CLI-NATIVE-TRANSFER-01", "cli-native-transfer-02"] {
            let parsed = args(&[POLICY, "--request-file", &p, "--request-id", id]).unwrap();
            assert!(
                prepare("exec", &parsed)
                    .unwrap_err()
                    .message
                    .contains("exactly match")
            );
        }
        std::fs::remove_file(path).unwrap();
        let parsed = args(&[POLICY, "--request-file", "-"]).unwrap();
        assert!(prepare("exec", &parsed).is_err());
    }
    #[test]
    fn shipped_command_refuses_before_configuration_or_network() {
        let path = temp("shipped", ENVELOPE);
        let parsed = args(&[POLICY, "--request-file", path.to_str().unwrap()]).unwrap();
        let mut err = String::new();
        // No ALLOWIT_URL or token is needed: refusal precedes Config::load and Client::new.
        let e = exec("exec", &parsed, &mut err).err().unwrap();
        assert_eq!(e.code, 3);
        assert!(e.message.contains("Nothing was sent"));
        assert!(err.is_empty());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn shipped_path_reads_skill_and_never_posts() {
        let body = synthetic_skill(&cfg("policy-1")).0.to_string();
        let body: &'static str = Box::leak(body.into_boxed_str());
        let (mut client, server) = serve(vec![Reply::Status(200, body), Reply::Status(200, "{}")]);
        // The normal skill check runs; then activation refuses before any POST.
        let skill = Skill::read(&mut client).unwrap();
        let e = activate(&skill, &client.cfg).err().unwrap();
        assert!(e.message.contains("Nothing was sent"));
        let seen = server.finish();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0]
                .head
                .starts_with("GET /api/harness/owner-1/policy-1/skill ")
        );
    }
    #[test]
    fn synthetic_transport_posts_canonical_body_once() {
        let (mut client, server) = serve(vec![
            Reply::Status(200, r#"{"request":{"synthetic":true}}"#),
            Reply::Status(200, "{}"),
        ]);
        client.cfg.policy = POLICY.into();
        let activated = synthetic_activated(&client.cfg);
        let request = decode_typed(ENVELOPE.as_bytes()).unwrap();
        let mut err = String::new();
        let e = submit(&mut client, &activated, &request, POLICY, &mut err).unwrap_err();
        // No reply is classified until the typed reply contract exists.
        assert_eq!(e.code, 5);
        assert!(
            e.message
                .contains(&format!("allowit status --wait 0s -- {POLICY} {ID}"))
        );
        assert!(err.is_empty());
        let seen = server.finish();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].head.starts_with(&format!(
            "POST /api/harness/owner-1/{POLICY}/runs HTTP/1.1\r\n"
        )));
        assert_eq!(seen[0].body, request.wire().unwrap());
    }
    #[test]
    fn synthetic_transport_unknown_outcomes_are_never_resent() {
        for reply in [
            Reply::Close,
            Reply::Status(503, "{}"),
            Reply::Status(409, "{}"),
        ] {
            let (mut client, server) = serve(vec![reply, Reply::Status(200, "{}")]);
            client.cfg.policy = POLICY.into();
            let activated = synthetic_activated(&client.cfg);
            let request = decode_typed(ENVELOPE.as_bytes()).unwrap();
            let mut err = String::new();
            let e = submit(&mut client, &activated, &request, POLICY, &mut err).unwrap_err();
            assert_eq!(e.code, 5);
            assert!(e.message.contains("do not use a new requestId"));
            assert!(e.message.contains(&format!("-- {POLICY} {ID}")));
            assert!(!e.message.contains(&client.cfg.token));
            assert_eq!(server.finish().len(), 1);
        }
    }
    #[test]
    fn binding_failure_sends_nothing() {
        let (mut client, server) = serve(vec![Reply::Status(200, "{}")]);
        // The token's policy differs, so the nonce cannot match.
        let activated = synthetic_activated(&client.cfg);
        let request = decode_typed(ENVELOPE.as_bytes()).unwrap();
        let mut err = String::new();
        let e = submit(&mut client, &activated, &request, POLICY, &mut err).unwrap_err();
        assert_eq!(e.code, 2);
        assert!(server.finish().is_empty());
    }
}
