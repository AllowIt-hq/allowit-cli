//! Local MCP transport for the same AllowIt backend command boundary.
use crate::{
    error::{Error, Result},
    gateway::{self, Gateway},
    gateway_args::{self, Invocation},
};
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};

pub(crate) fn run(inv: &Invocation, _stdout: &mut String, stderr: &mut String) -> Result<i32> {
    if !inv.args.is_empty() {
        return Err(Error::usage(
            "usage: allowit mcp [--policy version@addr] [--sandbox]",
        ));
    }
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = std::io::Read::by_ref(&mut reader)
            .take(65_537)
            .read_until(b'\n', &mut line)
            .map_err(|_| Error::config("cannot read MCP input"))?;
        if n == 0 {
            break;
        }
        if line.len() > 65_536 {
            return Err(Error::usage("MCP message exceeds 65536 bytes"));
        }
        let message: Value = serde_json::from_slice(&line)
            .map_err(|_| Error::usage("MCP input must be a JSON object"))?;
        if message.get("id").is_none() {
            continue;
        }
        let id = message["id"].clone();
        let result = dispatch(&message, inv, stderr);
        let response = match result {
            Ok(v) => json!({"jsonrpc":"2.0","id":id,"result":v}),
            Err(e) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":crate::output::one_line(&e.message)}})
            }
        };
        writeln!(writer, "{}", crate::redact(response.to_string()))
            .map_err(|_| Error::config("cannot write MCP response"))?;
        writer
            .flush()
            .map_err(|_| Error::config("cannot flush MCP response"))?;
    }
    Ok(0)
}

fn dispatch(message: &Value, inv: &Invocation, stderr: &mut String) -> Result<Value> {
    match message["method"].as_str().unwrap_or("") {
        "initialize" => Ok(
            json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"allowit","version":crate::VERSION}}),
        ),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools":[
            {"name":"allowit_call","description":"Call a service through the selected AllowIt account or explicit bound policy. The backend owns payment and connections.","inputSchema":{"type":"object","properties":{"target":{"type":"string"},"input":{},"operationId":{"type":"string"}},"required":["target","operationId"],"additionalProperties":false}},
            {"name":"allowit_services","description":"List services from the authenticated AllowIt backend catalog.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
            {"name":"allowit_status","description":"Read an existing operation without creating another purchase.","inputSchema":{"type":"object","properties":{"operationId":{"type":"string"}},"required":["operationId"],"additionalProperties":false}}
        ]})),
        "tools/call" => {
            let name = message["params"]["name"].as_str().unwrap_or("");
            let a = &message["params"]["arguments"];
            let mut common = inv.common.clone();
            common.json = true;
            let mut out = String::new();
            let result = match name {
                "allowit_services" => Gateway::new(&common)?.send(
                    "GET",
                    &format!(
                        "/api/gateway/services?{}",
                        gateway_args::query_context(&common)
                    ),
                    None,
                )?,
                "allowit_status" => {
                    let id = a["operationId"]
                        .as_str()
                        .filter(|s| crate::request::request_id_valid(s))
                        .ok_or_else(|| Error::usage("operationId is required"))?;
                    let mut q = gateway_args::context(&common);
                    q["operationId"] = json!(id);
                    let value = Gateway::new(&common)?.send(
                        "POST",
                        "/api/gateway/operations/status",
                        Some(&q),
                    )?;
                    if value["operationId"].as_str() != Some(id) {
                        return Err(Error::uncertain(
                            "status response does not match the requested operation",
                        ));
                    }
                    value
                }
                "allowit_call" => {
                    let target = a["target"]
                        .as_str()
                        .ok_or_else(|| Error::usage("target is required"))?;
                    let id = a["operationId"]
                        .as_str()
                        .filter(|s| crate::request::request_id_valid(s))
                        .ok_or_else(|| Error::usage("operationId is required"))?;
                    common.operation_id = Some(id.into());
                    let mut argv = vec![target.into()];
                    if let Some(v) = a.get("input") {
                        argv.push(v.to_string());
                    }
                    let call = Invocation {
                        group: "call".into(),
                        args: argv,
                        common: common.clone(),
                        help: false,
                    };
                    let (service, request, input) = gateway_args::call_target(&call)?;
                    let mut q = gateway_args::context(&common);
                    if let Some(v) = service {
                        q["serviceId"] = json!(v);
                    }
                    if let Some(v) = request {
                        q["request"] = json!(v);
                    }
                    if let Some(v) = input {
                        q["input"] = v;
                    }
                    let exit = gateway::purchase(q, &common, &mut out, stderr)?;
                    let v = serde_json::from_str::<Value>(&out).map_err(|_| {
                        Error::uncertain("AllowIt operation response was not available")
                    })?;
                    if exit != 0 {
                        return Ok(
                            json!({"isError":true,"content":[{"type":"text","text":v.to_string()}]}),
                        );
                    }
                    v
                }
                _ => return Err(Error::usage("unknown AllowIt MCP tool")),
            };
            Ok(json!({"content":[{"type":"text","text":result.to_string()}]}))
        }
        _ => Err(Error::usage("unknown MCP method")),
    }
}
