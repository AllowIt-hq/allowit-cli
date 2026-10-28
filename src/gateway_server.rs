//! Local seller facade. Installed backend resources own verification, signing and settlement.
use crate::{
    error::{Error, Result},
    gateway::Gateway,
    gateway_args::Invocation,
    output,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

pub(crate) fn run(inv: &Invocation, stdout: &mut String, stderr: &mut String) -> Result<i32> {
    if inv.common.policy_selector.is_some() {
        return Err(Error::usage(
            "seller serving does not use a buyer --policy capability",
        ));
    }
    let mut action = inv.args.first().map(String::as_str).unwrap_or("list");
    if action == "start" {
        action = "api";
    }
    let mut listen = "127.0.0.1:4020".to_owned();
    let mut resource = None;
    let mut config_path = None;
    let mut once = false;
    let mut output_path = None;
    let mut force = false;
    let mut write = false;
    let mut i = 1;
    while i < inv.args.len() {
        let a = &inv.args[i];
        match a.as_str() {
            "--once" => once = true,
            "--force" => force = true,
            "--write" => write = true,
            "publish" if action == "plans" => {}
            "--listen" | "--resource" | "--config" | "--output" => {
                i += 1;
                let v = inv
                    .args
                    .get(i)
                    .ok_or_else(|| Error::usage(format!("{a} requires a value")))?
                    .clone();
                match a.as_str() {
                    "--listen" => listen = v,
                    "--resource" => resource = Some(v),
                    "--config" => config_path = Some(v),
                    _ => output_path = Some(v),
                }
            }
            s if !s.starts_with('-') && action == "scaffold" && output_path.is_none() => {
                output_path = Some(s.into())
            }
            _ => {
                return Err(Error::usage(
                    "use --resource PATH, --listen HOST:PORT, --config FILE, or scaffold OUTPUT",
                ));
            }
        }
        i += 1;
    }
    if action == "scaffold" {
        let path = output_path.unwrap_or_else(|| "allowit-server.json".into());
        let value = json!({"version":1,"listen":listen,"resource":resource.unwrap_or_default()});
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut f = options.open(&path).map_err(|_| {
            Error::config("cannot create scaffold; use --force to replace an existing file")
        })?;
        f.write_all((output::json(&value)).as_bytes())
            .map_err(|_| Error::config("cannot write seller scaffold"))?;
        *stdout += &format!("{path}\n");
        return Ok(0);
    }
    if let Some(path) = config_path {
        let bytes = std::fs::read(path).map_err(|_| Error::usage("cannot read seller config"))?;
        if bytes.len() > 65536 {
            return Err(Error::usage("seller config exceeds 65536 bytes"));
        }
        let cfg: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::usage("seller config must be JSON"))?;
        if resource.is_none() {
            resource = cfg["resource"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
        }
        if listen == "127.0.0.1:4020"
            && let Some(l) = cfg["listen"].as_str()
        {
            listen = l.into();
        }
    }
    let backend = Gateway::public()?;
    let config = backend.send("GET", "/api/gateway/config", None)?;
    let resources = config["sellerResources"].as_array().ok_or_else(|| {
        Error::unsupported("the backend does not advertise registered seller resources")
    })?;
    if action == "list" {
        *stdout += &output::json(&json!({"sellerResources":resources}));
        return Ok(0);
    }
    if action == "plans" {
        let plans = resources
            .iter()
            .filter_map(|r| {
                r.get("plans")
                    .map(|p| json!({"id":r["id"],"path":r["path"],"plans":p}))
            })
            .collect::<Vec<_>>();
        if plans.is_empty() {
            return Err(Error::unsupported(
                "the backend has no installed subscription plan metadata",
            ));
        }
        let value = json!({"plans":plans,"publishedBy":"registered backend resource"});
        if write {
            let path = output_path.ok_or_else(|| {
                Error::usage("--write requires --output FILE for verified backend plan metadata")
            })?;
            std::fs::write(path, output::json(&value))
                .map_err(|_| Error::config("cannot write plan metadata"))?;
        } else {
            *stdout += &output::json(&value);
        }
        return Ok(0);
    }
    if !["demo", "api", "inference"].contains(&action) {
        return Err(Error::usage(
            "server actions: list, demo, scaffold, plans; gate actions: api, inference",
        ));
    }
    let selected=if let Some(path)=resource{resources.iter().find(|r|r["path"].as_str()==Some(&path)).cloned()}else if resources.len()==1{Some(resources[0].clone())}else{None}.ok_or_else(||Error::unsupported("select --resource from the backend's installed sellerResources; no seller process was started"))?;
    let path = selected["path"]
        .as_str()
        .filter(|p| p.starts_with("/api/providers/") && !p.contains(['?', '#', '\\']))
        .ok_or_else(|| Error::unsupported("backend seller resource path is invalid"))?
        .to_owned();
    let methods = selected["methods"]
        .as_array()
        .ok_or_else(|| Error::unsupported("backend seller resource lacks admitted HTTP methods"))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let listener = TcpListener::bind(&listen)
        .map_err(|_| Error::config("cannot bind the selected local seller address"))?;
    *stderr += &format!(
        "allowit: {action} serving {} via registered backend resource {path}\n",
        listener
            .local_addr()
            .map_err(|_| Error::config("cannot inspect seller listener"))?
    );
    crate::flush_stderr(stderr);
    let backend = Arc::new(backend);
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|_| Error::config("cannot accept seller request"))?;
        let result = relay(&mut stream, &backend, &path, &methods);
        if result.is_err() {
            let body = b"Registered backend resource request failed";
            let _ = write_reply(&mut stream, 502, &[], body);
        }
        if once {
            break;
        }
    }
    Ok(0)
}

fn relay(stream: &mut TcpStream, backend: &Gateway, path: &str, methods: &[String]) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| Error::config("cannot set seller request timeout"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| Error::config("cannot set seller response timeout"))?;
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|_| Error::config("cannot read seller request"))?,
    );
    let mut first = String::new();
    reader
        .by_ref()
        .take(8193)
        .read_line(&mut first)
        .map_err(|_| Error::usage("invalid HTTP request line"))?;
    if first.len() > 8192 {
        return Err(Error::usage("HTTP request line is too long"));
    }
    let pieces = first.split_whitespace().collect::<Vec<_>>();
    if pieces.len() != 3 || !pieces[2].starts_with("HTTP/1.") {
        return Err(Error::usage("use bounded HTTP/1 requests"));
    }
    let method = pieces[0];
    let (incoming_path, query) = pieces[1].split_once('?').unwrap_or((pieces[1], ""));
    if incoming_path != "/" && incoming_path != path {
        return write_reply(
            stream,
            404,
            &[],
            b"This facade serves one registered resource at its root",
        );
    }
    if !methods.iter().any(|m| m == method) {
        return write_reply(
            stream,
            405,
            &[],
            b"Method not admitted by registered backend resource",
        );
    }
    let mut headers = vec![];
    let mut bytes = first.len();
    let mut length = None;
    loop {
        let mut line = String::new();
        reader
            .by_ref()
            .take(8193)
            .read_line(&mut line)
            .map_err(|_| Error::usage("invalid request header"))?;
        bytes += line.len();
        if line.is_empty() || bytes > 32768 || line.len() > 8192 {
            return Err(Error::usage("request headers exceed bounds"));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line
            .trim_end_matches(['\r', '\n'])
            .split_once(':')
            .ok_or_else(|| Error::usage("invalid header"))?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return write_reply(
                stream,
                400,
                &[],
                b"Use Content-Length for this bounded seller facade",
            );
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(Error::usage("duplicate Content-Length"));
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| Error::usage("invalid Content-Length"))?,
            );
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    let length = length.unwrap_or(0);
    if length > 65536 {
        return write_reply(stream, 413, &[], b"Request body exceeds 65536 bytes");
    }
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| Error::usage("incomplete request body"))?;
    let (status, headers, body) = backend.relay_registered(path, query, method, &headers, body)?;
    write_reply(stream, status, &headers, &body)
}

fn write_reply(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<()> {
    write!(stream, "HTTP/1.1 {status} AllowIt\r\n")
        .map_err(|_| Error::config("cannot write seller response"))?;
    for (k, v) in headers {
        if [
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "trailer",
            "upgrade",
        ]
        .contains(&k.to_ascii_lowercase().as_str())
            || k.contains(['\r', '\n'])
            || v.contains(['\r', '\n'])
        {
            continue;
        }
        write!(stream, "{k}: {v}\r\n").map_err(|_| Error::config("cannot write seller header"))?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(body))
    .map_err(|_| Error::config("cannot write seller body"))
}
