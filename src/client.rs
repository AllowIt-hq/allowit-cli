use crate::{
    VERSION,
    config::Config,
    error::{Error, Result},
    output::one_line,
};
use reqwest::{blocking::Client as HttpClient, redirect::Policy, tls::Version};
use serde_json::Value;
use std::{io::Read, time::Duration};
pub(crate) const MAX_REQUEST: usize = 64 << 10;
pub(crate) struct Client {
    pub cfg: Config,
    http: HttpClient,
    pub resent: bool,
}
impl Client {
    pub fn new(cfg: Config) -> Result<Self> {
        let mut builder = HttpClient::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(60))
            .min_tls_version(Version::TLS_1_2);
        if !cfg.ca_file.is_empty() {
            let pem = std::fs::read(&cfg.ca_file).map_err(|_| {
                Error::config("ALLOWIT_CA_FILE must name a readable PEM certificate file")
            })?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| {
                Error::config("ALLOWIT_CA_FILE must name a readable PEM certificate file")
            })?;
            if certs.is_empty() {
                return Err(Error::config(
                    "ALLOWIT_CA_FILE must name a readable PEM certificate file",
                ));
            }
            for c in certs {
                builder = builder.add_root_certificate(c);
            }
        }
        let http = builder
            .build()
            .map_err(|_| Error::config("could not configure the AllowIt HTTP client"))?;
        Ok(Self {
            cfg,
            http,
            resent: false,
        })
    }
    fn once(&self, method: &str, action: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>)> {
        let mut request = self
            .http
            .request(method.parse().unwrap(), self.cfg.route(action))
            .bearer_auth(&self.cfg.token)
            .header("Accept", "application/json")
            .header("User-Agent", format!("allowit-cli/{VERSION}"));
        if let Some(b) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(b.to_vec());
        }
        let mut response = request.send().map_err(|e| {
            let mut text = e.to_string();
            let mut source = std::error::Error::source(&e);
            while let Some(cause) = source {
                text.push_str(&cause.to_string());
                source = cause.source();
            }
            if text.contains("certificate") || text.contains("Certificate") {
                Error::config("TLS certificate for ALLOWIT_URL is not trusted")
            } else {
                Error::uncertain(format!("network error talking to AllowIt: {e}"))
            }
        })?;
        let status = response.status().as_u16();
        let mut data = Vec::new();
        Read::by_ref(&mut response)
            .take((2 << 20) + 1)
            .read_to_end(&mut data)
            .map_err(|e| {
                Error::uncertain(format!("network error reading the AllowIt response: {e}"))
            })?;
        if data.len() > 2 << 20 {
            return Err(Error::uncertain("AllowIt response exceeded the 2 MB limit"));
        }
        Ok((status, data))
    }
    pub fn call(&mut self, method: &str, action: &str, body: Option<&[u8]>) -> Result<Value> {
        if body.is_some_and(|b| b.len() > MAX_REQUEST) {
            return Err(Error::unsupported("request is larger than the 64 KB limit"));
        }
        let mut last = Error::uncertain("network error talking to AllowIt");
        let mut processed = false;
        self.resent = false;
        for attempt in 0..=2 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs(attempt));
            }
            let (status, data) = match self.once(method, action, body) {
                Ok(x) => x,
                Err(e) => {
                    if e.config {
                        return Err(final_error(e, processed, &last));
                    }
                    last = e;
                    processed = method != "GET";
                    continue;
                }
            };
            if matches!(status, 502..=504) {
                last = Error::uncertain(Error::api(status, error_message(&data)).message);
                processed = method != "GET";
                continue;
            }
            if (300..400).contains(&status) {
                let msg =
                    format!("AllowIt answered with a redirect (HTTP {status}); check ALLOWIT_URL");
                return Err(if method != "GET" {
                    Error::uncertain(msg)
                } else {
                    final_error(Error::config(msg), processed, &last)
                });
            }
            if status != 200 {
                let e = Error::api(status, error_message(&data));
                return Err(if status >= 500 || (200..300).contains(&status) {
                    Error::uncertain(e.message)
                } else {
                    final_error(e, processed, &last)
                });
            }
            let value: Value = serde_json::from_slice(&data).map_err(|_| {
                Error::uncertain("AllowIt returned a response that is not valid JSON")
            })?;
            if !value.is_object() && !value.is_null() {
                return Err(Error::uncertain(
                    "AllowIt returned a response that is not valid JSON",
                ));
            }
            self.resent = processed;
            return Ok(value);
        }
        Err(if last.code == 5 {
            last
        } else {
            Error::uncertain(last.message)
        })
    }
    /// Send one POST and never resend it. Only HTTP 200 with a JSON object is a known outcome.
    /// Every other result is uncertain: the caller must recover by status lookup with the same
    /// request ID. Messages never contain the token, the route or request/response bodies.
    pub fn post_once(&mut self, action: &str, body: &[u8]) -> Result<Value> {
        if body.len() > MAX_REQUEST {
            return Err(Error::unsupported("request is larger than the 64 KB limit"));
        }
        self.resent = false;
        let (status, data) = self.once("POST", action, Some(body)).map_err(|e| {
            if e.config {
                e
            } else {
                Error::uncertain(format!(
                    "network error talking to AllowIt; {UNKNOWN_OUTCOME}"
                ))
            }
        })?;
        if status != 200 {
            let mut e =
                Error::uncertain(format!("AllowIt returned HTTP {status}; {UNKNOWN_OUTCOME}"));
            e.status = Some(status);
            return Err(e);
        }
        match serde_json::from_slice::<Value>(&data) {
            Ok(value) if value.is_object() => Ok(value),
            _ => Err(Error::uncertain(format!(
                "AllowIt returned a response that is not a JSON object; {UNKNOWN_OUTCOME}"
            ))),
        }
    }
}
const UNKNOWN_OUTCOME: &str =
    "the request outcome is unknown; do not resend it, check its status with the same requestId";
fn final_error(e: Error, processed: bool, last: &Error) -> Error {
    if !processed || e.code == 5 {
        e
    } else {
        Error::uncertain(format!(
            "{e} (after an earlier attempt that may have been processed: {last})"
        ))
    }
}
fn error_message(data: &[u8]) -> String {
    serde_json::from_slice::<Value>(data)
        .ok()
        .and_then(|v| v["error"].as_str().filter(|s| !s.is_empty()).map(one_line))
        .unwrap_or_else(|| "no error message".into())
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        io::{ErrorKind, Write},
        net::{TcpListener, TcpStream},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::JoinHandle,
        time::Instant,
    };
    const TOKEN: &str = "owner-1.policy-1.secret-token-0123456789";
    const BODY: &[u8] = br#"{"requestId":"req-private-0001","amount":"private-amount-77"}"#;
    pub(crate) enum Reply {
        Close,
        Status(u16, &'static str),
    }
    pub(crate) struct Seen {
        pub head: String,
        pub body: Vec<u8>,
    }
    pub(crate) struct Server {
        listener: Arc<TcpListener>,
        done: Arc<AtomicBool>,
        handle: JoinHandle<Vec<Seen>>,
    }
    fn read_request(stream: &mut TcpStream) -> Seen {
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let length = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|n| n.parse().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        Seen { head, body }
    }
    /// Serve one scripted reply per connection until the script ends or the client returns.
    pub(crate) fn serve(replies: Vec<Reply>) -> (Client, Server) {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let accept = listener.clone();
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(20);
            for reply in replies {
                let mut stream = loop {
                    match accept.accept() {
                        Ok((s, _)) => break s,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            if stop.load(Ordering::SeqCst) || Instant::now() > deadline {
                                return seen;
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                seen.push(read_request(&mut stream));
                if let Reply::Status(status, body) = reply {
                    write!(
                        stream,
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nConnection: close\r\nLocation: /elsewhere\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .unwrap();
                }
            }
            seen
        });
        let cfg = Config {
            origin,
            owner: "owner-1".into(),
            policy: "policy-1".into(),
            token: TOKEN.into(),
            ca_file: String::new(),
        };
        (
            Client::new(cfg).unwrap(),
            Server {
                listener,
                done,
                handle,
            },
        )
    }
    impl Server {
        /// Join the script and prove the client opened no further connection before returning.
        pub(crate) fn finish(self) -> Vec<Seen> {
            self.done.store(true, Ordering::SeqCst);
            let seen = self.handle.join().unwrap();
            match self.listener.accept() {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                _ => panic!("client opened an unexpected extra connection"),
            }
            seen
        }
    }
    fn assert_private(e: &Error) {
        for private in [
            TOKEN,
            "secret-token",
            "req-private",
            "private-amount",
            "127.0.0.1",
            "owner-1",
            "server-private",
        ] {
            assert!(
                !e.message.contains(private),
                "leaked {private}: {}",
                e.message
            );
        }
        assert!(e.message.contains("do not resend"), "{}", e.message);
        assert!(e.message.contains("same requestId"), "{}", e.message);
    }
    #[test]
    fn post_once_sends_exact_bearer_route_and_body() {
        let (mut client, server) = serve(vec![Reply::Status(200, r#"{"status":"accepted"}"#)]);
        let value = client.post_once("run", BODY).unwrap();
        assert_eq!(value, serde_json::json!({"status": "accepted"}));
        assert!(!client.resent);
        let seen = server.finish();
        assert_eq!(seen.len(), 1);
        let head = seen[0].head.to_ascii_lowercase();
        assert!(
            seen[0]
                .head
                .starts_with("POST /api/harness/owner-1/policy-1/run HTTP/1.1\r\n")
        );
        assert!(head.contains(&format!(
            "\r\nauthorization: bearer {}\r\n",
            TOKEN.to_ascii_lowercase()
        )));
        assert!(head.contains("\r\ncontent-type: application/json\r\n"));
        assert!(head.contains("\r\naccept: application/json\r\n"));
        assert!(head.contains(&format!("\r\nuser-agent: allowit-cli/{VERSION}\r\n")));
        assert_eq!(seen[0].body, BODY);
    }
    #[test]
    fn post_once_connection_close_is_unknown_without_retry() {
        let (mut client, server) = serve(vec![Reply::Close, Reply::Status(200, "{}")]);
        let e = client.post_once("run", BODY).unwrap_err();
        assert_eq!((e.code, e.status, e.config), (5, None, false));
        assert_private(&e);
        assert_eq!(server.finish().len(), 1);
    }
    #[test]
    fn post_once_gateway_errors_are_unknown_without_retry() {
        for status in [502, 503, 504] {
            let (mut client, server) = serve(vec![
                Reply::Status(
                    status,
                    r#"{"error":"server-private echo req-private-0001"}"#,
                ),
                Reply::Status(200, "{}"),
            ]);
            let e = client.post_once("run", BODY).unwrap_err();
            assert_eq!((e.code, e.status), (5, Some(status)));
            assert!(
                e.message
                    .starts_with(&format!("AllowIt returned HTTP {status};"))
            );
            assert_private(&e);
            assert_eq!(server.finish().len(), 1);
        }
    }
    #[test]
    fn post_once_classifies_every_non_200_as_unknown() {
        for status in [201, 204, 302, 400, 401, 403, 404, 409, 422, 429, 500] {
            let (mut client, server) = serve(vec![
                Reply::Status(
                    status,
                    r#"{"error":"server-private echo req-private-0001"}"#,
                ),
                Reply::Status(200, "{}"),
            ]);
            let e = client.post_once("run", BODY).unwrap_err();
            assert_eq!((e.code, e.status, e.config), (5, Some(status), false));
            assert_private(&e);
            // A redirect is neither followed nor retried.
            assert_eq!(server.finish().len(), 1, "HTTP {status}");
        }
    }
    #[test]
    fn post_once_rejects_non_object_success_bodies_as_unknown() {
        for body in ["not json server-private", "null", "[1]", r#""req-private""#] {
            let (mut client, server) = serve(vec![Reply::Status(200, body)]);
            let e = client.post_once("run", BODY).unwrap_err();
            assert_eq!((e.code, e.status), (5, None));
            assert_private(&e);
            assert_eq!(server.finish().len(), 1);
        }
    }
    #[test]
    fn post_once_rejects_oversized_body_before_sending() {
        let (mut client, server) = serve(vec![]);
        let e = client
            .post_once("run", &vec![b' '; MAX_REQUEST + 1])
            .unwrap_err();
        assert_eq!(e.code, 3);
        assert!(server.finish().is_empty());
    }
    #[test]
    fn scalar_call_still_retries_post_after_gateway_error_and_close() {
        let (mut client, server) = serve(vec![
            Reply::Status(503, r#"{"error":"busy"}"#),
            Reply::Close,
            Reply::Status(200, r#"{"ok":true}"#),
        ]);
        let value = client.call("POST", "request", Some(BODY)).unwrap();
        assert_eq!(value, serde_json::json!({"ok": true}));
        assert!(client.resent);
        let seen = server.finish();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|s| s.body == BODY));
    }
    #[test]
    fn scalar_call_keeps_api_error_and_null_success_behavior() {
        let (mut client, server) = serve(vec![Reply::Status(400, r#"{"error":"bad input"}"#)]);
        let e = client.call("POST", "request", Some(BODY)).unwrap_err();
        assert_eq!((e.code, e.status), (4, Some(400)));
        assert_eq!(e.message, "AllowIt returned HTTP 400: bad input");
        assert_eq!(server.finish().len(), 1);
        let (mut client, server) = serve(vec![Reply::Status(200, "null")]);
        assert_eq!(client.call("GET", "skill", None).unwrap(), Value::Null);
        assert!(!client.resent);
        assert_eq!(server.finish().len(), 1);
    }
}
