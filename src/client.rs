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
}
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
