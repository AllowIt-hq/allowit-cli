use crate::error::{Error, Result, quoted};
use std::{env, net::IpAddr};
use url::Url;
#[derive(Clone)]
pub(crate) struct Config {
    pub origin: String,
    pub owner: String,
    pub policy: String,
    pub token: String,
    pub ca_file: String,
}
fn valid_id(s: &str, min: usize, max: usize) -> bool {
    s.len() >= min
        && s.len() <= max
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
pub(crate) fn env_value(name: &str) -> String {
    env::var(name).unwrap_or_default()
}
impl Config {
    pub fn load(policy: &str) -> Result<Self> {
        let origin = parse_origin(&env_value("ALLOWIT_URL"))?;
        let raw = env_value("ALLOWIT_TOKEN");
        if raw.is_empty() {
            return Err(Error::config(
                "set ALLOWIT_TOKEN to the policy's harness token",
            ));
        }
        let parts: Vec<_> = raw.split('.').collect();
        if parts.len() != 3
            || !valid_id(parts[0], 1, 128)
            || !valid_id(parts[1], 1, 128)
            || !valid_id(parts[2], 16, 128)
        {
            return Err(Error::config(
                "ALLOWIT_TOKEN must have the form owner.policy.secret",
            ));
        }
        if policy != parts[1] {
            return Err(Error::config(format!(
                "POLICY {} does not match the policy in ALLOWIT_TOKEN",
                quoted(policy)
            )));
        }
        Ok(Self {
            origin,
            owner: parts[0].into(),
            policy: parts[1].into(),
            token: raw,
            ca_file: env_value("ALLOWIT_CA_FILE"),
        })
    }
    pub fn route(&self, action: &str) -> String {
        format!(
            "{}/api/harness/{}/{}/{}",
            self.origin, self.owner, self.policy, action
        )
    }
    pub fn is_route(&self, action: &str, raw: &str) -> bool {
        if raw.is_empty() || raw.contains(['?', '#', '\\']) {
            return false;
        }
        let Ok(base) = Url::parse(&self.route("skill")) else {
            return false;
        };
        let Ok(u) = base.join(raw) else {
            return false;
        };
        u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.origin().ascii_serialization() == self.origin
            && u.path() == format!("/api/harness/{}/{}/{action}", self.owner, self.policy)
    }
}
pub(crate) fn parse_origin(raw: &str) -> Result<String> {
    if raw.is_empty() {
        return Err(Error::config(
            "set ALLOWIT_URL to the AllowIt service origin, e.g. https://allowit.example",
        ));
    }
    let invalid = || Error::config("ALLOWIT_URL must be an origin such as https://allowit.example");
    let (scheme, rest) = raw.split_once("://").ok_or_else(invalid)?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split('/').next().unwrap_or_default();
    let u = Url::parse(raw).map_err(|_| invalid())?;
    if u.cannot_be_a_base() || u.host_str().is_none() || authority.is_empty() {
        return Err(invalid());
    }
    if authority.contains('@') {
        return Err(Error::config("ALLOWIT_URL must not contain credentials"));
    }
    let path = &rest[authority.len()..];
    if !path.is_empty() && path != "/" || raw.contains(['?', '#']) {
        return Err(Error::config(
            "ALLOWIT_URL must be an origin without a path, query or fragment",
        ));
    }
    let host = if let Some(h) = authority.strip_prefix('[') {
        h.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    match scheme.as_str() {
        "https" => {}
        "http" => {
            if !host.eq_ignore_ascii_case("localhost")
                && !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            {
                return Err(Error::config(
                    "ALLOWIT_URL must use https (http is allowed only for localhost)",
                ));
            }
        }
        _ => return Err(Error::config("ALLOWIT_URL must use https")),
    }
    let mut authority = authority.to_lowercase();
    if authority.ends_with(if scheme == "https" { ":443" } else { ":80" }) {
        authority = if host.contains(':') {
            format!("[{}]", host.to_lowercase())
        } else {
            host.to_lowercase()
        };
    }
    Ok(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origins_are_strict() {
        assert_eq!(
            parse_origin("https://EXAMPLE.com:443/").unwrap(),
            "https://example.com"
        );
        assert_eq!(parse_origin("http://[::1]:80").unwrap(), "http://[::1]");
        for s in [
            "http://example.com",
            "http://127.1",
            "https://example.com/.",
            "https://example.com?",
            "https://user@example.com",
        ] {
            assert!(parse_origin(s).is_err(), "{s}");
        }
    }
}
