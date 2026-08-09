use crate::error::{Error, Result};
use reqwest::Url;
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 30;

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn guard_scheme(parsed: &Url, allow_http: bool) -> Result<()> {
    let host_ok = allow_http && parsed.host_str().is_some_and(is_loopback_host);
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if host_ok => Ok(()),
        other => Err(Error::Fetch(format!(
            "refusing to fetch {other} URL for non-loopback host or --allow-http not set: {parsed}"
        ))),
    }
}

pub fn parse_base(log_base: &str) -> Result<Url> {
    let url = Url::parse(log_base)
        .map_err(|e| Error::Fetch(format!("invalid log base URL {log_base}: {e}")))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        other => Err(Error::Fetch(format!(
            "log base URL must be http or https, got {other}"
        ))),
    }
}

pub fn resolve(base: &Url, raw: &str) -> Result<Url> {
    if let Ok(direct) = Url::parse(raw) {
        if direct.scheme() == "http" || direct.scheme() == "https" {
            return Ok(direct);
        }
    }
    base.join(raw)
        .map_err(|e| Error::Fetch(format!("invalid relative URL {raw}: {e}")))
}

pub struct Client {
    allow_http: bool,
    inner: reqwest::blocking::Client,
}

impl Client {
    pub fn new(allow_http: bool) -> Client {
        let inner = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .expect("reqwest client builds with a fixed timeout");
        Client { allow_http, inner }
    }

    pub fn get_bytes(&self, url: &Url) -> Result<Vec<u8>> {
        guard_scheme(url, self.allow_http)?;
        let resp = self
            .inner
            .get(url.clone())
            .send()
            .map_err(|e| Error::Fetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Fetch(format!("HTTP {} for {url}", resp.status())));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| Error::Fetch(e.to_string()))
    }

    pub fn get_json(&self, url: &Url) -> Result<(Vec<u8>, serde_json::Value)> {
        let bytes = self.get_bytes(url)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        Ok((bytes, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_scheme_allows_https_regardless_of_allow_http() {
        let url = Url::parse("https://example.com/x.json").unwrap();
        assert!(guard_scheme(&url, false).is_ok());
        assert!(guard_scheme(&url, true).is_ok());
    }

    #[test]
    fn guard_scheme_allows_http_loopback_only_when_allow_http_set() {
        let url = Url::parse("http://127.0.0.1:8080/x.json").unwrap();
        assert!(guard_scheme(&url, false).is_err());
        assert!(guard_scheme(&url, true).is_ok());

        let url = Url::parse("http://localhost:8080/x.json").unwrap();
        assert!(guard_scheme(&url, true).is_ok());
    }

    #[test]
    fn guard_scheme_rejects_http_non_loopback_even_with_allow_http() {
        let url = Url::parse("http://example.com/x.json").unwrap();
        assert!(guard_scheme(&url, true).is_err());
        assert!(guard_scheme(&url, false).is_err());
    }

    #[test]
    fn resolve_prefers_absolute_url_over_base() {
        let base = Url::parse("https://log.example/").unwrap();
        let resolved = resolve(&base, "https://other.example/manifest.json").unwrap();
        assert_eq!(resolved.as_str(), "https://other.example/manifest.json");
    }

    #[test]
    fn resolve_joins_root_relative_path_against_base_authority() {
        let base = Url::parse("https://log.example/ignored/path").unwrap();
        let resolved = resolve(&base, "/snapshots/2026-08-09/manifest.json").unwrap();
        assert_eq!(
            resolved.as_str(),
            "https://log.example/snapshots/2026-08-09/manifest.json"
        );
    }

    #[test]
    fn parse_base_rejects_non_http_scheme() {
        assert!(parse_base("ftp://log.example/").is_err());
        assert!(parse_base("not a url").is_err());
        assert!(parse_base("https://log.example").is_ok());
    }
}
