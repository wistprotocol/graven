use crate::error::{Error, Result};
use reqwest::Url;
use std::io::Read;
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 30;

/// A loopback literal, `localhost` or a name under `.localhost`, which
/// RFC 6761 §6.3 resolves to loopback by definition.
pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .to_ascii_lowercase()
            .trim_end_matches('.')
            .ends_with(".localhost")
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

/// WIST-3 §5 and §6: a Log's paths are rooted at a base URL — the
/// Service Origin, or a Mirror's `mirror_urls` entry, "each ending in
/// `/`" — so every path is resolved under that base's own path rather
/// than at its origin, and a Mirror serving the Log under a prefix is
/// read at that prefix.
pub fn resolve(base: &Url, raw: &str) -> Result<Url> {
    if let Ok(direct) = Url::parse(raw) {
        if direct.scheme() == "http" || direct.scheme() == "https" {
            return Ok(direct);
        }
    }
    let mut rooted = base.clone();
    if !rooted.path().ends_with('/') {
        let path = format!("{}/", rooted.path());
        rooted.set_path(&path);
    }
    rooted
        .join(raw.trim_start_matches('/'))
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

    pub fn allow_http(&self) -> bool {
        self.allow_http
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
        let value = wist_core::json::parse(&bytes)?;
        Ok((bytes, value))
    }

    /// WIST-3 §6 and §10: reads a response while it streams and refuses it
    /// at `limit` before buffering octets past it. Equality with the bound
    /// is permitted; one octet more is `WIST3-E03`, and no more than that
    /// one octet is ever held.
    pub fn get_bounded(&self, url: &Url, limit: u64) -> Result<Vec<u8>> {
        guard_scheme(url, self.allow_http)?;
        let mut resp = self
            .inner
            .get(url.clone())
            .send()
            .map_err(|e| Error::Fetch(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::Fetch(format!("WIST3-E01 no file at {url}")));
        }
        if !resp.status().is_success() {
            return Err(Error::Fetch(format!(
                "WIST3-E01 HTTP {} for {url}",
                resp.status()
            )));
        }
        let over = || {
            Error::Verify(format!(
                "WIST3-E03 {url} carries more than the {limit} octets its bound admits"
            ))
        };
        if resp
            .content_length()
            .is_some_and(|declared| declared > limit)
        {
            return Err(over());
        }
        let ceiling = usize::try_from(limit.saturating_add(1)).unwrap_or(usize::MAX);
        let mut body = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let room = ceiling - body.len();
            if room == 0 {
                return Err(over());
            }
            let take = room.min(chunk.len());
            let read = resp
                .read(&mut chunk[..take])
                .map_err(|e| Error::Fetch(e.to_string()))?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        if body.len() as u64 > limit {
            return Err(over());
        }
        Ok(body)
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
        let url = Url::parse("http://labeler.localhost/x.json").unwrap();
        assert!(guard_scheme(&url, true).is_ok());
        assert!(guard_scheme(&url, false).is_err());
        let url = Url::parse("http://localhost.example/x.json").unwrap();
        assert!(guard_scheme(&url, true).is_err());
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
    fn resolve_keeps_every_path_under_the_bases_own_prefix() {
        for base in ["https://cdn.example/wist/", "https://cdn.example/wist"] {
            let base = Url::parse(base).unwrap();
            assert_eq!(
                resolve(&base, "/checkpoint").unwrap().as_str(),
                "https://cdn.example/wist/checkpoint"
            );
            assert_eq!(
                resolve(&base, "/tile/0/000").unwrap().as_str(),
                "https://cdn.example/wist/tile/0/000"
            );
            assert_eq!(
                resolve(&base, "/snapshots/2026-08-09/manifest.json")
                    .unwrap()
                    .as_str(),
                "https://cdn.example/wist/snapshots/2026-08-09/manifest.json"
            );
        }
        let origin = Url::parse("https://log.example").unwrap();
        assert_eq!(
            resolve(&origin, "/log/checkpoints/000000001")
                .unwrap()
                .as_str(),
            "https://log.example/log/checkpoints/000000001"
        );
    }

    #[test]
    fn parse_base_rejects_non_http_scheme() {
        assert!(parse_base("ftp://log.example/").is_err());
        assert!(parse_base("not a url").is_err());
        assert!(parse_base("https://log.example").is_ok());
    }
}
