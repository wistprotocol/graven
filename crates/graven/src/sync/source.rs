use crate::error::{Error, Result};
use crate::fetch::{resolve, Client};
use reqwest::Url;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// WIST-3 §5 and §8: the Aggregator's Service Origin and every Mirror the
/// Consumer holds for the Log, tried in order. A file a source does not
/// hold is `WIST3-E01` and a file whose octets do not verify is
/// `WIST3-E03`; both are answered by asking the next source, since
/// integrity never depends on where the octets came from.
pub struct Sources<'a> {
    client: &'a Client,
    bases: Vec<Url>,
    cache: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl<'a> Sources<'a> {
    pub fn new(client: &'a Client, bases: Vec<Url>) -> Self {
        Sources {
            client,
            bases,
            cache: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn primary(&self) -> &Url {
        &self.bases[0]
    }

    pub fn count(&self) -> usize {
        self.bases.len()
    }

    /// Fetches one path from the first source whose octets `check`
    /// accepts, under the octet bound the path's format carries.
    pub fn verified(
        &self,
        path: &str,
        limit: u64,
        check: impl Fn(&[u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let mut last: Option<Error> = None;
        for base in &self.bases {
            let url = match resolve(base, path) {
                Ok(url) => url,
                Err(error) => {
                    last = Some(error);
                    continue;
                }
            };
            match self
                .client
                .get_bounded(&url, limit)
                .and_then(|bytes| check(&bytes).map(|()| bytes))
            {
                Ok(bytes) => return Ok(bytes),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| Error::Fetch(format!("WIST3-E01 no source holds {path}"))))
    }

    /// Fetches one path from one named source, so that a group of files
    /// that only verify together is re-fetched from one source at a time.
    pub fn at(
        &self,
        path: &str,
        limit: u64,
        index: usize,
        check: impl Fn(&[u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let base = self
            .bases
            .get(index)
            .ok_or_else(|| Error::Fetch(format!("WIST3-E01 no source holds {path}")))?;
        let url = resolve(base, path)?;
        let bytes = self.client.get_bounded(&url, limit)?;
        check(&bytes)?;
        Ok(bytes)
    }

    /// Fetches one path whose format carries no octet bound and returns
    /// what `read` makes of the first source's octets it accepts. A
    /// Snapshot's documents and files are bounded by nothing and held to
    /// the manifest's `sha256` and `bytes` or to an envelope signature
    /// instead, so a source that does not hold the path, or serves octets
    /// those checks refuse, sends the same path to the next source.
    pub fn whole<T>(&self, path: &str, read: impl Fn(&[u8]) -> Result<T>) -> Result<T> {
        let mut last: Option<Error> = None;
        for base in &self.bases {
            match resolve(base, path)
                .and_then(|url| self.client.get_bytes(&url))
                .and_then(|bytes| read(&bytes))
            {
                Ok(value) => return Ok(value),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| Error::Fetch(format!("WIST3-E01 no source holds {path}"))))
    }

    /// The same unbounded fetch from one named source, for a path each
    /// source states for itself because the file is mutable (§6).
    pub fn whole_at<T>(
        &self,
        path: &str,
        index: usize,
        read: impl Fn(&[u8]) -> Result<T>,
    ) -> Result<T> {
        let base = self
            .bases
            .get(index)
            .ok_or_else(|| Error::Fetch(format!("WIST3-E01 no source holds {path}")))?;
        let url = resolve(base, path)?;
        read(&self.client.get_bytes(&url)?)
    }

    /// The same bounded fetch, remembering the verified octets: every path
    /// this serves but `/checkpoint` names an immutable file (§6).
    pub fn cached(
        &self,
        path: &str,
        limit: u64,
        check: impl Fn(&[u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        if let Some(held) = self.cache.borrow().get(path) {
            return Ok(held.clone());
        }
        let bytes = self.verified(path, limit, check)?;
        self.cache
            .borrow_mut()
            .insert(path.to_owned(), bytes.clone());
        Ok(bytes)
    }

    pub fn client(&self) -> &Client {
        self.client
    }
}
