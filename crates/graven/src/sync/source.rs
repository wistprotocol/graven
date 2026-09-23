use crate::error::{Error, Result};
use crate::fetch::{resolve, Client};
use reqwest::Url;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// WIST-3 §5 and §8: `WIST3-E01` and `WIST3-E03` both move to the next source, since integrity
/// never depends on where the octets came from.
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

    /// Files that only verify together are re-fetched from one source at a time.
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

    /// Snapshot documents carry no octet bound; the manifest, the index entry or the deferred
    /// signature bounds them instead.
    pub fn whole<T>(&self, path: &str, read: impl Fn(&[u8]) -> Result<T>) -> Result<(T, Url)> {
        self.whole_from(path, 0, read)
    }

    /// WIST-3 §9: a rejected Snapshot moves on only if the next source's documents are read before
    /// those already refused.
    pub fn whole_from<T>(
        &self,
        path: &str,
        from: usize,
        read: impl Fn(&[u8]) -> Result<T>,
    ) -> Result<(T, Url)> {
        let mut last: Option<Error> = None;
        let ordered = self.bases[from.min(self.bases.len())..]
            .iter()
            .chain(&self.bases[..from.min(self.bases.len())]);
        for base in ordered {
            let url = match resolve(base, path) {
                Ok(url) => url,
                Err(error) => {
                    last = Some(error);
                    continue;
                }
            };
            match self
                .client
                .get_bytes(&url)
                .and_then(|bytes| read(&bytes))
                .map(|value| (value, url))
            {
                Ok(served) => return Ok(served),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| Error::Fetch(format!("WIST3-E01 no source holds {path}"))))
    }

    /// WIST-3 §6: the file is mutable, so each source states its own.
    pub fn whole_at<T>(
        &self,
        path: &str,
        index: usize,
        read: impl Fn(&[u8]) -> Result<T>,
    ) -> Result<(T, Url)> {
        let base = self
            .bases
            .get(index)
            .ok_or_else(|| Error::Fetch(format!("WIST3-E01 no source holds {path}")))?;
        let url = resolve(base, path)?;
        let value = read(&self.client.get_bytes(&url)?)?;
        Ok((value, url))
    }

    /// WIST-3 §6: every path but `/checkpoint` is immutable, so its verified octets are cached.
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
