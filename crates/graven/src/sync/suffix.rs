//! WIST-4 §3.1 at the Consumer: the Public Suffix List snapshots the Log
//! pinned, obtained from `/log/suffix-lists/` and verified by identifier,
//! the acts that put each in force, and WIST-3 §3.2's per-domain capacity
//! of every walked Block under the snapshot in force at it.
use crate::error::{Error, Result};
use crate::fetch::{resolve, Client};
use reqwest::Url;
use rusqlite::Connection;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use wist_core::crypto::PublicKey;
use wist_core::suffix_list::{
    self, BlockCaps, Disposition, HeldFile, SuffixList, SuffixListReplay,
};

pub struct SuffixLists {
    replay: SuffixListReplay,
    octets: BTreeMap<String, Vec<u8>>,
    parsed: BTreeMap<String, Arc<SuffixList>>,
}

fn fetch(client: &Client, base: &Url, identifier: &str) -> Result<Vec<u8>> {
    let hex = identifier.strip_prefix("sha256:").unwrap_or(identifier);
    let url = resolve(base, &format!("/log/suffix-lists/{hex}.dat"))?;
    let octets = client.get_bytes(&url).map_err(|e| {
        Error::Verify(format!(
            "WIST3-E01 suffix-list snapshot {identifier} is not obtainable: {e}"
        ))
    })?;
    if suffix_list::identifier(&octets) != identifier {
        return Err(Error::Verify(format!(
            "WIST3-E03 the file served for suffix-list snapshot {identifier} does not hash to it"
        )));
    }
    Ok(octets)
}

impl SuffixLists {
    pub fn load(conn: &Connection) -> Result<Self> {
        conn.execute_batch(crate::store::CREATE_SUFFIX_LISTS)?;
        let mut replay = SuffixListReplay::new();
        let mut stmt = conn.prepare("SELECT height, sha256 FROM suffix_list_acts ORDER BY seq")?;
        for row in stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })? {
            let (height, identifier) = row?;
            replay.adopt(&identifier, height.max(0) as u64);
        }
        let mut octets = BTreeMap::new();
        let mut stmt = conn.prepare("SELECT sha256, octets FROM suffix_lists")?;
        for row in stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })? {
            let (identifier, file) = row?;
            octets.insert(identifier, file);
        }
        Ok(Self {
            replay,
            octets,
            parsed: BTreeMap::new(),
        })
    }

    pub fn save(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(crate::store::CREATE_SUFFIX_LISTS)?;
        for (identifier, octets) in &self.octets {
            conn.execute(
                "INSERT OR IGNORE INTO suffix_lists(sha256, octets) VALUES (?1, ?2)",
                (identifier, octets),
            )?;
        }
        conn.execute("DELETE FROM suffix_list_acts", [])?;
        for (height, identifier) in self.replay.accepted() {
            conn.execute(
                "INSERT INTO suffix_list_acts(height, sha256) VALUES (?1, ?2)",
                (*height as i64, identifier),
            )?;
        }
        Ok(())
    }

    /// WIST-3 §8 step 10: adopts the Snapshot's `suffix_list` tuple and
    /// obtains its file before any Block's capacity is checked under it.
    pub fn adopt(
        &mut self,
        client: &Client,
        base: &Url,
        identifier: &str,
        height: u64,
    ) -> Result<()> {
        if !self.octets.contains_key(identifier) {
            let octets = fetch(client, base, identifier)?;
            self.octets.insert(identifier.to_string(), octets);
        }
        self.replay.adopt(identifier, height);
        Ok(())
    }

    /// The snapshot in force at Block `height`.
    pub fn in_force_at_block(&mut self, height: u64) -> Result<Option<Arc<SuffixList>>> {
        let Some((identifier, _)) = self.replay.in_force_at_block(height) else {
            return Ok(None);
        };
        let identifier = identifier.to_string();
        if let Some(list) = self.parsed.get(&identifier) {
            return Ok(Some(list.clone()));
        }
        let octets = self.octets.get(&identifier).ok_or_else(|| {
            Error::Verify(format!(
                "WIST3-E01 suffix-list snapshot {identifier} in force at block {height} is not held"
            ))
        })?;
        let list = Arc::new(SuffixList::parse(octets).map_err(|e| Error::Verify(e.to_string()))?);
        self.parsed.insert(identifier, list.clone());
        Ok(Some(list))
    }

    /// WIST-3 §3.2: the Block's `publisher_delta`, `label` and `dispute`
    /// Entries per Registrable Domain under the snapshot in force at it.
    pub fn check_capacity(&mut self, height: u64, block: &Value, caps: BlockCaps) -> Result<()> {
        let list = self.in_force_at_block(height)?;
        let entries = block["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let kind = entry["type"].as_str()?;
                let host = match kind {
                    "publisher_delta" => entry["body"]["delta"]["publisher"].as_str(),
                    "label" => entry["body"]["label"]["labeler"].as_str(),
                    "dispute" => entry["body"]["dispute"]["disputant"].as_str(),
                    _ => None,
                }?;
                Some((kind, host))
            });
        suffix_list::check_block_capacity(entries, list.as_deref(), caps)
            .map_err(|e| Error::Verify(format!("block {height}: {e}")))
    }

    /// Replays one `suffix_list_update` sealed at `height`, obtaining the
    /// named file when the act verifies; an act the Log key does not
    /// authenticate or whose details fail their contract is ignored with
    /// its code, and a file that cannot be obtained or does not hash to
    /// its name fails the walk.
    pub fn apply_act(
        &mut self,
        client: &Client,
        base: &Url,
        height: u64,
        body: &Value,
        log_key: impl Fn(&str) -> Option<PublicKey>,
    ) -> Result<()> {
        let fetched: RefCell<BTreeMap<String, Result<Vec<u8>>>> = RefCell::new(BTreeMap::new());
        let octets = &self.octets;
        let held = |identifier: &str| -> HeldFile {
            if let Some(file) = octets.get(identifier) {
                return HeldFile::Bytes(file.len() as u64);
            }
            let mut fetched = fetched.borrow_mut();
            fetched
                .entry(identifier.to_string())
                .or_insert_with(|| fetch(client, base, identifier))
                .as_ref()
                .map_or(HeldFile::Unobtainable, |file| {
                    HeldFile::Bytes(file.len() as u64)
                })
        };
        let disposition = self.replay.apply(height, body, log_key, held);
        let fetched = fetched.into_inner();
        match disposition {
            Disposition::Accepted { .. } => {
                for (identifier, file) in fetched {
                    self.octets.insert(identifier, file?);
                }
                Ok(())
            }
            Disposition::Rejected("WIST3-E01") => {
                let failure = fetched
                    .into_values()
                    .find_map(|file| file.err())
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "WIST3-E01 the named file is not obtainable".into());
                Err(Error::Verify(format!("block {height}: {failure}")))
            }
            Disposition::Rejected(code) => {
                eprintln!("ignoring a suffix_list_update at height {height}: {code}");
                Ok(())
            }
            Disposition::NotSuffixList => Ok(()),
        }
    }
}
