use crate::error::{Error, Result};
use crate::sync::SyncState;
use rmcp::schemars;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const CREATE_UNIQUE_INDEX: &str =
    "CREATE UNIQUE INDEX IF NOT EXISTS records_url_publisher ON records(url, publisher)";

pub const CREATE_DECLARATIONS: &str =
    "CREATE TABLE IF NOT EXISTS declarations(domain TEXT NOT NULL, seq INTEGER NOT NULL, height INTEGER NOT NULL, sealed_at TEXT NOT NULL, baseline INTEGER NOT NULL, envelope TEXT NOT NULL, PRIMARY KEY(domain, seq, height))";

/// WIST-3 §7: the chain tip per (Publisher domain, Normalized URL). A
/// deleted URL keeps its tip, because a chain never restarts.
pub const CREATE_CHAIN_TIPS: &str =
    "CREATE TABLE IF NOT EXISTS chain_tips(publisher TEXT NOT NULL, url TEXT NOT NULL, tip TEXT NOT NULL, PRIMARY KEY(publisher, url))";

/// WIST-3 §3.4: the Aggregator keys valid for this Log, with the
/// permanently retired ones kept so a later add naming one is rejected.
pub const CREATE_AGGREGATOR_KEYS: &str =
    "CREATE TABLE IF NOT EXISTS aggregator_keys(key_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, removed INTEGER NOT NULL)";

/// WIST-4 §7's ladder as the Log states it, and WIST-4 §5's exclusions,
/// both of which WIST-3 §7 reads when materializing.
pub const CREATE_SANCTIONS: &str =
    "CREATE TABLE IF NOT EXISTS sanctions(domain TEXT PRIMARY KEY, level INTEGER NOT NULL, since_height INTEGER NOT NULL, notice_at INTEGER, appeal_at INTEGER, ruling TEXT, ruling_at INTEGER); CREATE TABLE IF NOT EXISTS exclusions(publisher TEXT NOT NULL, url TEXT NOT NULL, since_height INTEGER NOT NULL, PRIMARY KEY(publisher, url))";

pub const CREATE_TIER1: &str = "CREATE TABLE IF NOT EXISTS extracts(url TEXT NOT NULL, publisher TEXT NOT NULL, delta_id TEXT NOT NULL, extract TEXT NOT NULL, PRIMARY KEY(url, publisher)); CREATE VIRTUAL TABLE IF NOT EXISTS extracts_fts USING fts5(extract, content=extracts, content_rowid=rowid); CREATE TABLE IF NOT EXISTS links(source_url TEXT NOT NULL, target_url TEXT NOT NULL, position INTEGER NOT NULL)";

pub const CREATE_EMBEDDINGS: &str = "CREATE TABLE IF NOT EXISTS embeddings(delta_id TEXT PRIMARY KEY, url TEXT NOT NULL, publisher TEXT NOT NULL, vector BLOB NOT NULL); CREATE TABLE IF NOT EXISTS pack_meta(id INTEGER PRIMARY KEY CHECK(id = 1), model_json TEXT NOT NULL, metric TEXT NOT NULL, dim INTEGER NOT NULL, imported_at TEXT NOT NULL, key_b64u TEXT NOT NULL)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHit {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub observed_at: String,
    pub weight: String,
    pub title: String,
    pub r#abstract: Option<String>,
}

fn row_to_hit(row: &rusqlite::Row) -> rusqlite::Result<RecordHit> {
    Ok(RecordHit {
        url: row.get(0)?,
        publisher: row.get(1)?,
        delta_id: row.get(2)?,
        observed_at: row.get(3)?,
        weight: row.get(4)?,
        title: row.get(5)?,
        r#abstract: row.get(6)?,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct ProvEntry {
    pub log_id: String,
    pub synced_height: u64,
    pub weight: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MergedHit {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub observed_at: String,
    pub title: String,
    pub r#abstract: Option<String>,
    pub provenance: Vec<ProvEntry>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimilarHit {
    pub hit: MergedHit,
    pub score: f64,
}

#[derive(Debug, Clone)]
struct ExtractRow {
    extract: String,
    delta_id: String,
    observed_at: String,
    weight: String,
}

fn merge_extract(rows: Vec<(String, u64, ExtractRow)>) -> Option<(String, Vec<ProvEntry>)> {
    let mut by_delta: BTreeMap<String, (ExtractRow, Vec<ProvEntry>)> = BTreeMap::new();
    for (log_id, synced_height, row) in rows {
        let weight = row.weight.clone();
        let entry = by_delta
            .entry(row.delta_id.clone())
            .or_insert_with(|| (row, Vec::new()));
        entry.1.push(ProvEntry {
            log_id,
            synced_height,
            weight,
        });
    }

    let mut winner: Option<(String, String, String, Vec<ProvEntry>)> = None;
    for (delta_id, (row, mut provenance)) in by_delta {
        provenance.sort_by(|a, b| a.log_id.cmp(&b.log_id));
        let is_better = match &winner {
            Some((obs, did, _, _)) => {
                (row.observed_at.as_str(), delta_id.as_str()) > (obs.as_str(), did.as_str())
            }
            None => true,
        };
        if is_better {
            winner = Some((
                row.observed_at.clone(),
                delta_id,
                row.extract.clone(),
                provenance,
            ));
        }
    }
    winner.map(|(_, _, extract, provenance)| (extract, provenance))
}

fn quote_phrase(q: &str) -> String {
    format!("\"{}\"", q.replace('"', "\"\""))
}

pub(crate) fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let hit: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(hit.is_some())
}

fn blob_to_vec(blob: &[u8]) -> Result<Vec<f32>> {
    if !blob.len().is_multiple_of(4) {
        return Err(Error::Verify(format!(
            "embedding vector blob length {} is not a multiple of 4",
            blob.len()
        )));
    }
    Ok(blob
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

fn cosine_score(a: &[f32], b: &[f32]) -> f64 {
    let dot: f64 = a
        .iter()
        .zip(b)
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum();
    let norm_a: f64 = a.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot / (norm_a * norm_b)
    }
}

fn dot_score(a: &[f32], b: &[f32]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum()
}

fn euclidean_distance(a: &[f32], b: &[f32]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(x, y)| (f64::from(*x) - f64::from(*y)).powi(2))
        .sum::<f64>()
        .sqrt()
}

fn score_for(metric: &str, a: &[f32], b: &[f32]) -> Result<f64> {
    match metric {
        "cosine" => Ok(cosine_score(a, b)),
        "dot" => Ok(dot_score(a, b)),
        "euclidean" => Ok(-euclidean_distance(a, b)),
        other => Err(Error::Verify(format!("unsupported metric {other:?}"))),
    }
}

struct SimilarCandidate {
    delta_id: String,
    vector: Vec<u8>,
    url: String,
    publisher: String,
    observed_at: String,
    weight: String,
    title: String,
    r#abstract: Option<String>,
}

fn row_to_similar_candidate(row: &rusqlite::Row) -> rusqlite::Result<SimilarCandidate> {
    Ok(SimilarCandidate {
        delta_id: row.get(0)?,
        vector: row.get(1)?,
        url: row.get(2)?,
        publisher: row.get(3)?,
        observed_at: row.get(4)?,
        weight: row.get(5)?,
        title: row.get(6)?,
        r#abstract: row.get(7)?,
    })
}

fn merge(rows: Vec<(String, u64, RecordHit)>) -> Vec<MergedHit> {
    let mut by_delta: BTreeMap<String, (RecordHit, Vec<ProvEntry>)> = BTreeMap::new();
    for (log_id, synced_height, hit) in rows {
        let weight = hit.weight.clone();
        let entry = by_delta
            .entry(hit.delta_id.clone())
            .or_insert_with(|| (hit, Vec::new()));
        entry.1.push(ProvEntry {
            log_id,
            synced_height,
            weight,
        });
    }

    let mut by_url_publisher: BTreeMap<(String, String), MergedHit> = BTreeMap::new();
    for (_, (hit, mut provenance)) in by_delta {
        provenance.sort_by(|a, b| a.log_id.cmp(&b.log_id));
        let candidate = MergedHit {
            url: hit.url,
            publisher: hit.publisher,
            delta_id: hit.delta_id,
            observed_at: hit.observed_at,
            title: hit.title,
            r#abstract: hit.r#abstract,
            provenance,
        };
        let key = (candidate.url.clone(), candidate.publisher.clone());
        match by_url_publisher.get(&key) {
            Some(existing)
                if (existing.observed_at.as_str(), existing.delta_id.as_str())
                    >= (candidate.observed_at.as_str(), candidate.delta_id.as_str()) => {}
            _ => {
                by_url_publisher.insert(key, candidate);
            }
        }
    }
    by_url_publisher.into_values().collect()
}

fn read_synced_height(dir: &Path) -> Result<u64> {
    let sync_path = dir.join("sync.json");
    let bytes = std::fs::read(&sync_path).map_err(|_| Error::NotSynced(dir.to_path_buf()))?;
    let state: SyncState = serde_json::from_slice(&bytes)?;
    Ok(state.head_number)
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct DomainCoverage {
    pub domain: String,
    /// The `sealed_at` of the earliest Declaration this index holds for
    /// the domain — the instant from which its statements are covered.
    pub since: String,
    pub records: i64,
}

pub struct LogHandle {
    pub log_id: String,
    pub synced_height: u64,
    pub store: Store,
}

pub struct MultiStore {
    logs: Vec<LogHandle>,
}

impl MultiStore {
    pub fn open_read_only(dir: &Path) -> Result<MultiStore> {
        crate::registry::check_not_legacy(dir)?;
        let reg = crate::registry::load(dir)?;
        if reg.logs.is_empty() {
            return Err(Error::NotSynced(dir.to_path_buf()));
        }
        for entry in &reg.logs {
            if let Some(other) = crate::registry::find_collision(&reg.logs, &entry.log_id) {
                return Err(Error::Verify(format!(
                    "log_id {:?} sanitizes to the same directory as log_id {:?} (both -> {:?}); refusing to open the shared directory as two logs",
                    entry.log_id,
                    other.log_id,
                    crate::registry::sanitize(&entry.log_id)
                )));
            }
        }
        let mut logs = Vec::with_capacity(reg.logs.len());
        for entry in reg.logs {
            crate::registry::validate_log_id(&entry.log_id)?;
            let log_dir = crate::registry::log_dir(dir, &entry.log_id);
            let store = Store::open_read_only(&log_dir)?;
            let synced_height = read_synced_height(&log_dir)?;
            logs.push(LogHandle {
                log_id: entry.log_id,
                synced_height,
                store,
            });
        }
        Ok(MultiStore { logs })
    }

    pub fn logs(&self) -> &[LogHandle] {
        &self.logs
    }

    pub fn search(&self, q: &str, limit: usize) -> Result<Vec<MergedHit>> {
        let mut rows = Vec::new();
        for handle in &self.logs {
            for hit in handle.store.search(q, limit)? {
                rows.push((handle.log_id.clone(), handle.synced_height, hit));
            }
        }
        let mut merged = merge(rows);
        merged.truncate(limit);
        Ok(merged)
    }

    pub fn get(&self, url: &str) -> Result<Option<MergedHit>> {
        let mut rows = Vec::new();
        for handle in &self.logs {
            if let Some(hit) = handle.store.get(url)? {
                rows.push((handle.log_id.clone(), handle.synced_height, hit));
            }
        }
        Ok(merge(rows).into_iter().next())
    }

    pub fn extract(&self, url: &str) -> Result<Option<(String, Vec<ProvEntry>)>> {
        let mut rows = Vec::new();
        for handle in &self.logs {
            if let Some(row) = handle.store.extract_row(url)? {
                rows.push((handle.log_id.clone(), handle.synced_height, row));
            }
        }
        Ok(merge_extract(rows))
    }

    pub fn links(&self, url: &str) -> Result<Vec<(String, i64)>> {
        let Some((_, provenance)) = self.extract(url)? else {
            return Ok(Vec::new());
        };
        let Some(winning_log_id) = provenance.first().map(|p| p.log_id.clone()) else {
            return Ok(Vec::new());
        };
        match self.logs.iter().find(|h| h.log_id == winning_log_id) {
            Some(handle) => handle.store.links_rows(url),
            None => Ok(Vec::new()),
        }
    }

    /// Every Publisher domain the local index carries, with the earliest
    /// Declaration instant it holds for that domain and the record
    /// count, so a caller can tell whether a domain is covered at all
    /// before spending a query on it.
    pub fn coverage(&self, domain: Option<&str>) -> Result<Vec<DomainCoverage>> {
        let mut merged: BTreeMap<String, DomainCoverage> = BTreeMap::new();
        for handle in &self.logs {
            for row in handle.store.coverage(domain)? {
                merged
                    .entry(row.domain.clone())
                    .and_modify(|existing| {
                        if row.since < existing.since {
                            existing.since = row.since.clone();
                        }
                        existing.records += row.records;
                    })
                    .or_insert(row);
            }
        }
        Ok(merged.into_values().collect())
    }

    pub fn similar(&self, url: &str, k: usize) -> Result<Vec<SimilarHit>> {
        for handle in &self.logs {
            if let Some(hits) =
                handle
                    .store
                    .similar_within(url, k, &handle.log_id, handle.synced_height)?
            {
                return Ok(hits);
            }
        }
        Err(Error::Verify(format!("no embedding for url {url}")))
    }
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        let conn = Connection::open(dir.join("index.sqlite"))?;
        conn.execute(CREATE_UNIQUE_INDEX, [])?;
        Ok(Store { conn })
    }

    pub fn open_read_only(dir: &Path) -> Result<Store> {
        let path = dir.join("index.sqlite");
        if !path.exists() {
            return Err(Error::NotSynced(dir.to_path_buf()));
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Store { conn })
    }

    pub fn search(&self, q: &str, limit: usize) -> Result<Vec<RecordHit>> {
        let phrase = quote_phrase(q);
        let mut stmt = self.conn.prepare(
            "SELECT r.url, r.publisher, r.delta_id, r.observed_at, r.weight, r.title, r.abstract
             FROM records_fts f JOIN records r ON r.rowid = f.rowid
             WHERE records_fts MATCH ?1 LIMIT ?2",
        )?;
        let mut rows = stmt
            .query_map((phrase.as_str(), limit as i64), row_to_hit)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        if table_exists(&self.conn, "extracts")? {
            let mut estmt = self.conn.prepare(
                "SELECT r.url, r.publisher, r.delta_id, r.observed_at, r.weight, r.title, r.abstract
                 FROM extracts_fts f JOIN extracts e ON e.rowid = f.rowid
                 JOIN records r ON r.url = e.url AND r.publisher = e.publisher
                 WHERE extracts_fts MATCH ?1 LIMIT ?2",
            )?;
            let mut seen: std::collections::HashSet<String> =
                rows.iter().map(|h| h.delta_id.clone()).collect();
            for hit in estmt
                .query_map((phrase.as_str(), limit as i64), row_to_hit)?
                .collect::<rusqlite::Result<Vec<_>>>()?
            {
                if seen.insert(hit.delta_id.clone()) {
                    rows.push(hit);
                }
            }
        }
        Ok(rows)
    }

    pub fn coverage(&self, domain: Option<&str>) -> Result<Vec<DomainCoverage>> {
        if !table_exists(&self.conn, "declarations")? {
            return Ok(Vec::new());
        }
        let sql = "SELECT d.domain, MIN(d.sealed_at), (SELECT COUNT(*) FROM records r WHERE r.publisher = d.domain)
                   FROM declarations d GROUP BY d.domain ORDER BY d.domain";
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DomainCoverage {
                    domain: row.get(0)?,
                    since: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    records: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(match domain {
            Some(wanted) => rows.into_iter().filter(|r| r.domain == wanted).collect(),
            None => rows,
        })
    }

    pub fn get(&self, url: &str) -> Result<Option<RecordHit>> {
        self.conn
            .query_row(
                "SELECT url, publisher, delta_id, observed_at, weight, title, abstract
                 FROM records WHERE url = ?1 LIMIT 1",
                [url],
                row_to_hit,
            )
            .optional()
            .map_err(Into::into)
    }

    fn extract_row(&self, url: &str) -> Result<Option<ExtractRow>> {
        if !table_exists(&self.conn, "extracts")? {
            return Ok(None);
        }
        self.conn
            .query_row(
                "SELECT e.extract, e.delta_id, r.observed_at, r.weight
                 FROM extracts e JOIN records r ON r.url = e.url AND r.publisher = e.publisher
                 WHERE e.url = ?1 LIMIT 1",
                [url],
                |row| {
                    Ok(ExtractRow {
                        extract: row.get(0)?,
                        delta_id: row.get(1)?,
                        observed_at: row.get(2)?,
                        weight: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn links_rows(&self, url: &str) -> Result<Vec<(String, i64)>> {
        if !table_exists(&self.conn, "links")? {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn.prepare(
            "SELECT target_url, position FROM links WHERE source_url = ?1 ORDER BY position",
        )?;
        let rows = stmt
            .query_map([url], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn similar_within(
        &self,
        url: &str,
        k: usize,
        log_id: &str,
        synced_height: u64,
    ) -> Result<Option<Vec<SimilarHit>>> {
        if !table_exists(&self.conn, "embeddings")? {
            return Ok(None);
        }
        let metric: Option<String> = self
            .conn
            .query_row("SELECT metric FROM pack_meta WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(metric) = metric else {
            return Ok(None);
        };

        let target: Option<(String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT delta_id, vector FROM embeddings WHERE url = ?1 LIMIT 1",
                [url],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((self_delta_id, target_blob)) = target else {
            return Ok(None);
        };
        let target_vec = blob_to_vec(&target_blob)?;

        let mut stmt = self.conn.prepare(
            "SELECT e.delta_id, e.vector, r.url, r.publisher, r.observed_at, r.weight, r.title, r.abstract
             FROM embeddings e JOIN records r ON r.delta_id = e.delta_id",
        )?;
        let candidates = stmt
            .query_map([], row_to_similar_candidate)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut scored: Vec<(f64, SimilarCandidate)> = Vec::new();
        for candidate in candidates {
            if candidate.delta_id == self_delta_id {
                continue;
            }
            let vector = blob_to_vec(&candidate.vector)?;
            let score = score_for(&metric, &target_vec, &vector)?;
            scored.push((score, candidate));
        }

        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.delta_id.cmp(&b.1.delta_id))
        });
        scored.truncate(k);

        Ok(Some(
            scored
                .into_iter()
                .map(|(score, candidate)| SimilarHit {
                    hit: MergedHit {
                        url: candidate.url,
                        publisher: candidate.publisher,
                        delta_id: candidate.delta_id,
                        observed_at: candidate.observed_at,
                        title: candidate.title,
                        r#abstract: candidate.r#abstract,
                        provenance: vec![ProvEntry {
                            log_id: log_id.to_string(),
                            synced_height,
                            weight: candidate.weight,
                        }],
                    },
                    score,
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(dir: &Path) {
        let conn = Connection::open(dir.join("index.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE records(url TEXT, publisher TEXT, delta_id TEXT, observed_at TEXT, weight TEXT, title TEXT, abstract TEXT, lang TEXT);
             CREATE VIRTUAL TABLE records_fts USING fts5(title, abstract, content=records, content_rowid=rowid);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                "https://example.com/alpha",
                "example.com",
                "sha256:a",
                "2026-08-09T00:00:00Z",
                "full",
                "Alpha Title",
                Some("Alpha abstract text"),
                "en",
            ),
        )
        .unwrap();
        conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])
            .unwrap();
    }

    #[test]
    fn open_adds_unique_index_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path());
        Store::open(tmp.path()).unwrap();
        Store::open(tmp.path()).unwrap();
    }

    #[test]
    fn search_matches_title_via_fts() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path());
        let store = Store::open(tmp.path()).unwrap();
        let hits = store.search("Alpha", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].url, "https://example.com/alpha");
        assert_eq!(hits[0].title, "Alpha Title");
        assert_eq!(hits[0].r#abstract.as_deref(), Some("Alpha abstract text"));
        assert!(store.search("nonexistent-term", 10).unwrap().is_empty());
    }

    #[test]
    fn get_returns_none_for_unknown_url() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path());
        let store = Store::open(tmp.path()).unwrap();
        assert!(store.get("https://example.com/nope").unwrap().is_none());
        let hit = store.get("https://example.com/alpha").unwrap().unwrap();
        assert_eq!(hit.publisher, "example.com");
        assert_eq!(hit.weight, "full");
    }

    #[test]
    fn search_with_fts5_operator_input_returns_empty_not_error() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path());
        let store = Store::open(tmp.path()).unwrap();
        let hits = store.search("alpha AND", 10).unwrap();
        assert!(hits.is_empty());
        let hits = store.search("title:foo OR bar*", 10).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn open_read_only_rejects_fresh_dir_with_clear_error() {
        let tmp = tempfile::tempdir().unwrap();
        let Err(err) = Store::open_read_only(tmp.path()) else {
            panic!("expected NotSynced error");
        };
        assert!(err.to_string().contains("run `graven sync` first"));
    }

    #[test]
    fn open_read_only_serves_existing_index() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path());
        let store = Store::open_read_only(tmp.path()).unwrap();
        let hits = store.search("Alpha", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(store.get("https://example.com/alpha").unwrap().is_some());
    }

    fn hit(url: &str, delta_id: &str, observed_at: &str, weight: &str) -> RecordHit {
        RecordHit {
            url: url.into(),
            publisher: "example.com".into(),
            delta_id: delta_id.into(),
            observed_at: observed_at.into(),
            weight: weight.into(),
            title: "T".into(),
            r#abstract: None,
        }
    }

    #[test]
    fn same_delta_in_two_logs_merges_to_one_hit() {
        let rows = vec![
            (
                "log-b".to_string(),
                5u64,
                hit(
                    "https://example.com/a",
                    "sha256:same",
                    "2026-08-09T12:00:00Z",
                    "reduced",
                ),
            ),
            (
                "log-a".to_string(),
                3u64,
                hit(
                    "https://example.com/a",
                    "sha256:same",
                    "2026-08-09T12:00:00Z",
                    "full",
                ),
            ),
        ];
        let merged = merge(rows);
        assert_eq!(merged.len(), 1);
        let m = &merged[0];
        assert_eq!(m.provenance.len(), 2);
        assert_eq!(m.provenance[0].log_id, "log-a");
        assert_eq!(m.provenance[0].synced_height, 3);
        assert_eq!(m.provenance[0].weight, "full");
        assert_eq!(m.provenance[1].log_id, "log-b");
        assert_eq!(m.provenance[1].synced_height, 5);
        assert_eq!(m.provenance[1].weight, "reduced");
    }

    #[test]
    fn same_url_different_delta_ids_prefers_latest_observed_at() {
        let rows = vec![
            (
                "log-a".to_string(),
                3u64,
                hit(
                    "https://example.com/a",
                    "sha256:stale",
                    "2026-08-09T12:00:00Z",
                    "full",
                ),
            ),
            (
                "log-b".to_string(),
                5u64,
                hit(
                    "https://example.com/a",
                    "sha256:fresh",
                    "2026-08-09T13:00:00Z",
                    "full",
                ),
            ),
        ];
        let merged = merge(rows);
        assert_eq!(merged.len(), 1);
        let m = &merged[0];
        assert_eq!(m.delta_id, "sha256:fresh");
        assert_eq!(m.provenance.len(), 1);
        assert_eq!(m.provenance[0].log_id, "log-b");
    }

    #[test]
    fn tie_on_observed_at_breaks_by_delta_id() {
        let rows = vec![
            (
                "log-a".to_string(),
                3u64,
                hit(
                    "https://example.com/a",
                    "sha256:aaa",
                    "2026-08-09T12:00:00Z",
                    "full",
                ),
            ),
            (
                "log-b".to_string(),
                5u64,
                hit(
                    "https://example.com/a",
                    "sha256:bbb",
                    "2026-08-09T12:00:00Z",
                    "full",
                ),
            ),
        ];
        let merged = merge(rows);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].delta_id, "sha256:bbb");
    }

    fn seed_row(
        log_dir: &Path,
        url: &str,
        delta_id: &str,
        observed_at: &str,
        weight: &str,
        title: &str,
    ) {
        std::fs::create_dir_all(log_dir).unwrap();
        let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS records(url TEXT, publisher TEXT, delta_id TEXT, observed_at TEXT, weight TEXT, title TEXT, abstract TEXT, lang TEXT);
             CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(title, abstract, content=records, content_rowid=rowid);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang) VALUES (?1, 'example.com', ?2, ?3, ?4, ?5, NULL, 'en')",
            (url, delta_id, observed_at, weight, title),
        )
        .unwrap();
        conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])
            .unwrap();
    }

    fn seed_tier1_row(
        log_dir: &Path,
        url: &str,
        delta_id: &str,
        extract: &str,
        links: &[(&str, i64)],
    ) {
        std::fs::create_dir_all(log_dir).unwrap();
        let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
        conn.execute_batch(CREATE_TIER1).unwrap();
        conn.execute(
            "INSERT INTO extracts(url, publisher, delta_id, extract) VALUES (?1, 'example.com', ?2, ?3)",
            (url, delta_id, extract),
        )
        .unwrap();
        for (target, position) in links {
            conn.execute(
                "INSERT INTO links(source_url, target_url, position) VALUES (?1, ?2, ?3)",
                (url, target, position),
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )
        .unwrap();
    }

    fn seed_sync(log_dir: &Path, height: u64) {
        std::fs::write(
            log_dir.join("sync.json"),
            serde_json::to_vec(&SyncState {
                log_position: 0,
                head_number: height,
                head_hash: "sha256:deadbeef".into(),
                content_digest: None,
            })
            .unwrap(),
        )
        .unwrap();
    }

    fn seed_registry(dir: &Path, log_ids: &[&str]) {
        let logs = log_ids
            .iter()
            .map(|id| crate::registry::LogEntry {
                log_id: id.to_string(),
                anchor: format!("anchor-{id}"),
                base: format!("https://{id}.example"),
                tier1: false,
            })
            .collect();
        crate::registry::save(dir, &crate::registry::Registry { logs }).unwrap();
    }

    #[test]
    fn multi_store_search_merges_hits_across_logs() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        let log_b = crate::registry::log_dir(tmp.path(), "log-b");
        seed_row(
            &log_a,
            "https://example.com/alpha",
            "sha256:same",
            "2026-08-09T00:00:00Z",
            "full",
            "Alpha Title",
        );
        seed_sync(&log_a, 3);
        seed_row(
            &log_b,
            "https://example.com/alpha",
            "sha256:same",
            "2026-08-09T00:00:00Z",
            "reduced",
            "Alpha Title",
        );
        seed_sync(&log_b, 5);
        seed_registry(tmp.path(), &["log-a", "log-b"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let hits = store.search("Alpha", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].provenance.len(), 2);
        assert_eq!(hits[0].provenance[0].log_id, "log-a");
        assert_eq!(hits[0].provenance[0].weight, "full");
        assert_eq!(hits[0].provenance[1].log_id, "log-b");
        assert_eq!(hits[0].provenance[1].weight, "reduced");

        let record = store.get("https://example.com/alpha").unwrap().unwrap();
        assert_eq!(record.provenance.len(), 2);
    }

    #[test]
    fn multi_store_search_truncates_after_merging() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        seed_row(
            &log_a,
            "https://example.com/alpha",
            "sha256:a",
            "2026-08-09T00:00:00Z",
            "full",
            "Match One",
        );
        seed_row(
            &log_a,
            "https://example.com/beta",
            "sha256:b",
            "2026-08-09T01:00:00Z",
            "full",
            "Match Two",
        );
        seed_sync(&log_a, 1);
        seed_registry(tmp.path(), &["log-a"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let hits = store.search("Match", 1).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn multi_store_open_read_only_errors_when_registry_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let Err(err) = MultiStore::open_read_only(tmp.path()) else {
            panic!("expected NotSynced error");
        };
        assert!(err.to_string().contains("run `graven sync` first"));
    }

    #[test]
    fn multi_store_open_read_only_errors_on_legacy_layout() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("index.sqlite"), b"").unwrap();
        std::fs::write(tmp.path().join("sync.json"), b"{}").unwrap();
        let Err(err) = MultiStore::open_read_only(tmp.path()) else {
            panic!("expected legacy layout error");
        };
        assert!(err.to_string().contains("run `graven sync --anchor"));
    }

    #[test]
    fn multi_store_open_read_only_rejects_a_hand_edited_unsafe_log_id() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("logs")).unwrap();
        seed(tmp.path());
        std::fs::write(
            tmp.path().join("sync.json"),
            serde_json::to_vec(&SyncState {
                log_position: 0,
                head_number: 1,
                head_hash: "sha256:deadbeef".into(),
                content_digest: None,
            })
            .unwrap(),
        )
        .unwrap();
        crate::registry::save(
            tmp.path(),
            &crate::registry::Registry {
                logs: vec![crate::registry::LogEntry {
                    log_id: "..".into(),
                    anchor: "anchor.json".into(),
                    base: "https://log.example".into(),
                    tier1: false,
                }],
            },
        )
        .unwrap();

        let Err(err) = MultiStore::open_read_only(tmp.path()) else {
            panic!(
                "expected an error rejecting the unsafe log_id, not a silently opened store over {}",
                tmp.path().display()
            );
        };
        assert!(err.to_string().contains(".."), "error was: {err}");
    }

    #[test]
    fn multi_store_open_read_only_rejects_hand_edited_sanitized_dir_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let log_dir = crate::registry::log_dir(tmp.path(), "host-9");
        seed_row(
            &log_dir,
            "https://example.com/alpha",
            "sha256:a",
            "2026-08-09T00:00:00Z",
            "full",
            "Alpha Title",
        );
        seed_sync(&log_dir, 1);
        crate::registry::save(
            tmp.path(),
            &crate::registry::Registry {
                logs: vec![
                    crate::registry::LogEntry {
                        log_id: "host-9".into(),
                        anchor: "anchor-a.json".into(),
                        base: "https://host-9.example".into(),
                        tier1: false,
                    },
                    crate::registry::LogEntry {
                        log_id: "host:9".into(),
                        anchor: "anchor-b.json".into(),
                        base: "https://host-b.example".into(),
                        tier1: false,
                    },
                ],
            },
        )
        .unwrap();

        let Err(err) = MultiStore::open_read_only(tmp.path()) else {
            panic!("expected an error rejecting the sanitized-directory collision");
        };
        assert!(
            err.to_string().contains("host-9") && err.to_string().contains("host:9"),
            "error was: {err}"
        );
    }

    #[test]
    fn multi_store_logs_exposes_log_id_and_synced_height() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        seed_row(
            &log_a,
            "https://example.com/alpha",
            "sha256:a",
            "2026-08-09T00:00:00Z",
            "full",
            "Alpha Title",
        );
        seed_sync(&log_a, 4);
        seed_registry(tmp.path(), &["log-a"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        assert_eq!(store.logs().len(), 1);
        assert_eq!(store.logs()[0].log_id, "log-a");
        assert_eq!(store.logs()[0].synced_height, 4);
    }

    #[test]
    fn search_matches_extract_only_text_via_fts() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path());
        seed_tier1_row(
            tmp.path(),
            "https://example.com/alpha",
            "sha256:a",
            "distinctive extract payload",
            &[],
        );
        let store = Store::open(tmp.path()).unwrap();
        let hits = store.search("distinctive extract", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].url, "https://example.com/alpha");
    }

    #[test]
    fn search_dedupes_records_and_extracts_fts_hit_for_same_delta() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path());
        seed_tier1_row(
            tmp.path(),
            "https://example.com/alpha",
            "sha256:a",
            "the extract also mentions Alpha Title verbatim",
            &[],
        );
        let store = Store::open(tmp.path()).unwrap();
        let hits = store.search("Alpha Title", 10).unwrap();
        assert_eq!(
            hits.len(),
            1,
            "a record matching both records_fts and extracts_fts must appear once"
        );
    }

    #[test]
    fn multi_store_extract_prefers_latest_delta_across_logs() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        let log_b = crate::registry::log_dir(tmp.path(), "log-b");

        seed_row(
            &log_a,
            "https://example.com/alpha",
            "sha256:stale",
            "2026-08-09T12:00:00Z",
            "full",
            "Alpha Title",
        );
        seed_tier1_row(
            &log_a,
            "https://example.com/alpha",
            "sha256:stale",
            "stale extract",
            &[("https://example.com/stale-link", 0)],
        );
        seed_sync(&log_a, 3);

        seed_row(
            &log_b,
            "https://example.com/alpha",
            "sha256:fresh",
            "2026-08-09T13:00:00Z",
            "full",
            "Alpha Title",
        );
        seed_tier1_row(
            &log_b,
            "https://example.com/alpha",
            "sha256:fresh",
            "fresh extract",
            &[("https://example.com/fresh-link", 0)],
        );
        seed_sync(&log_b, 5);

        seed_registry(tmp.path(), &["log-a", "log-b"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let (extract, provenance) = store.extract("https://example.com/alpha").unwrap().unwrap();
        assert_eq!(extract, "fresh extract");
        assert_eq!(provenance.len(), 1);
        assert_eq!(provenance[0].log_id, "log-b");

        let links = store.links("https://example.com/alpha").unwrap();
        assert_eq!(
            links,
            vec![("https://example.com/fresh-link".to_string(), 0)]
        );
    }

    fn vector_blob(v: &[f32]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(v.len() * 4);
        for x in v {
            blob.extend_from_slice(&x.to_le_bytes());
        }
        blob
    }

    fn seed_embeddings(log_dir: &Path, metric: &str, dim: i64, rows: &[(&str, &str, &[f32])]) {
        std::fs::create_dir_all(log_dir).unwrap();
        let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
        conn.execute_batch(CREATE_EMBEDDINGS).unwrap();
        for (delta_id, url, vector) in rows {
            conn.execute(
                "INSERT INTO embeddings(delta_id, url, publisher, vector) VALUES (?1, ?2, 'example.com', ?3)",
                (*delta_id, *url, vector_blob(vector)),
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO pack_meta(id, model_json, metric, dim, imported_at, key_b64u) VALUES (1, '{}', ?1, ?2, 'now', 'key')",
            (metric, dim),
        )
        .unwrap();
    }

    fn seed_four_cosine_records(log_dir: &Path) {
        seed_row(
            log_dir,
            "https://example.com/a",
            "sha256:a",
            "2026-08-09T00:00:00Z",
            "full",
            "A",
        );
        seed_row(
            log_dir,
            "https://example.com/b",
            "sha256:b",
            "2026-08-09T00:00:00Z",
            "full",
            "B",
        );
        seed_row(
            log_dir,
            "https://example.com/c",
            "sha256:c",
            "2026-08-09T00:00:00Z",
            "full",
            "C",
        );
        seed_row(
            log_dir,
            "https://example.com/d",
            "sha256:d",
            "2026-08-09T00:00:00Z",
            "full",
            "D",
        );
        seed_embeddings(
            log_dir,
            "cosine",
            2,
            &[
                ("sha256:a", "https://example.com/a", &[1.0, 0.0]),
                ("sha256:b", "https://example.com/b", &[1.0, 1.0]),
                ("sha256:c", "https://example.com/c", &[0.0, 1.0]),
                ("sha256:d", "https://example.com/d", &[-1.0, 0.0]),
            ],
        );
    }

    #[test]
    fn cosine_score_treats_zero_norm_vector_as_zero_score() {
        assert_eq!(cosine_score(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
        assert_eq!(cosine_score(&[1.0, 1.0], &[0.0, 0.0]), 0.0);
    }

    #[test]
    fn similar_cosine_orders_by_score_descending() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        seed_four_cosine_records(&log_a);
        seed_sync(&log_a, 1);
        seed_registry(tmp.path(), &["log-a"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let hits = store.similar("https://example.com/a", 5).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].hit.delta_id, "sha256:b");
        assert!((hits[0].score - std::f64::consts::FRAC_1_SQRT_2).abs() < 1e-9);
        assert_eq!(hits[1].hit.delta_id, "sha256:c");
        assert!((hits[1].score - 0.0).abs() < 1e-9);
        assert_eq!(hits[2].hit.delta_id, "sha256:d");
        assert!((hits[2].score - (-1.0)).abs() < 1e-9);
        assert_eq!(hits[0].hit.provenance.len(), 1);
        assert_eq!(hits[0].hit.provenance[0].log_id, "log-a");
        assert_eq!(hits[0].hit.provenance[0].weight, "full");
    }

    #[test]
    fn similar_respects_k_truncation() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        seed_four_cosine_records(&log_a);
        seed_sync(&log_a, 1);
        seed_registry(tmp.path(), &["log-a"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let hits = store.similar("https://example.com/a", 1).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].hit.delta_id, "sha256:b");
    }

    #[test]
    fn similar_excludes_self() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        seed_four_cosine_records(&log_a);
        seed_sync(&log_a, 1);
        seed_registry(tmp.path(), &["log-a"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let hits = store.similar("https://example.com/a", 10).unwrap();
        assert_eq!(hits.len(), 3);
        assert!(hits.iter().all(|h| h.hit.delta_id != "sha256:a"));
    }

    #[test]
    fn similar_euclidean_orders_by_negative_distance() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        seed_row(
            &log_a,
            "https://example.com/origin",
            "sha256:origin",
            "2026-08-09T00:00:00Z",
            "full",
            "Origin",
        );
        seed_row(
            &log_a,
            "https://example.com/near",
            "sha256:near",
            "2026-08-09T00:00:00Z",
            "full",
            "Near",
        );
        seed_row(
            &log_a,
            "https://example.com/mid",
            "sha256:mid",
            "2026-08-09T00:00:00Z",
            "full",
            "Mid",
        );
        seed_row(
            &log_a,
            "https://example.com/far",
            "sha256:far",
            "2026-08-09T00:00:00Z",
            "full",
            "Far",
        );
        seed_embeddings(
            &log_a,
            "euclidean",
            2,
            &[
                ("sha256:origin", "https://example.com/origin", &[0.0, 0.0]),
                ("sha256:near", "https://example.com/near", &[1.0, 0.0]),
                ("sha256:mid", "https://example.com/mid", &[0.0, 2.0]),
                ("sha256:far", "https://example.com/far", &[3.0, 4.0]),
            ],
        );
        seed_sync(&log_a, 1);
        seed_registry(tmp.path(), &["log-a"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let hits = store.similar("https://example.com/origin", 5).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].hit.delta_id, "sha256:near");
        assert!((hits[0].score - (-1.0)).abs() < 1e-9);
        assert_eq!(hits[1].hit.delta_id, "sha256:mid");
        assert!((hits[1].score - (-2.0)).abs() < 1e-9);
        assert_eq!(hits[2].hit.delta_id, "sha256:far");
        assert!((hits[2].score - (-5.0)).abs() < 1e-9);
    }

    #[test]
    fn similar_picks_first_registry_log_with_embeddings_for_url() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        let log_b = crate::registry::log_dir(tmp.path(), "log-b");
        seed_row(
            &log_a,
            "https://example.com/other",
            "sha256:other",
            "2026-08-09T00:00:00Z",
            "full",
            "Other",
        );
        seed_sync(&log_a, 1);

        seed_row(
            &log_b,
            "https://example.com/a",
            "sha256:a",
            "2026-08-09T00:00:00Z",
            "full",
            "A",
        );
        seed_row(
            &log_b,
            "https://example.com/b",
            "sha256:b",
            "2026-08-09T00:00:00Z",
            "full",
            "B",
        );
        seed_embeddings(
            &log_b,
            "cosine",
            2,
            &[
                ("sha256:a", "https://example.com/a", &[1.0, 0.0]),
                ("sha256:b", "https://example.com/b", &[1.0, 0.0]),
            ],
        );
        seed_sync(&log_b, 2);
        seed_registry(tmp.path(), &["log-a", "log-b"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let hits = store.similar("https://example.com/a", 5).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].hit.provenance[0].log_id, "log-b");
    }

    #[test]
    fn similar_errors_when_no_log_has_the_url() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        seed_row(
            &log_a,
            "https://example.com/a",
            "sha256:a",
            "2026-08-09T00:00:00Z",
            "full",
            "A",
        );
        seed_sync(&log_a, 1);
        seed_registry(tmp.path(), &["log-a"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        let Err(err) = store.similar("https://example.com/nope", 5) else {
            panic!("expected an error for a url with no embedding in any log");
        };
        assert!(err.to_string().contains("no embedding for url"));
    }

    #[test]
    fn multi_store_extract_and_links_are_empty_when_no_tier1_data() {
        let tmp = tempfile::tempdir().unwrap();
        let log_a = crate::registry::log_dir(tmp.path(), "log-a");
        seed_row(
            &log_a,
            "https://example.com/alpha",
            "sha256:a",
            "2026-08-09T00:00:00Z",
            "full",
            "Alpha Title",
        );
        seed_sync(&log_a, 1);
        seed_registry(tmp.path(), &["log-a"]);

        let store = MultiStore::open_read_only(tmp.path()).unwrap();
        assert!(store
            .extract("https://example.com/alpha")
            .unwrap()
            .is_none());
        assert!(store.links("https://example.com/alpha").unwrap().is_empty());
    }
}
