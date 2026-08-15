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

pub const CREATE_TIER1: &str = "CREATE TABLE IF NOT EXISTS extracts(url TEXT NOT NULL, publisher TEXT NOT NULL, delta_id TEXT NOT NULL, extract TEXT NOT NULL, PRIMARY KEY(url, publisher)); CREATE VIRTUAL TABLE IF NOT EXISTS extracts_fts USING fts5(extract, content=extracts, content_rowid=rowid); CREATE TABLE IF NOT EXISTS links(source_url TEXT NOT NULL, target_url TEXT NOT NULL, position INTEGER NOT NULL)";

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

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let hit: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(hit.is_some())
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
