use crate::error::Result;
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

pub const CREATE_UNIQUE_INDEX: &str =
    "CREATE UNIQUE INDEX IF NOT EXISTS records_url_publisher ON records(url, publisher)";

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

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store> {
        let conn = Connection::open(dir.join("index.sqlite"))?;
        conn.execute(CREATE_UNIQUE_INDEX, [])?;
        Ok(Store { conn })
    }

    pub fn search(&self, q: &str, limit: usize) -> Result<Vec<RecordHit>> {
        let phrase = format!("\"{}\"", q.replace('"', "\"\""));
        let mut stmt = self.conn.prepare(
            "SELECT r.url, r.publisher, r.delta_id, r.observed_at, r.weight, r.title, r.abstract
             FROM records_fts f JOIN records r ON r.rowid = f.rowid
             WHERE records_fts MATCH ?1 LIMIT ?2",
        )?;
        let rows = stmt
            .query_map((phrase, limit as i64), row_to_hit)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
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
}
