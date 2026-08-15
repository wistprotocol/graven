use crate::error::Error;
use crate::store::{MergedHit, MultiStore, ProvEntry, SimilarHit};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData, Json, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RecordOut {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub observed_at: String,
    pub title: String,
    pub r#abstract: Option<String>,
    pub provenance: Vec<ProvEntry>,
}

fn to_record_out(hit: MergedHit) -> RecordOut {
    RecordOut {
        url: hit.url,
        publisher: hit.publisher,
        delta_id: hit.delta_id,
        observed_at: hit.observed_at,
        title: hit.title,
        r#abstract: hit.r#abstract,
        provenance: hit.provenance,
    }
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ExtractOut {
    pub url: String,
    pub extract: String,
    pub provenance: Vec<ProvEntry>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct LinkOut {
    pub target_url: String,
    pub position: i64,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct SimilarOut {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub title: String,
    pub score: f64,
    pub provenance: Vec<ProvEntry>,
}

fn to_similar_out(hit: SimilarHit) -> SimilarOut {
    SimilarOut {
        url: hit.hit.url,
        publisher: hit.hit.publisher,
        delta_id: hit.hit.delta_id,
        title: hit.hit.title,
        score: hit.score,
        provenance: hit.hit.provenance,
    }
}

fn default_limit() -> usize {
    10
}

fn default_k() -> usize {
    5
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    pub query: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetRecordParams {
    pub url: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SimilarParams {
    pub url: String,
    #[serde(default = "default_k")]
    pub k: usize,
}

#[derive(Clone)]
pub struct GravenServer {
    store: Arc<Mutex<MultiStore>>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl GravenServer {
    pub fn new(store: MultiStore) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            tool_router: Self::tool_router(),
        }
    }

    fn store(&self) -> std::sync::MutexGuard<'_, MultiStore> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[tool_router]
impl GravenServer {
    #[tool(description = "Full-text search the local WIST index")]
    fn search(
        &self,
        Parameters(SearchParams { query, limit }): Parameters<SearchParams>,
    ) -> std::result::Result<Json<Vec<RecordOut>>, ErrorData> {
        let hits = self
            .store()
            .search(&query, limit)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(hits.into_iter().map(to_record_out).collect()))
    }

    #[tool(description = "Fetch a single record by URL")]
    fn get_record(
        &self,
        Parameters(GetRecordParams { url }): Parameters<GetRecordParams>,
    ) -> std::result::Result<Json<RecordOut>, ErrorData> {
        let hit = self
            .store()
            .get(&url)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        match hit {
            Some(hit) => Ok(Json(to_record_out(hit))),
            None => Err(ErrorData::resource_not_found("not found", None)),
        }
    }

    #[tool(description = "Fetch the stored tier1 extract for a URL")]
    fn get_extract(
        &self,
        Parameters(GetRecordParams { url }): Parameters<GetRecordParams>,
    ) -> std::result::Result<Json<ExtractOut>, ErrorData> {
        let result = self
            .store()
            .extract(&url)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        match result {
            Some((extract, provenance)) => Ok(Json(ExtractOut {
                url,
                extract,
                provenance,
            })),
            None => Err(ErrorData::resource_not_found("no extract for url", None)),
        }
    }

    #[tool(description = "List outbound declared links for a URL")]
    fn get_links(
        &self,
        Parameters(GetRecordParams { url }): Parameters<GetRecordParams>,
    ) -> std::result::Result<Json<Vec<LinkOut>>, ErrorData> {
        let rows = self
            .store()
            .links(&url)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(
            rows.into_iter()
                .map(|(target_url, position)| LinkOut {
                    target_url,
                    position,
                })
                .collect(),
        ))
    }

    #[tool(description = "Nearest records by imported embedding pack (single-log scores)")]
    fn similar_records(
        &self,
        Parameters(SimilarParams { url, k }): Parameters<SimilarParams>,
    ) -> std::result::Result<Json<Vec<SimilarOut>>, ErrorData> {
        let hits = self.store().similar(&url, k).map_err(|e| match &e {
            Error::Verify(msg) if msg.starts_with("no embedding for url") => {
                ErrorData::resource_not_found(msg.clone(), None)
            }
            _ => ErrorData::internal_error(e.to_string(), None),
        })?;
        Ok(Json(hits.into_iter().map(to_similar_out).collect()))
    }
}

#[tool_handler]
impl ServerHandler for GravenServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Graven: search, get_record, get_extract, get_links and similar_records over a local WIST index",
        )
    }
}

pub async fn serve_stdio(dir: &Path) -> crate::error::Result<()> {
    let store = MultiStore::open_read_only(dir)?;
    let server = GravenServer::new(store);
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| Error::Mcp(format!("serve: {e}")))?;
    running
        .waiting()
        .await
        .map_err(|e| Error::Mcp(format!("wait: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{self, LogEntry, Registry};
    use crate::sync::SyncState;
    use rusqlite::Connection;
    use std::path::PathBuf;

    fn seed_two_records(log_dir: &Path) {
        std::fs::create_dir_all(log_dir).unwrap();
        let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
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
        conn.execute(
            "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                "https://example.com/beta",
                "example.com",
                "sha256:b",
                "2026-08-09T01:00:00Z",
                "full",
                "Beta Title",
                Some("Beta abstract text"),
                "en",
            ),
        )
        .unwrap();
        conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])
            .unwrap();
    }

    fn seed_tier1(log_dir: &Path) {
        let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
        conn.execute_batch(crate::store::CREATE_TIER1).unwrap();
        conn.execute(
            "INSERT INTO extracts(url, publisher, delta_id, extract) VALUES (?1, ?2, ?3, ?4)",
            (
                "https://example.com/alpha",
                "example.com",
                "sha256:a",
                "alpha body text",
            ),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO links(source_url, target_url, position) VALUES (?1, ?2, ?3)",
            (
                "https://example.com/alpha",
                "https://example.com/second",
                1i64,
            ),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO links(source_url, target_url, position) VALUES (?1, ?2, ?3)",
            (
                "https://example.com/alpha",
                "https://example.com/first",
                0i64,
            ),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )
        .unwrap();
    }

    fn setup_server_dir(dir: &Path) -> PathBuf {
        let log_dir = registry::log_dir(dir, "test-log");
        seed_two_records(&log_dir);
        std::fs::write(
            log_dir.join("sync.json"),
            serde_json::to_vec(&SyncState {
                log_position: 0,
                head_number: 7,
                head_hash: "sha256:deadbeef".into(),
                content_digest: None,
            })
            .unwrap(),
        )
        .unwrap();
        registry::save(
            dir,
            &Registry {
                logs: vec![LogEntry {
                    log_id: "test-log".into(),
                    anchor: "anchor.json".into(),
                    base: "https://log.example".into(),
                    tier1: false,
                }],
            },
        )
        .unwrap();
        log_dir
    }

    fn test_server(dir: &Path) -> GravenServer {
        setup_server_dir(dir);
        let store = MultiStore::open_read_only(dir).unwrap();
        GravenServer::new(store)
    }

    fn test_server_with_tier1(dir: &Path) -> GravenServer {
        let log_dir = setup_server_dir(dir);
        seed_tier1(&log_dir);
        let store = MultiStore::open_read_only(dir).unwrap();
        GravenServer::new(store)
    }

    fn seed_embeddings(log_dir: &Path) {
        let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
        conn.execute_batch(crate::store::CREATE_EMBEDDINGS).unwrap();
        let blob = |v: &[f32]| -> Vec<u8> {
            let mut b = Vec::with_capacity(v.len() * 4);
            for x in v {
                b.extend_from_slice(&x.to_le_bytes());
            }
            b
        };
        conn.execute(
            "INSERT INTO embeddings(delta_id, url, publisher, vector) VALUES (?1, ?2, ?3, ?4)",
            (
                "sha256:a",
                "https://example.com/alpha",
                "example.com",
                blob(&[1.0, 0.0]),
            ),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO embeddings(delta_id, url, publisher, vector) VALUES (?1, ?2, ?3, ?4)",
            (
                "sha256:b",
                "https://example.com/beta",
                "example.com",
                blob(&[1.0, 1.0]),
            ),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pack_meta(id, model_json, metric, dim, imported_at, key_b64u) VALUES (1, '{}', 'cosine', 2, 'now', 'key')",
            [],
        )
        .unwrap();
    }

    fn test_server_with_embeddings(dir: &Path) -> GravenServer {
        let log_dir = setup_server_dir(dir);
        seed_embeddings(&log_dir);
        let store = MultiStore::open_read_only(dir).unwrap();
        GravenServer::new(store)
    }

    #[test]
    fn search_returns_json_shape_with_provenance() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server(tmp.path());
        let Json(results) = server
            .search(Parameters(SearchParams {
                query: "Alpha".into(),
                limit: 10,
            }))
            .unwrap();
        assert_eq!(results.len(), 1);
        let hit = &results[0];
        assert_eq!(hit.url, "https://example.com/alpha");
        assert_eq!(hit.title, "Alpha Title");
        assert_eq!(hit.r#abstract.as_deref(), Some("Alpha abstract text"));
        assert_eq!(hit.provenance.len(), 1);
        assert_eq!(hit.provenance[0].log_id, "test-log");
        assert_eq!(hit.provenance[0].synced_height, 7);

        let value = serde_json::to_value(&results).unwrap();
        assert!(value.is_array());
        assert_eq!(value[0]["url"], "https://example.com/alpha");
        assert_eq!(value[0]["provenance"][0]["log_id"], "test-log");
        assert_eq!(value[0]["provenance"][0]["synced_height"], 7);
    }

    #[test]
    fn search_respects_default_limit_and_returns_empty_for_fts5_operators() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server(tmp.path());
        let Json(results) = server
            .search(Parameters(SearchParams {
                query: "Title".into(),
                limit: default_limit(),
            }))
            .unwrap();
        assert_eq!(results.len(), 2);

        let Json(results) = server
            .search(Parameters(SearchParams {
                query: "alpha AND".into(),
                limit: 10,
            }))
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_params_default_limit_via_serde() {
        let params: SearchParams = serde_json::from_str(r#"{"query":"x"}"#).unwrap();
        assert_eq!(params.limit, 10);
    }

    #[test]
    fn get_record_returns_record_for_known_url() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server(tmp.path());
        let Json(hit) = server
            .get_record(Parameters(GetRecordParams {
                url: "https://example.com/beta".into(),
            }))
            .unwrap();
        assert_eq!(hit.url, "https://example.com/beta");
        assert_eq!(hit.publisher, "example.com");
        assert_eq!(hit.provenance.len(), 1);
        assert_eq!(hit.provenance[0].synced_height, 7);
    }

    #[test]
    fn get_record_returns_not_found_error_for_unknown_url() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server(tmp.path());
        let Err(err) = server.get_record(Parameters(GetRecordParams {
            url: "https://example.com/nope".into(),
        })) else {
            panic!("expected resource_not_found error");
        };
        assert_eq!(err.message, "not found");
        assert_eq!(err.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
    }

    #[test]
    fn get_extract_returns_text_and_provenance() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server_with_tier1(tmp.path());
        let Json(out) = server
            .get_extract(Parameters(GetRecordParams {
                url: "https://example.com/alpha".into(),
            }))
            .unwrap();
        assert_eq!(out.url, "https://example.com/alpha");
        assert_eq!(out.extract, "alpha body text");
        assert_eq!(out.provenance.len(), 1);
        assert_eq!(out.provenance[0].log_id, "test-log");
        assert_eq!(out.provenance[0].synced_height, 7);
    }

    #[test]
    fn get_extract_unknown_url_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server_with_tier1(tmp.path());
        let Err(err) = server.get_extract(Parameters(GetRecordParams {
            url: "https://example.com/nope".into(),
        })) else {
            panic!("expected resource_not_found error");
        };
        assert_eq!(err.message, "no extract for url");
        assert_eq!(err.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
    }

    #[test]
    fn get_extract_without_tier1_data_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server(tmp.path());
        let Err(err) = server.get_extract(Parameters(GetRecordParams {
            url: "https://example.com/alpha".into(),
        })) else {
            panic!("expected resource_not_found error");
        };
        assert_eq!(err.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
    }

    #[test]
    fn get_links_returns_rows_ordered_by_position() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server_with_tier1(tmp.path());
        let Json(links) = server
            .get_links(Parameters(GetRecordParams {
                url: "https://example.com/alpha".into(),
            }))
            .unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].target_url, "https://example.com/first");
        assert_eq!(links[0].position, 0);
        assert_eq!(links[1].target_url, "https://example.com/second");
        assert_eq!(links[1].position, 1);
    }

    #[test]
    fn get_links_returns_empty_vec_not_error_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server_with_tier1(tmp.path());
        let Json(links) = server
            .get_links(Parameters(GetRecordParams {
                url: "https://example.com/beta".into(),
            }))
            .unwrap();
        assert!(links.is_empty());

        let Json(links) = server
            .get_links(Parameters(GetRecordParams {
                url: "https://example.com/nope".into(),
            }))
            .unwrap();
        assert!(links.is_empty());
    }

    #[test]
    fn search_matches_extract_only_phrase() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server_with_tier1(tmp.path());
        let Json(results) = server
            .search(Parameters(SearchParams {
                query: "alpha body".into(),
                limit: 10,
            }))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/alpha");
    }

    #[test]
    fn similar_params_default_k_via_serde() {
        let params: SimilarParams = serde_json::from_str(r#"{"url":"https://x"}"#).unwrap();
        assert_eq!(params.k, 5);
    }

    #[test]
    fn similar_records_returns_scored_results_with_provenance() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server_with_embeddings(tmp.path());
        let Json(results) = server
            .similar_records(Parameters(SimilarParams {
                url: "https://example.com/alpha".into(),
                k: default_k(),
            }))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/beta");
        assert_eq!(results[0].delta_id, "sha256:b");
        assert_eq!(results[0].provenance.len(), 1);
        assert_eq!(results[0].provenance[0].log_id, "test-log");
    }

    #[test]
    fn similar_records_returns_not_found_for_url_without_vector() {
        let tmp = tempfile::tempdir().unwrap();
        let server = test_server(tmp.path());
        let Err(err) = server.similar_records(Parameters(SimilarParams {
            url: "https://example.com/alpha".into(),
            k: default_k(),
        })) else {
            panic!("expected resource_not_found error");
        };
        assert_eq!(err.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);
    }
}
