use crate::error::Error;
use crate::store::{RecordHit, Store};
use crate::sync::SyncState;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData, Json, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Provenance {
    pub log_id: String,
    pub synced_height: u64,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct RecordOut {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub observed_at: String,
    pub weight: String,
    pub title: String,
    pub r#abstract: Option<String>,
    pub provenance: Provenance,
}

fn to_record_out(hit: RecordHit, provenance: &Provenance) -> RecordOut {
    RecordOut {
        url: hit.url,
        publisher: hit.publisher,
        delta_id: hit.delta_id,
        observed_at: hit.observed_at,
        weight: hit.weight,
        title: hit.title,
        r#abstract: hit.r#abstract,
        provenance: provenance.clone(),
    }
}

fn default_limit() -> usize {
    10
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

#[derive(Clone)]
pub struct GravenServer {
    store: Arc<Mutex<Store>>,
    provenance: Provenance,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl GravenServer {
    pub fn new(store: Store, provenance: Provenance) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            provenance,
            tool_router: Self::tool_router(),
        }
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
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
        Ok(Json(
            hits.into_iter()
                .map(|h| to_record_out(h, &self.provenance))
                .collect(),
        ))
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
            Some(hit) => Ok(Json(to_record_out(hit, &self.provenance))),
            None => Err(ErrorData::resource_not_found("not found", None)),
        }
    }
}

#[tool_handler]
impl ServerHandler for GravenServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Graven: search and get_record over a local WIST index")
    }
}

pub fn load_provenance(dir: &Path, log_id: String) -> crate::error::Result<Provenance> {
    let sync_path = dir.join("sync.json");
    let bytes = std::fs::read(&sync_path).map_err(|_| Error::NotSynced(dir.to_path_buf()))?;
    let state: SyncState = serde_json::from_slice(&bytes)?;
    Ok(Provenance {
        log_id,
        synced_height: state.head_number,
    })
}

pub async fn serve_stdio(dir: &Path, log_id: String) -> crate::error::Result<()> {
    let store = Store::open_read_only(dir)?;
    let provenance = load_provenance(dir, log_id)?;
    let server = GravenServer::new(store, provenance);
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
    use rusqlite::Connection;

    fn seed_two_records(dir: &Path) {
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

    fn test_server(dir: &Path) -> GravenServer {
        seed_two_records(dir);
        let store = Store::open_read_only(dir).unwrap();
        let provenance = Provenance {
            log_id: "test-log".into(),
            synced_height: 7,
        };
        GravenServer::new(store, provenance)
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
        assert_eq!(hit.provenance.log_id, "test-log");
        assert_eq!(hit.provenance.synced_height, 7);

        let value = serde_json::to_value(&results).unwrap();
        assert!(value.is_array());
        assert_eq!(value[0]["url"], "https://example.com/alpha");
        assert_eq!(value[0]["provenance"]["log_id"], "test-log");
        assert_eq!(value[0]["provenance"]["synced_height"], 7);
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
        assert_eq!(hit.provenance.synced_height, 7);
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
    fn load_provenance_reads_synced_height_from_sync_json() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("sync.json"),
            serde_json::to_vec(&SyncState {
                log_position: 0,
                head_number: 3,
                head_hash: "sha256:deadbeef".into(),
                content_digest: None,
            })
            .unwrap(),
        )
        .unwrap();
        let provenance = load_provenance(tmp.path(), "my-log".into()).unwrap();
        assert_eq!(provenance.log_id, "my-log");
        assert_eq!(provenance.synced_height, 3);
    }

    #[test]
    fn load_provenance_errors_clearly_when_sync_json_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let Err(err) = load_provenance(tmp.path(), "my-log".into()) else {
            panic!("expected NotSynced error");
        };
        assert!(err.to_string().contains("run `graven sync` first"));
    }
}
