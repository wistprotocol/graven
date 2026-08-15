use crate::error::{Error, Result};
use crate::registry;
use crate::store::CREATE_EMBEDDINGS;
use crate::sync::SyncState;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::envelope::verify_envelope;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackModel {
    pub name: String,
    pub version: String,
    pub weights_hash: String,
    pub dim: u32,
    pub quantization: String,
    pub metric: String,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackVectors {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub wist_version: String,
    pub content_digest: String,
    pub log_position: u64,
    pub model: PackModel,
    pub vectors: PackVectors,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackEnvelope {
    pub pack: Pack,
    pub sig: wist_core::objects::Sig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorRow {
    delta_id: String,
    url: String,
    publisher: String,
    vector: Vec<f32>,
}

#[derive(Debug)]
pub struct ImportReport {
    pub imported: u64,
    pub skipped: u64,
}

const VALID_METRICS: [&str; 3] = ["cosine", "dot", "euclidean"];

fn validate_metric(metric: &str) -> Result<()> {
    if VALID_METRICS.contains(&metric) {
        Ok(())
    } else {
        Err(Error::Verify(format!(
            "unsupported metric {metric:?}: expected one of {VALID_METRICS:?}"
        )))
    }
}

fn vector_to_blob(vector: &[f32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(vector.len() * 4);
    for v in vector {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    buf
}

fn resolve_log_dir(dir: &Path, log_id: &str) -> Result<std::path::PathBuf> {
    registry::check_not_legacy(dir)?;
    let reg = registry::load(dir)?;
    let entry = reg
        .logs
        .iter()
        .find(|e| e.log_id == log_id)
        .ok_or_else(|| {
            Error::Verify(format!(
                "log {log_id:?} is not registered in {}",
                dir.display()
            ))
        })?;
    registry::validate_log_id(&entry.log_id)?;
    Ok(registry::log_dir(dir, &entry.log_id))
}

pub fn import(dir: &Path, log_id: &str, pack_path: &Path, key_b64u: &str) -> Result<ImportReport> {
    let key = PublicKey::from_b64u(key_b64u)?;

    let bytes = std::fs::read(pack_path)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    verify_envelope(&value, "pack", &key)?;

    let envelope: PackEnvelope = serde_json::from_value(value)?;
    let pack = envelope.pack;
    validate_metric(&pack.model.metric)?;

    let log_dir = resolve_log_dir(dir, log_id)?;
    let sync_path = log_dir.join("sync.json");
    let sync_bytes = std::fs::read(&sync_path).map_err(|_| Error::NotSynced(log_dir.clone()))?;
    let sync_state: SyncState = serde_json::from_slice(&sync_bytes)?;

    if pack.log_position != sync_state.log_position
        || Some(pack.content_digest.clone()) != sync_state.content_digest
    {
        return Err(Error::Verify(
            "pack log_position/content_digest does not match local sync state".into(),
        ));
    }

    let base_dir = pack_path.parent().unwrap_or_else(|| Path::new("."));
    let vectors_path = base_dir.join(&pack.vectors.path);
    let compressed = std::fs::read(&vectors_path)?;
    if compressed.len() as u64 != pack.vectors.bytes {
        return Err(Error::Verify(format!(
            "vectors byte length mismatch: expected {}, got {}",
            pack.vectors.bytes,
            compressed.len()
        )));
    }
    if hex_encode(&Sha256::digest(&compressed)) != pack.vectors.sha256 {
        return Err(Error::Verify("vectors sha256 mismatch".into()));
    }

    let decoded = zstd::decode_all(compressed.as_slice())
        .map_err(|e| Error::Verify(format!("zstd decode of vectors file: {e}")))?;
    let text = String::from_utf8(decoded)
        .map_err(|e| Error::Verify(format!("vectors file is not valid UTF-8: {e}")))?;
    let rows: Vec<VectorRow> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(Error::from))
        .collect::<Result<_>>()?;

    if rows.len() as u64 != pack.vectors.count {
        return Err(Error::Verify(format!(
            "vectors row count mismatch: expected {}, got {}",
            pack.vectors.count,
            rows.len()
        )));
    }
    for row in &rows {
        if row.vector.len() != pack.model.dim as usize {
            return Err(Error::Verify(format!(
                "vector for {} has length {}, expected dim {}",
                row.delta_id,
                row.vector.len(),
                pack.model.dim
            )));
        }
    }

    let index_path = log_dir.join("index.sqlite");
    let conn = Connection::open(&index_path)?;
    let mut stmt = conn.prepare("SELECT delta_id FROM records")?;
    let known: HashSet<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;
    drop(stmt);

    let mut imported_rows = Vec::new();
    let mut skipped = 0u64;
    for row in rows {
        if known.contains(&row.delta_id) {
            imported_rows.push(row);
        } else {
            skipped += 1;
        }
    }

    if imported_rows.is_empty() {
        return Err(Error::Verify("pack matches no local record".into()));
    }

    conn.execute_batch(CREATE_EMBEDDINGS)?;
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM embeddings", [])?;
    for row in &imported_rows {
        tx.execute(
            "INSERT OR REPLACE INTO embeddings(delta_id, url, publisher, vector) VALUES (?1, ?2, ?3, ?4)",
            (
                &row.delta_id,
                &row.url,
                &row.publisher,
                vector_to_blob(&row.vector),
            ),
        )?;
    }
    let model_json = serde_json::to_string(&pack.model)?;
    let imported_at = jiff::Timestamp::now().to_string();
    tx.execute(
        "INSERT OR REPLACE INTO pack_meta(id, model_json, metric, dim, imported_at, key_b64u) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        (
            &model_json,
            &pack.model.metric,
            pack.model.dim as i64,
            &imported_at,
            key_b64u,
        ),
    )?;
    tx.commit()?;

    Ok(ImportReport {
        imported: imported_rows.len() as u64,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_metric_accepts_known_metrics() {
        assert!(validate_metric("cosine").is_ok());
        assert!(validate_metric("dot").is_ok());
        assert!(validate_metric("euclidean").is_ok());
    }

    #[test]
    fn validate_metric_rejects_unknown_metric() {
        let err = validate_metric("manhattan").unwrap_err();
        assert!(err.to_string().contains("manhattan"));
    }

    #[test]
    fn vector_to_blob_encodes_little_endian_f32() {
        let blob = vector_to_blob(&[1.0f32, -2.5f32]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&1.0f32.to_le_bytes());
        expected.extend_from_slice(&(-2.5f32).to_le_bytes());
        assert_eq!(blob, expected);
    }

    #[test]
    fn vector_row_rejects_unknown_fields() {
        let json = r#"{"delta_id":"sha256:a","url":"https://x","publisher":"x.example","vector":[0.1],"extra":true}"#;
        assert!(serde_json::from_str::<VectorRow>(json).is_err());
    }
}
