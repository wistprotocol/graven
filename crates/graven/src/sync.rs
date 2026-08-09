use crate::error::{Error, Result};
use crate::fetch::{resolve, Client};
use crate::store::CREATE_UNIQUE_INDEX;
use reqwest::Url;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use wist_core::block::{block_hash, verify_block, verify_chain_link, verify_checkpoint_binding};
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::delta::{content_bytes, delta_id, verify_commitment};
use wist_core::envelope::verify_envelope;
use wist_core::objects::{
    ChangeType, CheckpointEnvelope, DeltaEnvelope, DeltaPayloadCommitment, LogAnchorEnvelope,
    Payload, SnapshotIndexEnvelope, SnapshotManifestEnvelope, SnapshotStateEnvelope,
};
use wist_core::snapshot::{content_digest, state_digest};

#[derive(Debug, Clone, Copy)]
pub struct SyncReport {
    pub log_position_before: Option<u64>,
    pub head: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncState {
    pub log_position: u64,
    pub head_number: u64,
    pub head_hash: String,
}

struct TempFileGuard<'a> {
    path: &'a Path,
    active: bool,
}

impl<'a> TempFileGuard<'a> {
    fn new(path: &'a Path) -> Self {
        TempFileGuard { path, active: true }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

fn verify_file_integrity(
    bytes: &[u8],
    expected_sha256_hex: &str,
    expected_bytes: u64,
) -> Result<()> {
    if bytes.len() as u64 != expected_bytes {
        return Err(Error::Verify(format!(
            "byte length mismatch: expected {expected_bytes}, got {}",
            bytes.len()
        )));
    }
    if hex_encode(&Sha256::digest(bytes)) != expected_sha256_hex {
        return Err(Error::Verify("sha256 mismatch".into()));
    }
    Ok(())
}

fn load_anchor_bytes(spec: &str, client: &Client) -> Result<Vec<u8>> {
    if let Ok(url) = Url::parse(spec) {
        if url.scheme() == "http" || url.scheme() == "https" {
            return client.get_bytes(&url);
        }
    }
    Ok(std::fs::read(spec)?)
}

fn recompute_content_digest(sqlite_path: &Path) -> Result<String> {
    let conn = Connection::open(sqlite_path)?;
    let mut stmt =
        conn.prepare("SELECT url, publisher, delta_id, observed_at, weight FROM records")?;
    let records = stmt
        .query_map([], |row| {
            Ok(serde_json::json!({
                "url": row.get::<_, String>(0)?,
                "publisher": row.get::<_, String>(1)?,
                "delta_id": row.get::<_, String>(2)?,
                "observed_at": row.get::<_, String>(3)?,
                "weight": row.get::<_, String>(4)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<Value>>>()?;
    Ok(content_digest(&records)?)
}

fn fetch_payload(
    client: &Client,
    base: &Url,
    hex: &str,
    commitment: &DeltaPayloadCommitment,
) -> Result<(String, Option<String>)> {
    let url = resolve(base, &format!("/payloads/{hex}.json"))?;
    let (_, value) = client.get_json(&url)?;
    let payload: Payload = serde_json::from_value(value.clone())?;
    verify_commitment(&payload.salt, &value["content"], &commitment.commitment)?;
    if content_bytes(&value["content"])? != commitment.bytes {
        return Err(Error::Verify("payload content bytes mismatch".into()));
    }
    Ok((
        payload.content.summary.title,
        payload.content.summary.r#abstract,
    ))
}

fn url_authority(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

struct BlockWalk {
    delta_bodies: Vec<Value>,
    last_block_value: Option<Value>,
}

fn walk_blocks(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    start_number: u64,
    end_number: u64,
    start_hash: &str,
) -> Result<BlockWalk> {
    let mut prev_hash = start_hash.to_string();
    let mut last_block_value: Option<Value> = None;
    let mut delta_bodies: Vec<Value> = Vec::new();
    for n in start_number..=end_number {
        let block_url = resolve(base, &format!("/log/blocks/{n:09}.json.zst"))?;
        let compressed = client.get_bytes(&block_url)?;
        let decompressed = zstd::decode_all(compressed.as_slice())
            .map_err(|e| Error::Verify(format!("zstd decode of block {n}: {e}")))?;
        let block_value: Value = serde_json::from_slice(&decompressed)?;
        verify_block(&block_value, trust_key)?;
        let header = block_value
            .get("header")
            .ok_or_else(|| Error::Verify(format!("block {n} missing header")))?;
        verify_chain_link(header, &prev_hash)?;
        prev_hash = block_hash(header)?;
        for entry in block_value
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if entry.get("type").and_then(Value::as_str) == Some("publisher_delta") {
                if let Some(delta_entry_body) = entry.get("body") {
                    delta_bodies.push(delta_entry_body.clone());
                }
            }
        }
        last_block_value = Some(block_value);
    }
    Ok(BlockWalk {
        delta_bodies,
        last_block_value,
    })
}

fn load_trust_key(anchor: &str, client: &Client) -> Result<PublicKey> {
    let anchor_bytes = load_anchor_bytes(anchor, client)?;
    let anchor_value: Value = serde_json::from_slice(&anchor_bytes)?;
    let anchor_env: LogAnchorEnvelope = serde_json::from_value(anchor_value.clone())?;
    let trust_key = PublicKey::from_b64u(&anchor_env.anchor.genesis_key.public_key)?;
    verify_envelope(&anchor_value, "anchor", &trust_key)?;
    Ok(trust_key)
}

fn apply_post_snapshot_deltas(
    conn: &Connection,
    client: &Client,
    base: &Url,
    delta_bodies: Vec<Value>,
) -> Result<()> {
    for body in delta_bodies {
        let Some(delta_body) = body.get("delta") else {
            continue;
        };
        let Ok(env) = serde_json::from_value::<DeltaEnvelope>(body.clone()) else {
            continue;
        };
        let delta = env.delta;
        if !matches!(delta.change_type, ChangeType::New | ChangeType::Update) {
            continue;
        }
        let Ok(id) = delta_id(delta_body) else {
            continue;
        };
        let Some(hex) = id.strip_prefix("sha256:") else {
            continue;
        };
        let Some(publisher) = Url::parse(&delta.url).ok().as_ref().and_then(url_authority) else {
            continue;
        };

        let (title, abstract_text) = match &delta.payload {
            Some(commitment) => {
                fetch_payload(client, base, hex, commitment).unwrap_or((String::new(), None))
            }
            None => (String::new(), None),
        };

        conn.execute(
            "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang)
             VALUES (?1, ?2, ?3, ?4, 'full', ?5, ?6, ?7)
             ON CONFLICT(url, publisher) DO UPDATE SET
                delta_id = excluded.delta_id, observed_at = excluded.observed_at,
                weight = excluded.weight, title = excluded.title,
                abstract = excluded.abstract, lang = excluded.lang",
            (
                &delta.url,
                &publisher,
                &id,
                &delta.observed_at,
                &title,
                &abstract_text,
                &delta.meta.lang,
            ),
        )?;
    }
    Ok(())
}

pub fn run(anchor: &str, log_base: &str, dir: &Path, allow_http: bool) -> Result<SyncReport> {
    std::fs::create_dir_all(dir)?;
    let sync_path = dir.join("sync.json");

    let client = Client::new(allow_http);
    let base = crate::fetch::parse_base(log_base)?;
    let trust_key = load_trust_key(anchor, &client)?;

    if sync_path.exists() {
        run_incremental(&client, &base, &trust_key, dir, &sync_path)
    } else {
        run_cold_start(&client, &base, &trust_key, dir, &sync_path)
    }
}

fn run_incremental(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    dir: &Path,
    sync_path: &Path,
) -> Result<SyncReport> {
    let sync_bytes = std::fs::read(sync_path)?;
    let local: SyncState = serde_json::from_slice(&sync_bytes)?;

    let checkpoint_url = resolve(base, "/log/checkpoint.json")?;
    let (_, checkpoint_value) = client.get_json(&checkpoint_url)?;
    verify_envelope(&checkpoint_value, "checkpoint", trust_key)?;
    let checkpoint_env: CheckpointEnvelope = serde_json::from_value(checkpoint_value.clone())?;
    let checkpoint = checkpoint_env.checkpoint;

    if checkpoint.block_number < local.head_number {
        return Err(Error::Verify(format!(
            "rollback rejected: remote checkpoint head {} is behind local head {}",
            checkpoint.block_number, local.head_number
        )));
    }

    if checkpoint.block_number == local.head_number {
        if checkpoint.block_hash == local.head_hash {
            return Ok(SyncReport {
                log_position_before: Some(local.head_number),
                head: local.head_number,
            });
        }
        return Err(Error::Verify(format!(
            "checkpoint equivocation: block {} has hash {} locally but remote reports {}",
            local.head_number, local.head_hash, checkpoint.block_hash
        )));
    }

    let walk = walk_blocks(
        client,
        base,
        trust_key,
        local.head_number + 1,
        checkpoint.block_number,
        &local.head_hash,
    )?;
    let last_block_value = walk.last_block_value.ok_or_else(|| {
        Error::Verify("continuous sync produced no blocks despite checkpoint advancing".into())
    })?;
    verify_checkpoint_binding(&checkpoint_value, &last_block_value)?;

    let index_sqlite_path = dir.join("index.sqlite");
    {
        let conn = Connection::open(&index_sqlite_path)?;
        conn.execute(CREATE_UNIQUE_INDEX, [])?;
        apply_post_snapshot_deltas(&conn, client, base, walk.delta_bodies)?;
        conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    }

    let sync_state = SyncState {
        log_position: local.log_position,
        head_number: checkpoint.block_number,
        head_hash: checkpoint.block_hash.clone(),
    };
    std::fs::write(sync_path, serde_json::to_vec(&sync_state)?)?;

    Ok(SyncReport {
        log_position_before: Some(local.head_number),
        head: checkpoint.block_number,
    })
}

fn run_cold_start(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    dir: &Path,
    sync_path: &Path,
) -> Result<SyncReport> {
    let index_url = resolve(base, "/snapshots/index.json")?;
    let (_, index_value) = client.get_json(&index_url)?;
    verify_envelope(&index_value, "index", trust_key)?;
    let index_env: SnapshotIndexEnvelope = serde_json::from_value(index_value)?;
    let newest = index_env
        .index
        .snapshots
        .into_iter()
        .next()
        .ok_or_else(|| Error::Verify("snapshot index is empty".into()))?;

    let manifest_url = resolve(base, &newest.manifest_url)?;
    let (_, manifest_value) = client.get_json(&manifest_url)?;
    verify_envelope(&manifest_value, "manifest", trust_key)?;
    let manifest_env: SnapshotManifestEnvelope = serde_json::from_value(manifest_value)?;
    let manifest = manifest_env.manifest;
    let snapshot_base = format!("/snapshots/{}/", manifest.snapshot_date);

    let state_url = resolve(base, &format!("{snapshot_base}{}", manifest.state.path))?;
    let state_bytes = client.get_bytes(&state_url)?;
    verify_file_integrity(&state_bytes, &manifest.state.sha256, manifest.state.bytes)?;
    let state_value: Value = serde_json::from_slice(&state_bytes)?;
    verify_envelope(&state_value, "state", trust_key)?;
    let state_env: SnapshotStateEnvelope = serde_json::from_value(state_value)?;
    let state_entry_values: Vec<Value> = state_env
        .state
        .entries
        .iter()
        .map(serde_json::to_value)
        .collect::<serde_json::Result<_>>()?;
    let recomputed_state_digest = state_digest(&state_entry_values)?;
    if recomputed_state_digest != manifest.state.state_digest {
        return Err(Error::Verify(
            "state_digest mismatch: recomputed state digest does not match manifest".into(),
        ));
    }

    let mut tier0_bytes: Option<Vec<u8>> = None;
    for f in &manifest.files {
        let file_url = resolve(base, &format!("{snapshot_base}{}", f.path))?;
        let bytes = client.get_bytes(&file_url)?;
        verify_file_integrity(&bytes, &f.sha256, f.bytes)?;
        if f.tier == 0 && f.path == "tier0/index.sqlite" {
            tier0_bytes = Some(bytes);
        }
    }
    let tier0_bytes = tier0_bytes
        .ok_or_else(|| Error::Verify("manifest has no tier0/index.sqlite file".into()))?;

    let tmp_sqlite_path = dir.join("index.sqlite.verifying");
    std::fs::write(&tmp_sqlite_path, &tier0_bytes)?;
    let mut guard = TempFileGuard::new(&tmp_sqlite_path);

    let recomputed_content_digest = recompute_content_digest(&tmp_sqlite_path)?;
    if recomputed_content_digest != manifest.content_digest {
        return Err(Error::Verify(
            "content_digest mismatch: recomputed tier0 digest does not match manifest".into(),
        ));
    }

    let checkpoint_url = resolve(base, "/log/checkpoint.json")?;
    let (_, checkpoint_value) = client.get_json(&checkpoint_url)?;
    verify_envelope(&checkpoint_value, "checkpoint", trust_key)?;
    let checkpoint_env: CheckpointEnvelope = serde_json::from_value(checkpoint_value.clone())?;
    let checkpoint = checkpoint_env.checkpoint;

    if manifest.log_position > checkpoint.block_number {
        return Err(Error::Verify(
            "snapshot log_position is ahead of the checkpoint head".into(),
        ));
    }

    let walk = walk_blocks(
        client,
        base,
        trust_key,
        manifest.log_position + 1,
        checkpoint.block_number,
        &manifest.anchor_block_hash,
    )?;

    match &walk.last_block_value {
        Some(block_value) => verify_checkpoint_binding(&checkpoint_value, block_value)?,
        None => {
            if checkpoint.block_number != manifest.log_position
                || checkpoint.block_hash != manifest.anchor_block_hash
            {
                return Err(Error::Verify(
                    "checkpoint does not match the snapshot anchor at equal heights".into(),
                ));
            }
        }
    }

    {
        let conn = Connection::open(&tmp_sqlite_path)?;
        conn.execute(CREATE_UNIQUE_INDEX, [])?;
        apply_post_snapshot_deltas(&conn, client, base, walk.delta_bodies)?;
        conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    }

    guard.disarm();
    let index_sqlite_path = dir.join("index.sqlite");
    std::fs::rename(&tmp_sqlite_path, &index_sqlite_path)?;

    let sync_state = SyncState {
        log_position: manifest.log_position,
        head_number: checkpoint.block_number,
        head_hash: checkpoint.block_hash.clone(),
    };
    std::fs::write(sync_path, serde_json::to_vec(&sync_state)?)?;

    Ok(SyncReport {
        log_position_before: None,
        head: checkpoint.block_number,
    })
}
