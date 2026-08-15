use crate::error::{Error, Result};
use crate::fetch::{resolve, Client};
use crate::keyset::{url_authority, KeyHistory};
use crate::registry::{self, LogEntry};
use crate::store::{CREATE_DECLARATIONS, CREATE_UNIQUE_INDEX};
use reqwest::Url;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use wist_core::block::{block_hash, verify_block, verify_chain_link, verify_checkpoint_binding};
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::delta::{content_bytes, verify_commitment};
use wist_core::envelope::verify_envelope;
use wist_core::objects::{
    ChangeType, CheckpointEnvelope, DeltaEnvelope, DeltaPayloadCommitment, LogAnchorEnvelope,
    Payload, PublisherEnvelope, SnapshotIndexEnvelope, SnapshotManifestEnvelope,
    SnapshotStateEnvelope, StateEntry,
};
use wist_core::snapshot::{content_digest, state_digest};

#[derive(Debug, Clone)]
pub struct SyncReport {
    pub log_id: String,
    pub log_position_before: Option<u64>,
    pub head: u64,
    pub withdrawn: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncState {
    pub log_position: u64,
    pub head_number: u64,
    pub head_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
}

pub struct BlockEvent {
    pub height: u64,
    pub sealed_at: String,
    pub declarations: Vec<Value>,
    pub withdrawals: Vec<String>,
    pub delta_bodies: Vec<Value>,
}

pub struct ApplyStats {
    pub applied: u64,
    pub withdrawn: u64,
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

pub fn walk_blocks(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    start_number: u64,
    end_number: u64,
    start_hash: &str,
) -> Result<(Vec<BlockEvent>, Option<Value>)> {
    let mut prev_hash = start_hash.to_string();
    let mut last_block_value: Option<Value> = None;
    let mut events: Vec<BlockEvent> = Vec::new();
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
        let sealed_at = header
            .get("sealed_at")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Verify(format!("block {n} missing header.sealed_at")))?
            .to_string();

        let mut declarations = Vec::new();
        let mut withdrawals = Vec::new();
        let mut delta_bodies = Vec::new();

        for entry in block_value
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match entry.get("type").and_then(Value::as_str) {
                Some("publisher_declaration") => {
                    let body = entry.get("body").ok_or_else(|| {
                        Error::Verify(format!(
                            "block {n}: publisher_declaration entry missing body"
                        ))
                    })?;
                    declarations.push(body.clone());
                }
                Some("registry_update") => {
                    let body = entry.get("body").ok_or_else(|| {
                        Error::Verify(format!("block {n}: registry_update entry missing body"))
                    })?;
                    verify_envelope(body, "update", trust_key)?;
                    if body["update"]["action"] == "payload_withdrawal" {
                        let withdrawn_id = body["update"]["details"]["delta_id"]
                            .as_str()
                            .ok_or_else(|| {
                                Error::Verify(format!(
                                    "block {n}: payload_withdrawal missing details.delta_id"
                                ))
                            })?;
                        withdrawals.push(withdrawn_id.to_string());
                    }
                }
                Some("publisher_delta") => {
                    let body = entry.get("body").ok_or_else(|| {
                        Error::Verify(format!("block {n}: publisher_delta entry missing body"))
                    })?;
                    delta_bodies.push(body.clone());
                }
                _ => {}
            }
        }

        events.push(BlockEvent {
            height: n,
            sealed_at,
            declarations,
            withdrawals,
            delta_bodies,
        });
        last_block_value = Some(block_value);
    }
    Ok((events, last_block_value))
}

fn load_anchor(anchor: &str, client: &Client) -> Result<(PublicKey, String)> {
    let anchor_bytes = load_anchor_bytes(anchor, client)?;
    let anchor_value: Value = serde_json::from_slice(&anchor_bytes)?;
    let anchor_env: LogAnchorEnvelope = serde_json::from_value(anchor_value.clone())?;
    let trust_key = PublicKey::from_b64u(&anchor_env.anchor.genesis_key.public_key)?;
    verify_envelope(&anchor_value, "anchor", &trust_key)?;
    Ok((trust_key, anchor_env.anchor.log_id))
}

fn persist_declaration(
    conn: &Connection,
    height: u64,
    sealed_at: &str,
    baseline: bool,
    envelope: &Value,
) -> Result<()> {
    let env: PublisherEnvelope = serde_json::from_value(envelope.clone())?;
    conn.execute(
        "INSERT INTO declarations(domain, seq, height, sealed_at, baseline, envelope) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (
            env.publisher.domain,
            env.publisher.seq as i64,
            height as i64,
            sealed_at,
            baseline as i64,
            serde_json::to_string(envelope)?,
        ),
    )?;
    Ok(())
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

fn remove_derived(conn: &Connection, delta_id: &str, url: &str) -> Result<()> {
    if table_exists(conn, "extracts")? {
        conn.execute("DELETE FROM extracts WHERE delta_id = ?1", [delta_id])?;
    }
    if table_exists(conn, "links")? {
        conn.execute("DELETE FROM links WHERE source_url = ?1", [url])?;
    }
    if table_exists(conn, "embeddings")? {
        conn.execute("DELETE FROM embeddings WHERE delta_id = ?1", [delta_id])?;
    }
    Ok(())
}

fn remove_by_delta_id(conn: &Connection, delta_id: &str) -> Result<bool> {
    let url: Option<String> = conn
        .query_row(
            "SELECT url FROM records WHERE delta_id = ?1",
            [delta_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(url) = url else {
        return Ok(false);
    };
    conn.execute("DELETE FROM records WHERE delta_id = ?1", [delta_id])?;
    remove_derived(conn, delta_id, &url)?;
    Ok(true)
}

fn remove_by_url(conn: &Connection, url: &str, publisher: &str) -> Result<()> {
    let delta_id: Option<String> = conn
        .query_row(
            "SELECT delta_id FROM records WHERE url = ?1 AND publisher = ?2",
            [url, publisher],
            |row| row.get(0),
        )
        .optional()?;
    conn.execute(
        "DELETE FROM records WHERE url = ?1 AND publisher = ?2",
        [url, publisher],
    )?;
    if let Some(id) = delta_id {
        remove_derived(conn, &id, url)?;
    }
    Ok(())
}

pub fn load_history(conn: &Connection) -> Result<KeyHistory> {
    let mut stmt = conn.prepare(
        "SELECT height, sealed_at, baseline, envelope FROM declarations ORDER BY height, seq",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut history = KeyHistory::new();
    for (height, sealed_at, baseline, envelope) in rows {
        let value: Value = serde_json::from_str(&envelope)?;
        let height = height as u64;
        if baseline != 0 {
            history.add_baseline(height, &value)?;
        } else {
            history.add_declaration(height, &sealed_at, &value)?;
        }
    }
    Ok(history)
}

pub fn apply_events(
    conn: &Connection,
    client: &Client,
    base: &Url,
    history: &mut KeyHistory,
    events: &[BlockEvent],
) -> Result<ApplyStats> {
    let mut stats = ApplyStats {
        applied: 0,
        withdrawn: 0,
    };
    for event in events {
        for declaration in &event.declarations {
            history.add_declaration(event.height, &event.sealed_at, declaration)?;
            persist_declaration(conn, event.height, &event.sealed_at, false, declaration)?;
        }

        for delta_id in &event.withdrawals {
            if remove_by_delta_id(conn, delta_id)? {
                stats.withdrawn += 1;
            }
        }

        for body in &event.delta_bodies {
            let env: DeltaEnvelope = serde_json::from_value(body.clone())?;
            let id = history.verify_delta(event.height, body)?;
            let publisher = Url::parse(&env.delta.url)
                .ok()
                .as_ref()
                .and_then(url_authority)
                .ok_or_else(|| {
                    Error::Verify(format!("delta url {}: no authority", env.delta.url))
                })?;

            match env.delta.change_type {
                ChangeType::New | ChangeType::Update => {
                    let hex = id.trim_start_matches("sha256:");
                    let (title, abstract_text) = match &env.delta.payload {
                        Some(commitment) => fetch_payload(client, base, hex, commitment)
                            .unwrap_or((String::new(), None)),
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
                            &env.delta.url,
                            &publisher,
                            &id,
                            &env.delta.observed_at,
                            &title,
                            &abstract_text,
                            &env.delta.meta.lang,
                        ),
                    )?;
                    stats.applied += 1;
                }
                ChangeType::Delete => {
                    remove_by_url(conn, &env.delta.url, &publisher)?;
                }
                ChangeType::Attest => {}
            }
        }
    }
    Ok(stats)
}

pub fn run(
    anchor: &str,
    log_base: &str,
    dir: &Path,
    allow_http: bool,
    tier1: bool,
) -> Result<SyncReport> {
    std::fs::create_dir_all(dir)?;

    let client = Client::new(allow_http);
    let base = crate::fetch::parse_base(log_base)?;
    let (trust_key, log_id) = load_anchor(anchor, &client)?;
    registry::validate_log_id(&log_id)?;

    let migrated = migrate_legacy_layout(dir, &log_id)?;

    match run_registered(
        &client, &base, &trust_key, anchor, log_base, dir, &log_id, tier1,
    ) {
        Ok(report) => Ok(report),
        Err(err) => {
            if migrated {
                rollback_migration(dir, &log_id);
            }
            Err(err)
        }
    }
}

pub fn run_all(dir: &Path, allow_http: bool) -> Result<Vec<SyncReport>> {
    registry::check_not_legacy(dir)?;
    let reg = registry::load(dir)?;
    reg.logs
        .iter()
        .map(|entry| run(&entry.anchor, &entry.base, dir, allow_http, entry.tier1))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn run_registered(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    anchor: &str,
    log_base: &str,
    dir: &Path,
    log_id: &str,
    tier1: bool,
) -> Result<SyncReport> {
    let mut reg = registry::load(dir)?;
    match reg.logs.iter_mut().find(|e| e.log_id == log_id) {
        Some(entry) => {
            if entry.anchor != anchor || entry.base != log_base {
                return Err(Error::Verify(format!(
                    "log {log_id} is already registered with anchor={} base={}; requested anchor={anchor} base={log_base} conflicts with it",
                    entry.anchor, entry.base
                )));
            }
            if tier1 {
                entry.tier1 = true;
            }
        }
        None => reg.logs.push(LogEntry {
            log_id: log_id.to_string(),
            anchor: anchor.to_string(),
            base: log_base.to_string(),
            tier1,
        }),
    }
    registry::save(dir, &reg)?;

    let log_dir = registry::log_dir(dir, log_id);
    std::fs::create_dir_all(&log_dir)?;
    let sync_path = log_dir.join("sync.json");

    if sync_path.exists() {
        run_incremental(client, base, trust_key, log_id, &log_dir, &sync_path)
    } else {
        run_cold_start(client, base, trust_key, log_id, &log_dir, &sync_path)
    }
}

fn migrate_legacy_layout(dir: &Path, log_id: &str) -> Result<bool> {
    if !registry::is_unmigrated_legacy_layout(dir) {
        return Ok(false);
    }
    let target_dir = registry::log_dir(dir, log_id);
    std::fs::create_dir_all(&target_dir)?;
    std::fs::rename(dir.join("index.sqlite"), target_dir.join("index.sqlite"))?;
    std::fs::rename(dir.join("sync.json"), target_dir.join("sync.json"))?;
    Ok(true)
}

fn rollback_migration(dir: &Path, log_id: &str) {
    let target_dir = registry::log_dir(dir, log_id);
    let _ = std::fs::rename(target_dir.join("index.sqlite"), dir.join("index.sqlite"));
    let _ = std::fs::rename(target_dir.join("sync.json"), dir.join("sync.json"));
    let _ = std::fs::remove_dir_all(&target_dir);
    let _ = std::fs::remove_file(dir.join("logs.json"));
}

fn run_incremental(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    log_id: &str,
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
                log_id: log_id.to_string(),
                log_position_before: Some(local.head_number),
                head: local.head_number,
                withdrawn: 0,
            });
        }
        return Err(Error::Verify(format!(
            "checkpoint equivocation: block {} has hash {} locally but remote reports {}",
            local.head_number, local.head_hash, checkpoint.block_hash
        )));
    }

    let (events, last_block_value) = walk_blocks(
        client,
        base,
        trust_key,
        local.head_number + 1,
        checkpoint.block_number,
        &local.head_hash,
    )?;
    let last_block_value = last_block_value.ok_or_else(|| {
        Error::Verify("continuous sync produced no blocks despite checkpoint advancing".into())
    })?;
    verify_checkpoint_binding(&checkpoint_value, &last_block_value)?;

    let index_sqlite_path = dir.join("index.sqlite");
    let conn = Connection::open(&index_sqlite_path)?;
    let mut history = load_history(&conn)?;
    let tx = conn.unchecked_transaction()?;
    tx.execute(CREATE_UNIQUE_INDEX, [])?;
    tx.execute(CREATE_DECLARATIONS, [])?;
    let stats = apply_events(&tx, client, base, &mut history, &events)?;
    tx.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    tx.commit()?;

    let sync_state = SyncState {
        log_position: local.log_position,
        head_number: checkpoint.block_number,
        head_hash: checkpoint.block_hash.clone(),
        content_digest: local.content_digest.clone(),
    };
    std::fs::write(sync_path, serde_json::to_vec(&sync_state)?)?;

    Ok(SyncReport {
        log_id: log_id.to_string(),
        log_position_before: Some(local.head_number),
        head: checkpoint.block_number,
        withdrawn: stats.withdrawn,
    })
}

fn run_cold_start(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    log_id: &str,
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

    let conn = Connection::open(&tmp_sqlite_path)?;
    conn.execute(CREATE_UNIQUE_INDEX, [])?;
    conn.execute(CREATE_DECLARATIONS, [])?;

    let mut history = KeyHistory::new();
    for entry in &state_env.state.entries {
        if let StateEntry::Declaration(d) = entry {
            history.add_baseline(d.sealing_height, &d.declaration)?;
            persist_declaration(&conn, d.sealing_height, "", true, &d.declaration)?;
        }
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

    let (events, last_block_value) = walk_blocks(
        client,
        base,
        trust_key,
        manifest.log_position + 1,
        checkpoint.block_number,
        &manifest.anchor_block_hash,
    )?;

    match &last_block_value {
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

    let stats = apply_events(&conn, client, base, &mut history, &events)?;
    conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    drop(conn);

    guard.disarm();
    let index_sqlite_path = dir.join("index.sqlite");
    std::fs::rename(&tmp_sqlite_path, &index_sqlite_path)?;

    let sync_state = SyncState {
        log_position: manifest.log_position,
        head_number: checkpoint.block_number,
        head_hash: checkpoint.block_hash.clone(),
        content_digest: Some(manifest.content_digest.clone()),
    };
    std::fs::write(sync_path, serde_json::to_vec(&sync_state)?)?;

    Ok(SyncReport {
        log_id: log_id.to_string(),
        log_position_before: None,
        head: checkpoint.block_number,
        withdrawn: stats.withdrawn,
    })
}
