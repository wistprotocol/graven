use crate::error::{Error, Result};
use crate::fetch::{resolve, Client};
use crate::keyset::KeyHistory;
use crate::registry::{self, LogEntry};
use crate::store::{table_exists, CREATE_DECLARATIONS, CREATE_TIER1, CREATE_UNIQUE_INDEX};
use crate::tier1;
use reqwest::Url;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use wist_core::block::{block_hash, verify_block, verify_chain_link, verify_checkpoint_binding};
use wist_core::chain::ChainTips;
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::delta::{content_bytes, verify_commitment};
use wist_core::envelope::verify_envelope;
use wist_core::objects::{
    ChangeType, CheckpointEnvelope, DeltaEnvelope, DeltaPayloadCommitment, LogAnchorEnvelope,
    Payload, PublisherEnvelope, SnapshotIndexEnvelope, SnapshotManifestEnvelope,
    SnapshotStateEnvelope, StateEntry,
};
use wist_core::sanctions::Outcome;
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
    /// WIST-4 §7 governance acts, from which the sanction ladder is
    /// derived; WIST-3 §7 reads levels 2, 3 and 4 as materialization
    /// inputs.
    pub governance: Vec<Value>,
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

struct PayloadFields {
    title: String,
    abstract_text: Option<String>,
    extract: Option<String>,
    links: Vec<String>,
}

fn fetch_payload(
    client: &Client,
    base: &Url,
    hex: &str,
    commitment: &DeltaPayloadCommitment,
) -> Result<PayloadFields> {
    let url = resolve(base, &format!("/payloads/{hex}.json"))?;
    let (_, value) = client.get_json(&url)?;
    let payload: Payload = serde_json::from_value(value.clone())?;
    verify_commitment(&payload.salt, &value["content"], &commitment.commitment)?;
    if content_bytes(&value["content"])? != commitment.bytes {
        return Err(Error::Verify("payload content bytes mismatch".into()));
    }
    Ok(PayloadFields {
        title: payload.content.summary.title,
        abstract_text: payload.content.summary.r#abstract,
        extract: Some(payload.content.extract),
        links: payload.content.links.urls,
    })
}

/// WIST-3 §3.4: a Block sealed at height N MUST be signed by a key
/// valid at N — the genesis key, or one a validly-signed
/// `aggregator_key_add` sealed at a height ≤ N named and no
/// `aggregator_key_remove` has retired. Removal is permanent, so an
/// `aggregator_key_add` naming a removed `key_id` is rejected and
/// restores nothing.
pub struct AggregatorKeys {
    valid: BTreeMap<String, PublicKey>,
    removed: BTreeSet<String>,
}

impl AggregatorKeys {
    pub fn admit(&mut self, key_id: &str, public_key: &str, removed: bool) -> Result<()> {
        if removed {
            self.valid.remove(key_id);
            self.removed.insert(key_id.to_string());
        } else {
            self.valid
                .insert(key_id.to_string(), PublicKey::from_b64u(public_key)?);
        }
        Ok(())
    }
}

impl AggregatorKeys {
    pub fn genesis(key_id: &str, key: PublicKey) -> Self {
        let mut valid = BTreeMap::new();
        valid.insert(key_id.to_string(), key);
        AggregatorKeys {
            valid,
            removed: BTreeSet::new(),
        }
    }

    pub fn key(&self, key_id: &str) -> Option<&PublicKey> {
        self.valid.get(key_id)
    }

    fn signer_of(&self, envelope: &Value) -> Result<&PublicKey> {
        let key_id = envelope["sig"]["key_id"]
            .as_str()
            .ok_or_else(|| Error::Verify("entry signature names no key_id".into()))?;
        self.key(key_id).ok_or_else(|| {
            Error::Verify(format!(
                "no Aggregator key {key_id} is valid at this height"
            ))
        })
    }

    fn apply(&mut self, update: &Value) -> Result<()> {
        let action = update["update"]["action"].as_str().unwrap_or_default();
        let key_id = match update["update"]["details"]["key_id"].as_str() {
            Some(id) => id.to_string(),
            None => return Ok(()),
        };
        match action {
            "aggregator_key_add" => {
                if self.removed.contains(&key_id) {
                    return Err(Error::Verify(format!(
                        "aggregator_key_add names the retired key {key_id}"
                    )));
                }
                let public_key = update["update"]["details"]["public_key"]
                    .as_str()
                    .ok_or_else(|| {
                        Error::Verify("aggregator_key_add names no public_key".into())
                    })?;
                self.valid.insert(key_id, PublicKey::from_b64u(public_key)?);
            }
            "aggregator_key_remove" => {
                self.valid.remove(&key_id);
                self.removed.insert(key_id);
            }
            _ => {}
        }
        Ok(())
    }
}

/// A Checkpoint names a Block, so it is verified under the Aggregator
/// key set valid at that Block rather than under the genesis key alone.
fn verify_checkpoint_signature(checkpoint_value: &Value, keys: &AggregatorKeys) -> Result<()> {
    let key_id = checkpoint_value["sig"]["key_id"]
        .as_str()
        .ok_or_else(|| Error::Verify("checkpoint signature names no key_id".into()))?;
    let key = keys.key(key_id).ok_or_else(|| {
        Error::Verify(format!(
            "checkpoint is signed by {key_id}, valid at no height here"
        ))
    })?;
    verify_envelope(checkpoint_value, "checkpoint", key)?;
    Ok(())
}

fn load_aggregator_keys(
    conn: &Connection,
    genesis_key_id: &str,
    genesis_key: &PublicKey,
) -> Result<AggregatorKeys> {
    conn.execute_batch(crate::store::CREATE_AGGREGATOR_KEYS)?;
    let mut keys = AggregatorKeys::genesis(genesis_key_id, genesis_key.clone());
    let mut stmt =
        conn.prepare("SELECT key_id, public_key, removed FROM aggregator_keys WHERE key_id != ?1")?;
    let rows = stmt
        .query_map([genesis_key_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (key_id, public_key, removed) in rows {
        if removed {
            keys.valid.remove(&key_id);
            keys.removed.insert(key_id);
        } else {
            keys.valid
                .insert(key_id, PublicKey::from_b64u(&public_key)?);
        }
    }
    Ok(keys)
}

fn save_aggregator_keys(conn: &Connection, keys: &AggregatorKeys) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_AGGREGATOR_KEYS)?;
    for (key_id, key) in &keys.valid {
        conn.execute(
            "INSERT INTO aggregator_keys(key_id, public_key, removed) VALUES (?1, ?2, 0)
             ON CONFLICT(key_id) DO UPDATE SET public_key = excluded.public_key, removed = 0",
            (key_id, key.to_b64u()),
        )?;
    }
    for key_id in &keys.removed {
        conn.execute(
            "INSERT INTO aggregator_keys(key_id, public_key, removed) VALUES (?1, '', 1)
             ON CONFLICT(key_id) DO UPDATE SET removed = 1",
            [key_id],
        )?;
    }
    Ok(())
}

pub fn walk_blocks(
    client: &Client,
    base: &Url,
    keys: &mut AggregatorKeys,
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
        for entry in block_value
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|e| e.get("type").and_then(Value::as_str) == Some("registry_update"))
        {
            let body = entry
                .get("body")
                .ok_or_else(|| Error::Verify(format!("block {n}: registry_update missing body")))?;
            let signer = keys.signer_of(body)?.clone();
            verify_envelope(body, "update", &signer)?;
            keys.apply(body)?;
        }
        let block_key_id = block_value["sig"]["key_id"]
            .as_str()
            .ok_or_else(|| Error::Verify(format!("block {n} signature names no key_id")))?;
        let block_key = keys.key(block_key_id).ok_or_else(|| {
            Error::Verify(format!(
                "block {n} is signed by {block_key_id}, valid at no height here"
            ))
        })?;
        verify_block(&block_value, block_key)?;
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
        let mut governance = Vec::new();

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
                    if matches!(
                        body["update"]["action"].as_str(),
                        Some("sanction" | "sanction_lift" | "notice" | "appeal" | "appeal_ruling")
                    ) {
                        governance.push(body["update"].clone());
                    }
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
            governance,
        });
        last_block_value = Some(block_value);
    }
    Ok((events, last_block_value))
}

fn load_anchor(anchor: &str, client: &Client) -> Result<(PublicKey, String, String)> {
    let anchor_bytes = load_anchor_bytes(anchor, client)?;
    let anchor_value: Value = serde_json::from_slice(&anchor_bytes)?;
    let anchor_env: LogAnchorEnvelope = serde_json::from_value(anchor_value.clone())?;
    let trust_key = PublicKey::from_b64u(&anchor_env.anchor.genesis_key.public_key)?;
    verify_envelope(&anchor_value, "anchor", &trust_key)?;
    Ok((
        trust_key,
        anchor_env.anchor.log_id,
        anchor_env.anchor.genesis_key.key_id,
    ))
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

#[derive(Debug, Clone, Default)]
struct DomainSanction {
    level: u8,
    since_height: u64,
    notice_at: Option<i64>,
    appeal_at: Option<i64>,
    ruling: Option<(Outcome, i64)>,
}

/// WIST-4 §7 as WIST-3 §7 reads it: level 2 marks a domain's records
/// reduced-weight, level 3 stops its later Deltas from materializing
/// from the height it takes effect, level 4 removes its records. A
/// lapsed T, a lapsed ruling deadline and an "overturned" ruling void
/// the level-3 and level-4 states, leaving the rungs below in force.
#[derive(Default)]
struct SanctionLedger {
    domains: BTreeMap<String, DomainSanction>,
    exclusions: BTreeMap<(String, String), u64>,
}

impl SanctionLedger {
    fn apply(&mut self, height: u64, sealed_at_s: i64, update: &Value) {
        let Some(domain) = update["subject"].as_str() else {
            return;
        };
        let entry = self.domains.entry(domain.to_string()).or_default();
        match update["action"].as_str() {
            Some("sanction") => {
                if let Some(level) = update["details"]["level"].as_u64() {
                    entry.level = level.clamp(0, 4) as u8;
                    entry.since_height = height;
                }
            }
            Some("sanction_lift") => *entry = DomainSanction::default(),
            Some("notice") if update["details"]["kind"] == "sanction" => {
                entry.notice_at = Some(sealed_at_s);
            }
            Some("appeal") => entry.appeal_at = Some(sealed_at_s),
            Some("appeal_ruling") => {
                let outcome = match update["details"]["outcome"].as_str() {
                    Some("overturned") => Outcome::Overturned,
                    Some("upheld") => Outcome::Upheld,
                    _ => Outcome::Unappealed,
                };
                entry.ruling = Some((outcome, sealed_at_s));
            }
            _ => {}
        }
    }

    fn level_at(&self, domain: &str, now_s: i64) -> (u8, u64) {
        let Some(state) = self.domains.get(domain) else {
            return (0, 0);
        };
        if state.level >= 3 {
            if let Some(void_at) =
                wist_core::sanctions::state_void_at(state.notice_at, state.appeal_at, state.ruling)
            {
                if now_s >= void_at {
                    return (state.level.clamp(1, 2), state.since_height);
                }
            }
        }
        (state.level, state.since_height)
    }

    fn excluded(&self, publisher: &str, url: &str, height: u64) -> bool {
        self.exclusions
            .get(&(publisher.to_string(), url.to_string()))
            .is_some_and(|since| height >= *since)
    }
}

fn load_sanctions(conn: &Connection) -> Result<SanctionLedger> {
    conn.execute_batch(crate::store::CREATE_SANCTIONS)?;
    let mut ledger = SanctionLedger::default();
    let mut stmt = conn.prepare(
        "SELECT domain, level, since_height, notice_at, appeal_at, ruling, ruling_at FROM sanctions",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (domain, level, since, notice_at, appeal_at, ruling, ruling_at) in rows {
        let ruling = match (ruling.as_deref(), ruling_at) {
            (Some("overturned"), Some(at)) => Some((Outcome::Overturned, at)),
            (Some("upheld"), Some(at)) => Some((Outcome::Upheld, at)),
            (Some("unappealed"), Some(at)) => Some((Outcome::Unappealed, at)),
            _ => None,
        };
        ledger.domains.insert(
            domain,
            DomainSanction {
                level: level.clamp(0, 4) as u8,
                since_height: since.max(0) as u64,
                notice_at,
                appeal_at,
                ruling,
            },
        );
    }
    let mut stmt = conn.prepare("SELECT publisher, url, since_height FROM exclusions")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (publisher, url, since) in rows {
        ledger
            .exclusions
            .insert((publisher, url), since.max(0) as u64);
    }
    Ok(ledger)
}

fn save_sanctions(conn: &Connection, ledger: &SanctionLedger) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_SANCTIONS)?;
    for (domain, state) in &ledger.domains {
        let (ruling, ruling_at) = match state.ruling {
            Some((Outcome::Overturned, at)) => (Some("overturned"), Some(at)),
            Some((Outcome::Upheld, at)) => (Some("upheld"), Some(at)),
            Some((Outcome::Unappealed, at)) => (Some("unappealed"), Some(at)),
            None => (None, None),
        };
        conn.execute(
            "INSERT INTO sanctions(domain, level, since_height, notice_at, appeal_at, ruling, ruling_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(domain) DO UPDATE SET level = excluded.level, since_height = excluded.since_height, notice_at = excluded.notice_at, appeal_at = excluded.appeal_at, ruling = excluded.ruling, ruling_at = excluded.ruling_at",
            (
                domain,
                state.level as i64,
                state.since_height as i64,
                state.notice_at,
                state.appeal_at,
                ruling,
                ruling_at,
            ),
        )?;
    }
    for ((publisher, url), since) in &ledger.exclusions {
        conn.execute(
            "INSERT INTO exclusions(publisher, url, since_height) VALUES (?1, ?2, ?3)
             ON CONFLICT(publisher, url) DO UPDATE SET since_height = excluded.since_height",
            (publisher, url, *since as i64),
        )?;
    }
    Ok(())
}

pub fn apply_events(
    conn: &Connection,
    client: &Client,
    base: &Url,
    history: &mut KeyHistory,
    events: &[BlockEvent],
    tier1: bool,
) -> Result<ApplyStats> {
    let mut stats = ApplyStats {
        applied: 0,
        withdrawn: 0,
    };
    if tier1 {
        conn.execute_batch(CREATE_TIER1)?;
    }
    conn.execute_batch(crate::store::CREATE_CHAIN_TIPS)?;
    let mut tips = load_chain_tips(conn)?;
    let mut ledger = load_sanctions(conn)?;
    for event in events {
        let sealed_at_s = event
            .sealed_at
            .parse::<jiff::Timestamp>()
            .map(|t| t.as_second())
            .unwrap_or(0);
        for update in &event.governance {
            ledger.apply(event.height, sealed_at_s, update);
        }
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
            // WIST-3 §3.3: a sealed Delta that fails the Key Set its own
            // Block resolves is ignored exactly as a fork is — applied to
            // nothing, moving no chain tip — never a reason to abandon
            // the sync.
            let verified = match history.verify_delta(event.height, body) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ignoring a Delta at height {}: {e}", event.height);
                    continue;
                }
            };
            let env: DeltaEnvelope = serde_json::from_value(body.clone())?;
            let id = verified.id;
            let publisher = verified.publisher;
            // WIST-1 §3.5: a Delta whose prev is not the chain tip the
            // state carries is a fork, and moves nothing.
            if !tips.apply(&publisher, &env.delta.url, &id, env.delta.prev.as_deref()) {
                continue;
            }
            if !verified.materializes {
                continue;
            }
            let (level, since_height) = ledger.level_at(&publisher, sealed_at_s);
            // WIST-3 §7: level 4 removes the domain's records, level 3
            // stops its later Deltas from materializing at all, and
            // level 2 marks what does materialize reduced-weight.
            if level == 4 {
                conn.execute("DELETE FROM records WHERE publisher = ?1", [&publisher])?;
                continue;
            }
            if level == 3 && event.height >= since_height {
                continue;
            }
            if ledger.excluded(&publisher, &env.delta.url, event.height) {
                continue;
            }
            let weight = if level == 2 { "reduced" } else { "full" };

            match env.delta.change_type {
                ChangeType::New | ChangeType::Update => {
                    let hex = id.trim_start_matches("sha256:");
                    let fields = match &env.delta.payload {
                        Some(commitment) => fetch_payload(client, base, hex, commitment).ok(),
                        None => None,
                    };
                    let title = fields.as_ref().map(|f| f.title.clone()).unwrap_or_default();
                    let abstract_text = fields.as_ref().and_then(|f| f.abstract_text.clone());

                    conn.execute(
                        "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                         ON CONFLICT(url, publisher) DO UPDATE SET
                            delta_id = excluded.delta_id, observed_at = excluded.observed_at,
                            weight = excluded.weight, title = excluded.title,
                            abstract = excluded.abstract, lang = excluded.lang",
                        (
                            &env.delta.url,
                            &publisher,
                            &id,
                            &env.delta.observed_at,
                            weight,
                            &title,
                            &abstract_text,
                            &env.delta.meta.lang,
                        ),
                    )?;
                    stats.applied += 1;

                    if tier1 {
                        match &fields {
                            Some(f) => {
                                if let Some(extract) = &f.extract {
                                    conn.execute(
                                        "INSERT INTO extracts(url, publisher, delta_id, extract) VALUES (?1, ?2, ?3, ?4)
                                         ON CONFLICT(url, publisher) DO UPDATE SET
                                            delta_id = excluded.delta_id, extract = excluded.extract",
                                        (&env.delta.url, &publisher, &id, extract),
                                    )?;
                                }
                                conn.execute(
                                    "DELETE FROM links WHERE source_url = ?1",
                                    [&env.delta.url],
                                )?;
                                for (position, target_url) in f.links.iter().enumerate() {
                                    conn.execute(
                                        "INSERT INTO links(source_url, target_url, position) VALUES (?1, ?2, ?3)",
                                        (&env.delta.url, target_url, position as i64),
                                    )?;
                                }
                            }
                            None => {
                                conn.execute(
                                    "DELETE FROM extracts WHERE url = ?1 AND publisher = ?2",
                                    (&env.delta.url, &publisher),
                                )?;
                                conn.execute(
                                    "DELETE FROM links WHERE source_url = ?1",
                                    [&env.delta.url],
                                )?;
                            }
                        }
                    }
                }
                ChangeType::Delete => {
                    remove_by_url(conn, &env.delta.url, &publisher)?;
                }
                ChangeType::Attest => {
                    // WIST-3 §7: an attest refreshes the record's
                    // observed_at and leaves its anchor Delta in place.
                    conn.execute(
                        "UPDATE records SET observed_at = ?3 WHERE url = ?1 AND publisher = ?2",
                        (&env.delta.url, &publisher, &env.delta.observed_at),
                    )?;
                }
            }
        }
    }
    save_chain_tips(conn, &tips)?;
    save_sanctions(conn, &ledger)?;
    Ok(stats)
}

fn load_chain_tips(conn: &Connection) -> Result<ChainTips> {
    let mut tips = ChainTips::new();
    let mut stmt = conn.prepare("SELECT publisher, url, tip FROM chain_tips")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (publisher, url, tip) in rows {
        tips.adopt(&publisher, &url, &tip);
    }
    Ok(tips)
}

fn save_chain_tips(conn: &Connection, tips: &ChainTips) -> Result<()> {
    for (publisher, url, tip) in tips.tips() {
        conn.execute(
            "INSERT INTO chain_tips(publisher, url, tip) VALUES (?1, ?2, ?3)
             ON CONFLICT(publisher, url) DO UPDATE SET tip = excluded.tip",
            (publisher, url, tip),
        )?;
    }
    Ok(())
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
    let (trust_key, log_id, genesis_key_id) = load_anchor(anchor, &client)?;
    registry::validate_log_id(&log_id)?;

    let migrated = migrate_legacy_layout(dir, &log_id)?;

    match run_registered(
        &client,
        &base,
        &trust_key,
        &genesis_key_id,
        anchor,
        log_base,
        dir,
        &log_id,
        tier1,
    ) {
        Ok(report) => Ok(report),
        Err(err) => {
            if migrated {
                if let Err(rollback_err) = rollback_migration(dir, &log_id) {
                    return Err(Error::Verify(format!(
                        "sync failed: {err}; additionally, rollback of the legacy-layout migration failed: {rollback_err}"
                    )));
                }
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
    genesis_key_id: &str,
    anchor: &str,
    log_base: &str,
    dir: &Path,
    log_id: &str,
    tier1: bool,
) -> Result<SyncReport> {
    let mut reg = registry::load(dir)?;
    if let Some(other) = registry::find_collision(&reg.logs, log_id) {
        return Err(Error::Verify(format!(
            "log_id {log_id:?} sanitizes to the same directory as already-registered log_id {:?} (both -> {:?}); refusing to register to avoid a cross-log directory collision",
            other.log_id,
            registry::sanitize(log_id)
        )));
    }
    let effective_tier1 = match reg.logs.iter_mut().find(|e| e.log_id == log_id) {
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
            entry.tier1
        }
        None => {
            reg.logs.push(LogEntry {
                log_id: log_id.to_string(),
                anchor: anchor.to_string(),
                base: log_base.to_string(),
                tier1,
            });
            tier1
        }
    };
    registry::save(dir, &reg)?;

    let log_dir = registry::log_dir(dir, log_id);
    std::fs::create_dir_all(&log_dir)?;
    let sync_path = log_dir.join("sync.json");

    if sync_path.exists() {
        run_incremental(
            client,
            base,
            trust_key,
            genesis_key_id,
            log_id,
            &log_dir,
            &sync_path,
            effective_tier1,
        )
    } else {
        run_cold_start(
            client,
            base,
            trust_key,
            genesis_key_id,
            log_id,
            &log_dir,
            &sync_path,
            effective_tier1,
        )
    }
}

fn migrate_legacy_layout(dir: &Path, log_id: &str) -> Result<bool> {
    if !registry::is_unmigrated_legacy_layout(dir) {
        return Ok(false);
    }
    let target_dir = registry::log_dir(dir, log_id);
    std::fs::create_dir_all(&target_dir)?;

    let index_src = dir.join("index.sqlite");
    let index_dst = target_dir.join("index.sqlite");
    std::fs::rename(&index_src, &index_dst)?;

    let sync_src = dir.join("sync.json");
    let sync_dst = target_dir.join("sync.json");
    if let Err(err) = std::fs::rename(&sync_src, &sync_dst) {
        if let Err(undo_err) = std::fs::rename(&index_dst, &index_src) {
            return Err(Error::Verify(format!(
                "legacy migration failed moving {} into {} ({err}); additionally, could not move {} back to {} ({undo_err}); index.sqlite is stranded at {}",
                sync_src.display(),
                sync_dst.display(),
                index_dst.display(),
                index_src.display(),
                index_dst.display()
            )));
        }
        return Err(Error::Verify(format!(
            "legacy migration failed moving {} into {}: {err}",
            sync_src.display(),
            sync_dst.display()
        )));
    }
    Ok(true)
}

fn rollback_migration(dir: &Path, log_id: &str) -> Result<()> {
    let target_dir = registry::log_dir(dir, log_id);
    let index_src = target_dir.join("index.sqlite");
    let index_dst = dir.join("index.sqlite");
    let sync_src = target_dir.join("sync.json");
    let sync_dst = dir.join("sync.json");

    if let Err(err) = std::fs::rename(&index_src, &index_dst) {
        return Err(Error::Verify(format!(
            "rollback of legacy migration failed: could not move {} back to {}: {err}; both files remain in {}",
            index_src.display(),
            index_dst.display(),
            target_dir.display()
        )));
    }
    if let Err(err) = std::fs::rename(&sync_src, &sync_dst) {
        return Err(Error::Verify(format!(
            "rollback of legacy migration failed: index.sqlite was restored to {} but could not move {} back to {}: {err}; sync.json remains in {}",
            dir.display(),
            sync_src.display(),
            sync_dst.display(),
            target_dir.display()
        )));
    }

    std::fs::remove_dir_all(&target_dir).map_err(|err| {
        Error::Verify(format!(
            "rollback of legacy migration restored both files to {} but could not remove {}: {err}",
            dir.display(),
            target_dir.display()
        ))
    })?;
    std::fs::remove_file(dir.join("logs.json")).map_err(|err| {
        Error::Verify(format!(
            "rollback of legacy migration restored both files to {} but could not remove {}: {err}",
            dir.display(),
            dir.join("logs.json").display()
        ))
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_incremental(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    genesis_key_id: &str,
    log_id: &str,
    dir: &Path,
    sync_path: &Path,
    tier1: bool,
) -> Result<SyncReport> {
    let sync_bytes = std::fs::read(sync_path)?;
    let local: SyncState = serde_json::from_slice(&sync_bytes)?;

    let checkpoint_url = resolve(base, "/log/checkpoint.json")?;
    let (_, checkpoint_value) = client.get_json(&checkpoint_url)?;
    let checkpoint_env: CheckpointEnvelope = serde_json::from_value(checkpoint_value.clone())?;
    let checkpoint = checkpoint_env.checkpoint;

    if checkpoint.block_number < local.head_number {
        return Err(Error::Verify(format!(
            "rollback rejected: remote checkpoint head {} is behind local head {}",
            checkpoint.block_number, local.head_number
        )));
    }

    if checkpoint.block_number == local.head_number {
        let keys = load_aggregator_keys(
            &Connection::open(dir.join("index.sqlite"))?,
            genesis_key_id,
            trust_key,
        )?;
        verify_checkpoint_signature(&checkpoint_value, &keys)?;
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

    let index_sqlite_path = dir.join("index.sqlite");
    let conn = Connection::open(&index_sqlite_path)?;
    let mut aggregator_keys = load_aggregator_keys(&conn, genesis_key_id, trust_key)?;
    let (events, last_block_value) = walk_blocks(
        client,
        base,
        &mut aggregator_keys,
        local.head_number + 1,
        checkpoint.block_number,
        &local.head_hash,
    )?;
    verify_checkpoint_signature(&checkpoint_value, &aggregator_keys)?;
    save_aggregator_keys(&conn, &aggregator_keys)?;
    let last_block_value = last_block_value.ok_or_else(|| {
        Error::Verify("continuous sync produced no blocks despite checkpoint advancing".into())
    })?;
    verify_checkpoint_binding(&checkpoint_value, &last_block_value)?;

    let mut history = load_history(&conn)?;
    let tx = conn.unchecked_transaction()?;
    tx.execute(CREATE_UNIQUE_INDEX, [])?;
    tx.execute(CREATE_DECLARATIONS, [])?;
    let stats = apply_events(&tx, client, base, &mut history, &events, tier1)?;
    tx.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    if tier1 {
        tx.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )?;
    }
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

#[allow(clippy::too_many_arguments)]
fn run_cold_start(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    genesis_key_id: &str,
    log_id: &str,
    dir: &Path,
    sync_path: &Path,
    tier1: bool,
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
    // WIST-3 §8 step 2: the index entry and the manifest are two
    // independently signed statements about the same Snapshot, so they
    // must agree before either is trusted.
    for (field, from_index, from_manifest) in [
        (
            "snapshot_date",
            &newest.snapshot_date,
            &manifest.snapshot_date,
        ),
        (
            "content_digest",
            &newest.content_digest,
            &manifest.content_digest,
        ),
    ] {
        if from_index != from_manifest {
            return Err(Error::Verify(format!(
                "WIST3-E04: snapshot index names {field} {from_index}, its manifest {from_manifest}"
            )));
        }
    }
    if newest.log_position != manifest.log_position {
        return Err(Error::Verify(format!(
            "WIST3-E04: snapshot index names log_position {}, its manifest {}",
            newest.log_position, manifest.log_position
        )));
    }
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
    let mut tier1_extracts: Vec<Vec<u8>> = Vec::new();
    let mut tier1_links: Vec<Vec<u8>> = Vec::new();
    for f in &manifest.files {
        let file_url = resolve(base, &format!("{snapshot_base}{}", f.path))?;
        let bytes = client.get_bytes(&file_url)?;
        verify_file_integrity(&bytes, &f.sha256, f.bytes)?;
        if f.tier == 0 && f.path == "tier0/index.sqlite" {
            tier0_bytes = Some(bytes);
        } else if tier1 && f.path.ends_with("tier1/extracts.parquet") {
            tier1_extracts.push(bytes);
        } else if tier1 && f.path.ends_with("tier1/links.parquet") {
            tier1_links.push(bytes);
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

    if tier1 {
        conn.execute_batch(CREATE_TIER1)?;
        for bytes in &tier1_extracts {
            tier1::import_extracts(&conn, bytes)?;
        }
        for bytes in &tier1_links {
            tier1::import_links(&conn, bytes)?;
        }
    }

    // WIST-3 §8 step 10: adopt the state the Snapshot carries. Without
    // the chain tips, the first Delta continuing a chain the Snapshot
    // already holds reads as a fork; without the recovery windows, an
    // in-window rotation by a thief is invisible.
    let mut history = KeyHistory::new();
    conn.execute_batch(crate::store::CREATE_CHAIN_TIPS)?;
    let mut tips = ChainTips::new();
    let mut adopted_keys: Vec<(String, String, Option<u64>)> = Vec::new();
    let mut adopted_sanctions: Vec<(String, u64)> = Vec::new();
    let mut adopted_exclusions: Vec<(String, String, u64)> = Vec::new();
    let mut adopted_windows: Vec<(String, String, Value, u64)> = Vec::new();
    conn.execute_batch(crate::store::CREATE_ADOPTED_STATE)?;
    for entry in &state_env.state.entries {
        match entry {
            StateEntry::Declaration(d) => {
                history.add_baseline(d.sealing_height, &d.declaration)?;
                history.adopt_floor(&d.domain, d.highest_accepted_seq);
                persist_declaration(&conn, d.sealing_height, "", true, &d.declaration)?;
            }
            StateEntry::RecoveryWindow(w) => {
                adopted_windows.push((
                    w.domain.clone(),
                    w.window_end.clone(),
                    w.head.clone(),
                    w.head_height,
                ));
            }
            StateEntry::Auditor(a) => {
                conn.execute(
                    "INSERT OR REPLACE INTO auditors(auditor_id, key_id, public_key, admitted_height, removed_height) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (
                        &a.auditor_id,
                        &a.key_id,
                        &a.public_key,
                        a.admitted_height as i64,
                        a.removed_height.map(|h| h as i64),
                    ),
                )?;
            }
            StateEntry::Observer(o) => {
                conn.execute(
                    "INSERT OR REPLACE INTO observers(observer_id, key_id, public_key, registered_height, ended_height) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (
                        &o.observer_id,
                        &o.key_id,
                        &o.public_key,
                        o.registered_height as i64,
                        o.ended_height.map(|h| h as i64),
                    ),
                )?;
            }
            StateEntry::CanaryCommitment(c) => {
                conn.execute(
                    "INSERT OR REPLACE INTO canary_commitments(update_id, planter, root, leaves, sealing_height) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (
                        &c.update_id,
                        &c.planter,
                        &c.root,
                        c.leaves as i64,
                        c.sealing_height as i64,
                    ),
                )?;
            }
            StateEntry::Escalation(e) => {
                conn.execute(
                    "INSERT OR REPLACE INTO escalations(domain, establishing_sealed_at) VALUES (?1, ?2)",
                    (&e.domain, &e.establishing_sealed_at),
                )?;
            }
            StateEntry::CoverageFailure(f) => {
                conn.execute(
                    "INSERT OR REPLACE INTO coverage_failures(auditor_id, block_number) VALUES (?1, ?2)",
                    (&f.auditor_id, f.block_number as i64),
                )?;
            }
            StateEntry::ReputationInputs(r) => {
                conn.execute(
                    "INSERT OR REPLACE INTO reputation_inputs(domain, first_accepted_sealed_at, reset_height, counted_total, counted_json, penalties_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    (
                        &r.domain,
                        &r.first_accepted_sealed_at,
                        r.reset_height.map(|h| h as i64),
                        r.counted_total as i64,
                        serde_json::to_string(&r.counted_url_digests)?,
                        serde_json::to_string(&r.penalties)?,
                    ),
                )?;
            }
            StateEntry::Record(r) => tips.adopt(&r.publisher, &r.url, &r.delta_id),
            StateEntry::AggregatorKey(k) => {
                adopted_keys.push((k.key_id.clone(), k.public_key.clone(), k.removed_height));
            }
            StateEntry::SanctionState(state) => {
                adopted_sanctions.push((state.domain.clone(), state.level));
            }
            StateEntry::Exclusion(e) => {
                adopted_exclusions.push((
                    e.publisher.clone(),
                    e.url.clone(),
                    e.excluded_since_height,
                ));
            }
            _ => {}
        }
    }
    for (domain, window_end, head, head_height) in &adopted_windows {
        history.adopt_window(domain, window_end, head, *head_height)?;
        persist_declaration(&conn, *head_height, "", true, head)?;
    }
    save_chain_tips(&conn, &tips)?;
    let mut ledger = load_sanctions(&conn)?;
    for (domain, level) in &adopted_sanctions {
        let entry = ledger.domains.entry(domain.clone()).or_default();
        entry.level = (*level).clamp(0, 4) as u8;
    }
    for (publisher, url, since) in &adopted_exclusions {
        ledger
            .exclusions
            .insert((publisher.clone(), url.clone()), *since);
    }
    save_sanctions(&conn, &ledger)?;

    let checkpoint_url = resolve(base, "/log/checkpoint.json")?;
    let (_, checkpoint_value) = client.get_json(&checkpoint_url)?;
    let checkpoint_env: CheckpointEnvelope = serde_json::from_value(checkpoint_value.clone())?;
    let checkpoint = checkpoint_env.checkpoint;

    if manifest.log_position > checkpoint.block_number {
        return Err(Error::Verify(
            "snapshot log_position is ahead of the checkpoint head".into(),
        ));
    }

    let mut aggregator_keys = load_aggregator_keys(&conn, genesis_key_id, trust_key)?;
    for (key_id, public_key, removed_height) in &adopted_keys {
        aggregator_keys.admit(key_id, public_key, removed_height.is_some())?;
    }
    let (events, last_block_value) = walk_blocks(
        client,
        base,
        &mut aggregator_keys,
        manifest.log_position + 1,
        checkpoint.block_number,
        &manifest.anchor_block_hash,
    )?;
    verify_checkpoint_signature(&checkpoint_value, &aggregator_keys)?;
    save_aggregator_keys(&conn, &aggregator_keys)?;

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

    let stats = apply_events(&conn, client, base, &mut history, &events, tier1)?;
    conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    if tier1 {
        conn.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )?;
    }
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

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn migrate_legacy_layout_is_noop_when_not_legacy() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!migrate_legacy_layout(dir.path(), "log-a").unwrap());
    }

    #[test]
    fn migrate_legacy_layout_moves_both_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.sqlite"), b"idx").unwrap();
        std::fs::write(dir.path().join("sync.json"), b"sync").unwrap();

        assert!(migrate_legacy_layout(dir.path(), "log-a").unwrap());

        let target = registry::log_dir(dir.path(), "log-a");
        assert_eq!(std::fs::read(target.join("index.sqlite")).unwrap(), b"idx");
        assert_eq!(std::fs::read(target.join("sync.json")).unwrap(), b"sync");
        assert!(!dir.path().join("index.sqlite").exists());
        assert!(!dir.path().join("sync.json").exists());
    }

    #[test]
    fn migrate_legacy_layout_restores_first_file_when_second_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.sqlite"), b"idx").unwrap();
        std::fs::write(dir.path().join("sync.json"), b"sync").unwrap();

        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(target.join("sync.json")).unwrap();

        let err = migrate_legacy_layout(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("sync.json"), "error was: {err}");

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite must be restored to the top level, not stranded in target_dir"
        );
        assert!(!target.join("index.sqlite").exists());
        assert_eq!(
            std::fs::read(dir.path().join("sync.json")).unwrap(),
            b"sync"
        );
    }

    #[test]
    fn rollback_migration_moves_files_back_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        rollback_migration(dir.path(), "log-a").unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx"
        );
        assert_eq!(
            std::fs::read(dir.path().join("sync.json")).unwrap(),
            b"sync"
        );
        assert!(!target.exists());
        assert!(!dir.path().join("logs.json").exists());
    }

    #[test]
    fn rollback_migration_leaves_target_dir_intact_when_first_rename_back_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        std::fs::create_dir_all(dir.path().join("index.sqlite")).unwrap();

        let err = rollback_migration(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("index.sqlite"), "error was: {err}");

        assert_eq!(
            std::fs::read(target.join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite must still be in target_dir, not deleted by a premature remove_dir_all"
        );
        assert_eq!(std::fs::read(target.join("sync.json")).unwrap(), b"sync");
        assert!(
            target.exists(),
            "target_dir must not be removed while rollback is incomplete"
        );
        assert!(dir.path().join("logs.json").exists());
    }

    #[test]
    fn rollback_migration_preserves_sync_json_when_second_rename_back_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        std::fs::create_dir_all(dir.path().join("sync.json")).unwrap();

        let err = rollback_migration(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("sync.json"), "error was: {err}");

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite rename-back had already succeeded and must not be undone"
        );
        assert_eq!(
            std::fs::read(target.join("sync.json")).unwrap(),
            b"sync",
            "sync.json must still be in target_dir, not deleted by a premature remove_dir_all"
        );
        assert!(
            target.exists(),
            "target_dir must not be removed while rollback is incomplete"
        );
        assert!(dir.path().join("logs.json").exists());
    }
}
