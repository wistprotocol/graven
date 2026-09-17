mod history;
mod install;
mod persist;
mod suffix;

use history::*;
pub use history::{AggregatorKeys, ApplyStats, BlockEvent, ChainState};
use install::*;
use persist::*;
pub use persist::{load_sync_state, save_sync_state, CREATE_SYNC_STATE};
use suffix::SuffixLists;

use crate::error::{Error, Result};

use crate::fetch::{resolve, Client};

use crate::registry::{self, LogEntry};

use crate::store::{CREATE_DECLARATIONS, CREATE_UNIQUE_INDEX};

use reqwest::Url;

use rusqlite::Connection;

use serde::{Deserialize, Serialize};

use std::path::Path;

use wist_core::block::verify_checkpoint_binding;

use wist_core::crypto::PublicKey;

use wist_core::objects::CheckpointEnvelope;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_first_s: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_sealed_at_s: Option<i64>,
    #[serde(default)]
    pub largest_block_bytes: u64,
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
    let index_path = log_dir.join("index.sqlite");

    let mut synced =
        index_path.exists() && load_sync_state(&Connection::open(&index_path)?)?.is_some();
    if !synced && sync_path.exists() {
        let sync_bytes = std::fs::read(&sync_path)?;
        wist_core::json::validate(&sync_bytes)?;
        let legacy: SyncState = serde_json::from_slice(&sync_bytes)?;
        if !index_path.exists() {
            return Err(Error::Verify(format!(
                "{} records a sync but {} is missing; remove the record to start over",
                sync_path.display(),
                index_path.display()
            )));
        }
        save_sync_state(&Connection::open(&index_path)?, &legacy)?;
        synced = true;
    }

    let subscriptions = crate::store::load_subscriptions(dir)?;
    if synced {
        run_incremental(
            client,
            base,
            trust_key,
            genesis_key_id,
            log_id,
            &log_dir,
            &sync_path,
            effective_tier1,
            &subscriptions,
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
            &subscriptions,
        )
    }
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
    subscriptions: &std::collections::BTreeSet<String>,
) -> Result<SyncReport> {
    let index_sqlite_path = dir.join("index.sqlite");
    let conn = Connection::open(&index_sqlite_path)?;
    let local = load_sync_state(&conn)?
        .ok_or_else(|| Error::Verify("the index carries no sync state".into()))?;

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
        let keys = load_aggregator_keys(&conn, genesis_key_id, trust_key)?;
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

    let mut aggregator_keys = load_aggregator_keys(&conn, genesis_key_id, trust_key)?;
    let mut chain = ChainState::restore(&local, load_parameters(&conn)?);
    let mut withdrawals = load_withdrawn(&conn)?;
    let mut suffix_lists = SuffixLists::load(&conn)?;
    let (events, last_block_value) = walk_blocks(
        client,
        base,
        &mut aggregator_keys,
        &mut chain,
        &mut withdrawals,
        &mut suffix_lists,
        local.head_number + 1,
        checkpoint.block_number,
        &local.head_hash,
    )?;
    verify_checkpoint_signature(&checkpoint_value, &aggregator_keys)?;
    let last_block_value = last_block_value.ok_or_else(|| {
        Error::Verify("continuous sync produced no blocks despite checkpoint advancing".into())
    })?;
    verify_checkpoint_binding(&checkpoint_value, &last_block_value)?;

    let mut history = load_history(&conn)?;
    let tx = conn.unchecked_transaction()?;
    save_parameters(&tx, &chain)?;
    suffix_lists.save(&tx)?;
    save_aggregator_keys(&tx, &aggregator_keys)?;
    tx.execute(CREATE_UNIQUE_INDEX, [])?;
    tx.execute(CREATE_DECLARATIONS, [])?;
    let stats = apply_events(
        &tx,
        client,
        base,
        &mut history,
        &events,
        tier1,
        local.log_position,
    )?;
    fetch_definitions(&tx, client, &history, subscriptions)?;
    tx.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    if tier1 {
        tx.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )?;
    }
    let sync_state = SyncState {
        log_position: local.log_position,
        head_number: checkpoint.block_number,
        head_hash: checkpoint.block_hash.clone(),
        content_digest: local.content_digest.clone(),
        schedule_first_s: chain.schedule_first_s(),
        prior_sealed_at_s: chain.prior_at(),
        largest_block_bytes: chain.largest(),
    };
    save_sync_state(&tx, &sync_state)?;
    tx.commit()?;
    mirror_sync_state(sync_path, &sync_state);

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
    subscriptions: &std::collections::BTreeSet<String>,
) -> Result<SyncReport> {
    let mut installed = install::snapshot(client, base, trust_key, genesis_key_id, dir, tier1)?;
    let checkpoint_url = resolve(base, "/log/checkpoint.json")?;
    let (_, checkpoint_value) = client.get_json(&checkpoint_url)?;
    let checkpoint_env: CheckpointEnvelope = serde_json::from_value(checkpoint_value.clone())?;
    let checkpoint = checkpoint_env.checkpoint;

    if installed.log_position > checkpoint.block_number {
        return Err(Error::Verify(
            "snapshot log_position is ahead of the checkpoint head".into(),
        ));
    }

    let mut withdrawals = load_withdrawn(&installed.conn)?;
    let (events, last_block_value) = walk_blocks(
        client,
        base,
        &mut installed.aggregator_keys,
        &mut installed.chain,
        &mut withdrawals,
        &mut installed.suffix_lists,
        installed.log_position + 1,
        checkpoint.block_number,
        &installed.anchor_block_hash,
    )?;
    save_parameters(&installed.conn, &installed.chain)?;
    installed.suffix_lists.save(&installed.conn)?;
    verify_checkpoint_signature(&checkpoint_value, &installed.aggregator_keys)?;
    save_aggregator_keys(&installed.conn, &installed.aggregator_keys)?;

    match &last_block_value {
        Some(block_value) => verify_checkpoint_binding(&checkpoint_value, block_value)?,
        None => {
            if checkpoint.block_number != installed.log_position
                || checkpoint.block_hash != installed.anchor_block_hash
            {
                return Err(Error::Verify(
                    "checkpoint does not match the snapshot anchor at equal heights".into(),
                ));
            }
        }
    }

    let stats = apply_events(
        &installed.conn,
        client,
        base,
        &mut installed.history,
        &events,
        tier1,
        installed.log_position,
    )?;
    fetch_definitions(&installed.conn, client, &installed.history, subscriptions)?;
    installed
        .conn
        .execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    if tier1 {
        installed.conn.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )?;
    }
    let sync_state = SyncState {
        log_position: installed.log_position,
        head_number: checkpoint.block_number,
        head_hash: checkpoint.block_hash.clone(),
        content_digest: Some(installed.content_digest.clone()),
        schedule_first_s: installed.chain.schedule_first_s(),
        prior_sealed_at_s: installed.chain.prior_at(),
        largest_block_bytes: installed.chain.largest(),
    };
    save_sync_state(&installed.conn, &sync_state)?;
    installed.commit(dir)?;
    mirror_sync_state(sync_path, &sync_state);

    Ok(SyncReport {
        log_id: log_id.to_string(),
        log_position_before: None,
        head: checkpoint.block_number,
        withdrawn: stats.withdrawn,
    })
}

/// Writes the committed sync state next to the index for readers of the
/// file; the index row is authoritative, so a failure here changes
/// nothing a later sync relies on.
fn mirror_sync_state(sync_path: &Path, state: &SyncState) {
    if let Ok(bytes) = serde_json::to_vec(state) {
        let _ = std::fs::write(sync_path, bytes);
    }
}
