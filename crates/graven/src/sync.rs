pub mod checkpoints;
mod history;
mod install;
mod persist;
pub mod source;
mod suffix;
pub mod tree;

use history::*;
pub use history::{ApplyStats, ChainState, EpochEvent};
use install::*;
use persist::*;
pub use persist::{load_sync_state, save_sync_state, CREATE_SYNC_STATE};
use suffix::SuffixLists;

pub use checkpoints::{parse_roster, parse_witness_key, CREATE_CHECKPOINTS};
pub use source::Sources;
pub use tree::Tree;

use crate::error::{Error, Result};

use crate::fetch::Client;

use crate::registry::{self, LogEntry};

use crate::store::{CREATE_DECLARATIONS, CREATE_UNIQUE_INDEX};

use rusqlite::Connection;

use serde::{Deserialize, Serialize};

use std::path::Path;

use wist_core::checkpoint::{Adoption, Checkpoint, WitnessKey};

use wist_core::aggregator_keys::Registry;

use wist_core::crypto::PublicKey;

use wist_core::objects::GenesisKey;

#[derive(Debug, Clone)]
pub struct SyncReport {
    pub log_id: String,
    pub epoch_number_before: Option<u64>,
    pub head: u64,
    /// The tree size the adopted Checkpoint states (WIST-3 §7's
    /// `tree_size`).
    pub tree_size: u64,
    pub root: String,
    /// WIST-3 §5's interim: the adopted Checkpoint carried no Cosignature
    /// from a Witness this Consumer trusts.
    pub unwitnessed: bool,
    /// WIST-3 §5: the newest Checkpoint this Consumer can accept — the
    /// one it adopted, or the verified head it kept where nothing above
    /// it was acceptable — lags the current time by more than three
    /// sealing cadences.
    pub stale: bool,
    pub withdrawn: u64,
}

/// The format the sync state is written in. A store written before the
/// Log became one growing tree carries no `format` member and names a
/// Block hash rather than a tree size; one written before `block_number`
/// and `log_position` became `epoch_number` and `tree_size` carries an
/// older `format` member. Either is refused rather than reinterpreted.
pub const SYNC_STATE_FORMAT: u32 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub format: u32,
    /// The tree size the verified head states (WIST-3 §7).
    pub tree_size: u64,
    /// The Epoch the verified head ends.
    pub epoch_number: u64,
    /// The root of the tree at `tree_size`, in the `sha256:` form of
    /// WIST-3 §3.1.
    pub root: String,
    #[serde(default)]
    pub unwitnessed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_first_s: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_sealed_at_s: Option<i64>,
    #[serde(default)]
    pub largest_epoch_bytes: u64,
}

/// How a Log is configured: where its Anchor and its files come from, and
/// which Witnesses this Consumer trusts (WIST-3 §5).
#[derive(Debug, Clone)]
pub struct Follow<'a> {
    pub anchor: &'a str,
    pub log_base: &'a str,
    pub mirrors: &'a [String],
    pub witnesses: &'a [String],
    pub tier1: bool,
    pub allow_http: bool,
}

pub fn run(
    anchor: &str,
    log_base: &str,
    dir: &Path,
    allow_http: bool,
    tier1: bool,
) -> Result<SyncReport> {
    follow(
        &Follow {
            anchor,
            log_base,
            mirrors: &[],
            witnesses: &[],
            tier1,
            allow_http,
        },
        dir,
    )
}

pub fn follow(config: &Follow, dir: &Path) -> Result<SyncReport> {
    std::fs::create_dir_all(dir)?;

    let client = Client::new(config.allow_http);
    let (trust_key, log_id, genesis) = load_anchor(config.anchor, &client)?;
    registry::validate_log_id(&log_id)?;

    let migrated = migrate_legacy_layout(dir, &log_id)?;

    match run_registered(config, &client, &trust_key, &genesis, dir, &log_id) {
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
        .map(|entry| {
            follow(
                &Follow {
                    anchor: &entry.anchor,
                    log_base: &entry.base,
                    mirrors: &entry.mirrors,
                    witnesses: &entry.witnesses,
                    tier1: entry.tier1,
                    allow_http,
                },
                dir,
            )
        })
        .collect()
}

/// The registry entry this call registers or confirms, with the Mirror
/// list and Witness roster it leaves in force.
fn register(dir: &Path, config: &Follow, log_id: &str) -> Result<LogEntry> {
    let mut reg = registry::load(dir)?;
    if let Some(other) = registry::find_collision(&reg.logs, log_id) {
        return Err(Error::Verify(format!(
            "log_id {log_id:?} sanitizes to the same directory as already-registered log_id {:?} (both -> {:?}); refusing to register to avoid a cross-log directory collision",
            other.log_id,
            registry::sanitize(log_id)
        )));
    }
    let entry = match reg.logs.iter_mut().find(|e| e.log_id == log_id) {
        Some(entry) => {
            if entry.anchor != config.anchor || entry.base != config.log_base {
                return Err(Error::Verify(format!(
                    "log {log_id} is already registered with anchor={} base={}; requested anchor={} base={} conflicts with it",
                    entry.anchor, entry.base, config.anchor, config.log_base
                )));
            }
            if config.tier1 {
                entry.tier1 = true;
            }
            for mirror in config.mirrors {
                if !entry.mirrors.contains(mirror) {
                    entry.mirrors.push(mirror.clone());
                }
            }
            if !config.witnesses.is_empty() {
                entry.witnesses = config.witnesses.to_vec();
            }
            entry.clone()
        }
        None => {
            let entry = LogEntry {
                log_id: log_id.to_string(),
                anchor: config.anchor.to_string(),
                base: config.log_base.to_string(),
                tier1: config.tier1,
                mirrors: config.mirrors.to_vec(),
                witnesses: config.witnesses.to_vec(),
            };
            reg.logs.push(entry.clone());
            entry
        }
    };
    registry::save(dir, &reg)?;
    Ok(entry)
}

fn run_registered(
    config: &Follow,
    client: &Client,
    trust_key: &PublicKey,
    genesis: &GenesisKey,
    dir: &Path,
    log_id: &str,
) -> Result<SyncReport> {
    let entry = register(dir, config, log_id)?;
    let witnesses = parse_roster(&entry.witnesses)?;
    let mut bases = vec![crate::fetch::parse_base(&entry.base)?];
    for mirror in &entry.mirrors {
        bases.push(crate::fetch::parse_base(mirror)?);
    }
    let sources = Sources::new(client, bases);

    let log_dir = registry::log_dir(dir, log_id);
    std::fs::create_dir_all(&log_dir)?;
    // WIST-3 §5: a Consumer that verified an equivocation or a chain
    // divergence stops applying new data from that Aggregator.
    checkpoints::halted(&log_dir)?;
    let sync_path = log_dir.join("sync.json");
    let index_path = log_dir.join("index.sqlite");

    let mut synced =
        index_path.exists() && load_sync_state(&Connection::open(&index_path)?)?.is_some();
    if !synced && sync_path.exists() {
        let sync_bytes = std::fs::read(&sync_path)?;
        wist_core::json::validate(&sync_bytes)?;
        let legacy = read_sync_state(&sync_bytes)?;
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
    let context = SyncContext {
        sources: &sources,
        log_id,
        witnesses: &witnesses,
        trust_key,
        genesis,
        log_dir: &log_dir,
        sync_path: &sync_path,
        tier1: entry.tier1,
        subscriptions: &subscriptions,
    };
    if synced {
        run_incremental(&context)
    } else {
        run_cold_start(&context)
    }
}

struct SyncContext<'a> {
    sources: &'a Sources<'a>,
    log_id: &'a str,
    witnesses: &'a [WitnessKey],
    trust_key: &'a PublicKey,
    genesis: &'a GenesisKey,
    log_dir: &'a Path,
    sync_path: &'a Path,
    tier1: bool,
    subscriptions: &'a std::collections::BTreeSet<String>,
}

/// The state a walk mutates, restored from the committed index before
/// every attempt so that nothing an Epoch above the adopted Checkpoint
/// establishes survives into the store.
struct Restored {
    keys: Registry,
    chain: ChainState,
    withdrawals: wist_core::withdrawal::WithdrawalReplay,
    suffix_lists: SuffixLists,
    tree: Tree,
}

fn restore(conn: &Connection, context: &SyncContext, local: &SyncState) -> Result<Restored> {
    Ok(Restored {
        keys: load_aggregator_keys(conn, context.log_id, context.genesis)?,
        chain: ChainState::restore(local, load_parameters(conn)?),
        withdrawals: load_withdrawn(conn)?,
        suffix_lists: SuffixLists::load(conn)?,
        tree: Tree::load(conn)?,
    })
}

/// WIST-3 §8's continuous operation, steps 1–3: the offered head, the
/// archived Checkpoints between it and the verified head, and the newest
/// of them the Witness quorum admits.
fn offered_above(
    context: &SyncContext,
    conn: &Connection,
    head_epoch_number: u64,
    keys: &Registry,
) -> Result<Vec<Checkpoint>> {
    let Some(head) = checkpoints::offered_head(
        context.sources,
        context.log_dir,
        conn,
        context.log_id,
        head_epoch_number,
        keys,
    )?
    else {
        return Ok(Vec::new());
    };
    let mut offered = Vec::new();
    for number in head_epoch_number + 1..head.epoch_number() {
        offered.push(checkpoints::archived(context.sources, number)?);
    }
    offered.push(head);
    Ok(offered)
}

/// The Checkpoint the Consumer adopts and the Epochs up to it, walked
/// from the committed state. A Checkpoint short of the quorum leaves the
/// head where it is, so the walk is repeated at the newest Checkpoint the
/// quorum admits; the Entries above it are never handed to the index.
fn walk_to_adoption(
    context: &SyncContext,
    conn: &Connection,
    local: &SyncState,
    head: &Checkpoint,
    offered: &[Checkpoint],
) -> Result<Option<(Restored, Walk, Checkpoint, bool)>> {
    let mut end = offered.len();
    while end > 0 {
        let mut restored = restore(conn, context, local)?;
        let mut state = WalkState {
            keys: &mut restored.keys,
            chain: &mut restored.chain,
            withdrawals_replay: &mut restored.withdrawals,
            suffix_lists: &mut restored.suffix_lists,
            tree: &mut restored.tree,
        };
        let inputs = WalkInputs {
            sources: context.sources,
            log_id: context.log_id,
            witnesses: context.witnesses,
            log_dir: context.log_dir,
        };
        let walk = walk_checkpoints(&inputs, &mut state, head, &offered[..end])?;
        match walk.adopted() {
            None => return Ok(None),
            Some(adopted) => {
                let number = adopted.checkpoint.epoch_number();
                let unwitnessed =
                    matches!(adopted.adoption, Adoption::Adopted { unwitnessed: true });
                if number == offered[end - 1].epoch_number() {
                    let checkpoint = adopted.checkpoint.clone();
                    return Ok(Some((restored, walk, checkpoint, unwitnessed)));
                }
                end = offered
                    .iter()
                    .position(|c| c.epoch_number() == number)
                    .map(|index| index + 1)
                    .unwrap_or(0);
            }
        }
    }
    Ok(None)
}

fn run_incremental(context: &SyncContext) -> Result<SyncReport> {
    let index_sqlite_path = context.log_dir.join("index.sqlite");
    let conn = Connection::open(&index_sqlite_path)?;
    let local = load_sync_state(&conn)?
        .ok_or_else(|| Error::Verify("the index carries no sync state".into()))?;
    let head = checkpoints::retained(&conn, local.epoch_number)?.ok_or_else(|| {
        Error::Verify(
            "the index carries no Checkpoint at its verified head; remove the store and sync again"
                .into(),
        )
    })?;
    let cadence = ChainState::restore(&local, load_parameters(&conn)?).cadence();
    let unchanged = |stale: bool| SyncReport {
        log_id: context.log_id.to_string(),
        epoch_number_before: Some(local.epoch_number),
        head: local.epoch_number,
        tree_size: local.tree_size,
        root: local.root.clone(),
        unwitnessed: local.unwitnessed,
        stale,
        withdrawn: 0,
    };

    let keys = load_aggregator_keys(&conn, context.log_id, context.genesis)?;
    let offered = match offered_above(context, &conn, local.epoch_number, &keys) {
        Ok(offered) => offered,
        // No source served a head: the verified head is the newest
        // Checkpoint this Consumer can accept, and its staleness is
        // reported with the failure.
        Err(error) => {
            return Err(
                match checkpoints::warn_if_stale(context.log_id, &head, cadence) {
                    true => Error::Verify(format!(
                        "{error}; the verified head at epoch {} is stale, sealed at {}",
                        local.epoch_number,
                        head.sealed_at()
                    )),
                    false => error,
                },
            )
        }
    };
    if offered.is_empty() {
        return Ok(unchanged(checkpoints::warn_if_stale(
            context.log_id,
            &head,
            cadence,
        )));
    }

    let Some((restored, walk, adopted, unwitnessed)) =
        walk_to_adoption(context, &conn, &local, &head, &offered)?
    else {
        eprintln!(
            "log {}: no Checkpoint above epoch {} carries the Witness quorum in force; keeping the verified head",
            context.log_id, local.epoch_number
        );
        return Ok(unchanged(checkpoints::warn_if_stale(
            context.log_id,
            &head,
            cadence,
        )));
    };

    let Restored {
        keys,
        chain,
        suffix_lists,
        tree,
        ..
    } = restored;
    let mut history = load_history(&conn)?;
    let tx = conn.unchecked_transaction()?;
    save_parameters(&tx, &chain)?;
    suffix_lists.save(&tx)?;
    save_aggregator_keys(&tx, &keys)?;
    tree.save(&tx)?;
    for verified in &walk.verified {
        let adopted_here = verified.checkpoint.epoch_number() == adopted.epoch_number();
        checkpoints::save_checkpoint(
            &tx,
            &verified.checkpoint,
            adopted_here.then_some(unwitnessed),
        )?;
    }
    tx.execute(CREATE_UNIQUE_INDEX, [])?;
    tx.execute(CREATE_DECLARATIONS, [])?;
    let stats = apply_events(
        &tx,
        context.sources.client(),
        context.sources.primary(),
        &mut history,
        &walk.events,
        context.tier1,
        local.epoch_number,
    )?;
    fetch_definitions(
        &tx,
        context.sources.client(),
        &history,
        context.subscriptions,
    )?;
    tx.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    if context.tier1 {
        tx.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )?;
    }
    let sync_state = SyncState {
        format: SYNC_STATE_FORMAT,
        tree_size: adopted.tree_size(),
        epoch_number: adopted.epoch_number(),
        root: adopted.root_token(),
        unwitnessed,
        content_digest: local.content_digest.clone(),
        schedule_first_s: chain.schedule_first_s(),
        prior_sealed_at_s: chain.prior_at(),
        largest_epoch_bytes: chain.largest(),
    };
    save_sync_state(&tx, &sync_state)?;
    tx.commit()?;
    mirror_sync_state(context.sync_path, &sync_state);
    let stale = checkpoints::warn_if_stale(context.log_id, &adopted, chain.cadence());

    Ok(SyncReport {
        log_id: context.log_id.to_string(),
        epoch_number_before: Some(local.epoch_number),
        head: sync_state.epoch_number,
        tree_size: sync_state.tree_size,
        root: sync_state.root.clone(),
        unwitnessed,
        stale,
        withdrawn: stats.withdrawn,
    })
}

fn run_cold_start(context: &SyncContext) -> Result<SyncReport> {
    let mut installed = install::snapshot(
        context.sources,
        context.trust_key,
        context.log_id,
        context.genesis,
        context.log_dir,
        context.tier1,
    )?;
    // WIST-3 §8 step 5: the Checkpoint at the Snapshot's Epoch, verified
    // under the `aggregator_key` tuples just loaded, states the tree the
    // manifest names or the Snapshot describes another tree entirely.
    let anchor = checkpoints::archived(context.sources, installed.manifest.epoch_number)?;
    let verification = wist_core::checkpoint::verify(
        &anchor,
        context.log_id,
        &installed
            .aggregator_keys
            .valid_at(installed.manifest.epoch_number),
        context.witnesses,
    )?;
    wist_core::snapshot::check_manifest_anchor(&installed.manifest, &anchor)?;
    let sealed_at_s = anchor.sealed_at_s()?;
    installed.chain.seed_prior(sealed_at_s);
    let anchor_adoption =
        wist_core::checkpoint::adoption(&verification, installed.chain.quorum_at(sealed_at_s));
    installed.history.seed_head(
        anchor.epoch_number(),
        &anchor.root_token(),
        Some(sealed_at_s),
    );
    let mut tree = Tree::new();
    tree::seed(
        context.sources,
        &mut tree,
        anchor.tree_size(),
        anchor.root(),
    )?;
    tree.save(&installed.conn)?;
    installed.suffix_lists.save(&installed.conn)?;
    save_parameters(&installed.conn, &installed.chain)?;
    save_aggregator_keys(&installed.conn, &installed.aggregator_keys)?;
    checkpoints::save_checkpoint(
        &installed.conn,
        &anchor,
        Some(matches!(
            anchor_adoption,
            Adoption::Adopted { unwitnessed: true }
        )),
    )?;
    let anchor_state = SyncState {
        format: SYNC_STATE_FORMAT,
        tree_size: anchor.tree_size(),
        epoch_number: anchor.epoch_number(),
        root: anchor.root_token(),
        unwitnessed: matches!(anchor_adoption, Adoption::Adopted { unwitnessed: true }),
        content_digest: Some(installed.content_digest.clone()),
        schedule_first_s: installed.chain.schedule_first_s(),
        prior_sealed_at_s: installed.chain.prior_at(),
        largest_epoch_bytes: installed.chain.largest(),
    };
    save_sync_state(&installed.conn, &anchor_state)?;
    let cadence = installed.chain.cadence();
    let offered = offered_above(
        context,
        &installed.conn,
        anchor.epoch_number(),
        &installed.aggregator_keys,
    )?;

    let walked = if offered.is_empty() {
        None
    } else {
        walk_to_adoption(context, &installed.conn, &anchor_state, &anchor, &offered)?
    };

    let (adopted, unwitnessed, events, verified, state) = match walked {
        Some((restored, walk, adopted, unwitnessed)) => (
            adopted,
            unwitnessed,
            walk.events,
            walk.verified,
            Some(restored),
        ),
        None => {
            if matches!(anchor_adoption, Adoption::NotAdopted) {
                return Err(Error::Verify(format!(
                    "log {}: no Checkpoint from the Snapshot's Epoch upward carries the Witness quorum in force, so there is no state to act on; this is a wait, not a fault, and the sync can be retried",
                    context.log_id
                )));
            }
            (
                anchor.clone(),
                anchor_state.unwitnessed,
                Vec::new(),
                Vec::new(),
                None,
            )
        }
    };

    if let Some(state) = state {
        save_parameters(&installed.conn, &state.chain)?;
        state.suffix_lists.save(&installed.conn)?;
        save_aggregator_keys(&installed.conn, &state.keys)?;
        state.tree.save(&installed.conn)?;
        installed.chain = state.chain;
    }
    for entry in &verified {
        let adopted_here = entry.checkpoint.epoch_number() == adopted.epoch_number();
        checkpoints::save_checkpoint(
            &installed.conn,
            &entry.checkpoint,
            adopted_here.then_some(unwitnessed),
        )?;
    }

    let stats = apply_events(
        &installed.conn,
        context.sources.client(),
        context.sources.primary(),
        &mut installed.history,
        &events,
        context.tier1,
        anchor.epoch_number(),
    )?;
    fetch_definitions(
        &installed.conn,
        context.sources.client(),
        &installed.history,
        context.subscriptions,
    )?;
    installed
        .conn
        .execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    if context.tier1 {
        installed.conn.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )?;
    }
    let sync_state = SyncState {
        format: SYNC_STATE_FORMAT,
        tree_size: adopted.tree_size(),
        epoch_number: adopted.epoch_number(),
        root: adopted.root_token(),
        unwitnessed,
        content_digest: Some(installed.content_digest.clone()),
        schedule_first_s: installed.chain.schedule_first_s(),
        prior_sealed_at_s: installed.chain.prior_at(),
        largest_epoch_bytes: installed.chain.largest(),
    };
    save_sync_state(&installed.conn, &sync_state)?;
    installed.commit(context.log_dir)?;
    mirror_sync_state(context.sync_path, &sync_state);
    let stale = checkpoints::warn_if_stale(context.log_id, &adopted, cadence);

    Ok(SyncReport {
        log_id: context.log_id.to_string(),
        epoch_number_before: None,
        head: sync_state.epoch_number,
        tree_size: sync_state.tree_size,
        root: sync_state.root.clone(),
        unwitnessed,
        stale,
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
