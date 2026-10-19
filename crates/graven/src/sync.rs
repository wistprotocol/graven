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

use crate::keyset::KeyHistory;

use crate::registry::{self, LogEntry};

use crate::store::{CREATE_DECLARATIONS, CREATE_UNIQUE_INDEX};

use rusqlite::Connection;

use serde::{Deserialize, Serialize};

use std::path::Path;

use wist_core::checkpoint::{Adoption, Checkpoint, WitnessKey};

use wist_core::aggregator_keys::Registry;

use wist_core::objects::Anchor;

use wist_core::sealing::Replay;

#[derive(Debug, Clone)]
pub struct SyncReport {
    pub log_id: String,
    pub epoch_number_before: Option<u64>,
    pub head: u64,
    pub tree_size: u64,
    pub root: String,
    /// WIST-3 §5.
    pub unwitnessed: bool,
    /// WIST-3 §5.
    pub stale: bool,
    pub withdrawn: u64,
    /// WIST-1 §5.2: walked by this run and applying nothing.
    pub rejected: Vec<RejectedEpoch>,
    pub snapshot_rejected: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedEpoch {
    pub epoch_number: u64,
    pub codes: Vec<String>,
}

impl std::fmt::Display for RejectedEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.epoch_number, self.codes.join(", "))
    }
}

impl std::fmt::Display for SyncReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let from = self
            .epoch_number_before
            .map_or_else(|| "cold start".to_string(), |n| n.to_string());
        let witnessing = if self.unwitnessed {
            "unwitnessed"
        } else {
            "witnessed"
        };
        let staleness = if self.stale { ", stale" } else { "" };
        write!(
            f,
            "[{}] synced from {from} to head epoch {} (tree size {}, root {}, {witnessing}{staleness}), withdrawn {}",
            self.log_id, self.head, self.tree_size, self.root, self.withdrawn
        )?;
        if !self.rejected.is_empty() {
            let rejected: Vec<String> = self.rejected.iter().map(ToString::to_string).collect();
            write!(f, ", rejected epochs {}", rejected.join("; "))?;
        }
        if let Some(rejection) = &self.snapshot_rejected {
            write!(f, ", snapshot catch-up rejected: {rejection}")?;
        }
        Ok(())
    }
}

pub const SYNC_STATE_FORMAT: u32 = 7;

pub const DEFAULT_CATCH_UP_EPOCHS: u64 = 720;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub format: u32,
    pub tree_size: u64,
    pub epoch_number: u64,
    /// The `sha256:` form of WIST-3 §3.1.
    pub root: String,
    #[serde(default)]
    pub unwitnessed: bool,
    /// The installed Snapshot's, which a pack names (WIST-3 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_tree_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_first_s: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_sealed_at_s: Option<i64>,
    #[serde(default)]
    pub largest_epoch_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walk_floor: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_epochs: Vec<RejectedEpoch>,
}

fn rejected_in(events: &[EpochEvent]) -> Vec<RejectedEpoch> {
    events
        .iter()
        .filter_map(|event| {
            event.rejected.as_ref().map(|codes| RejectedEpoch {
                epoch_number: event.height,
                codes: codes.clone(),
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Follow<'a> {
    pub anchor: &'a str,
    pub log_base: &'a str,
    pub mirrors: &'a [String],
    pub witnesses: &'a [String],
    pub tier1: bool,
    pub allow_http: bool,
    pub catch_up_epochs: Option<u64>,
    pub payload_fetches: usize,
}

pub const DEFAULT_PAYLOAD_FETCHES: usize = 16;

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
            catch_up_epochs: None,
            payload_fetches: DEFAULT_PAYLOAD_FETCHES,
        },
        dir,
    )
}

pub fn follow(config: &Follow, dir: &Path) -> Result<SyncReport> {
    std::fs::create_dir_all(dir)?;

    let client = Client::new(config.allow_http);
    let anchor = load_anchor(config.anchor, &client)?;
    let log_id = anchor.log_id.clone();
    registry::validate_log_id(&log_id)?;

    let migrated = migrate_legacy_layout(dir, &log_id)?;

    match run_registered(config, &client, &anchor, dir, &log_id) {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRow {
    pub url: String,
    pub publisher: String,
    pub item_id: String,
    pub observed_at: String,
    pub attested_at: String,
    pub collection: Option<String>,
    pub generated_at: Option<String>,
    pub lang: Option<String>,
}

pub fn record_rows(log_dir: &Path) -> Result<Vec<RecordRow>> {
    let conn = Connection::open(log_dir.join("index.sqlite"))?;
    let mut stmt = conn.prepare(
        "SELECT url, publisher, item_id, observed_at, attested_at, collection, generated_at, lang
         FROM records ORDER BY publisher, url",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(RecordRow {
                url: row.get(0)?,
                publisher: row.get(1)?,
                item_id: row.get(2)?,
                observed_at: row.get(3)?,
                attested_at: row.get(4)?,
                collection: row.get(5)?,
                generated_at: row.get(6)?,
                lang: row.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn replayed_records(log_dir: &Path) -> Result<Vec<RecordRow>> {
    let conn = Connection::open(log_dir.join("index.sqlite"))?;
    let state = load_sync_state(&conn)?.ok_or_else(|| Error::NotSynced(log_dir.to_path_buf()))?;
    let head = checkpoints::retained(&conn, state.epoch_number)?.ok_or_else(|| {
        Error::Verify(format!(
            "the store retains no Checkpoint at its head epoch {}",
            state.epoch_number
        ))
    })?;
    let replay = load_replay(&conn, &head, state.walk_floor)?;
    replay
        .materialized()?
        .into_iter()
        .map(|tuple| {
            let record = replay
                .records()
                .record(&tuple.publisher, &tuple.url)
                .ok_or_else(|| {
                    Error::Verify(format!(
                        "the replay materializes {} of {} without its record",
                        tuple.url, tuple.publisher
                    ))
                })?;
            Ok(RecordRow {
                collection: Some(record.collection.clone()),
                generated_at: Some(record.generated_at.clone()),
                lang: record.item["meta"]["lang"].as_str().map(str::to_owned),
                url: tuple.url,
                publisher: tuple.publisher,
                item_id: tuple.item_id,
                observed_at: tuple.observed_at,
                attested_at: tuple.attested_at,
            })
        })
        .collect()
}

pub fn run_all(dir: &Path, allow_http: bool, payload_fetches: usize) -> Result<Vec<SyncReport>> {
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
                    catch_up_epochs: entry.catch_up_epochs,
                    payload_fetches,
                },
                dir,
            )
        })
        .collect()
}

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
            if config.catch_up_epochs.is_some() {
                entry.catch_up_epochs = config.catch_up_epochs;
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
                catch_up_epochs: config.catch_up_epochs,
            };
            reg.logs.push(entry.clone());
            entry
        }
    };
    registry::save(dir, &reg)?;
    Ok(entry)
}

fn holds_verified_head(log_dir: &Path) -> bool {
    let index = log_dir.join("index.sqlite");
    index.exists()
        && Connection::open(&index)
            .ok()
            .and_then(|conn| load_sync_state(&conn).ok())
            .flatten()
            .is_some()
}

/// WIST-3 §8: nothing derived from an unverified Snapshot persists, this run's registration
/// included.
fn undo_registration(dir: &Path, before: Option<Vec<u8>>, error: Error) -> Error {
    match registry::restore(dir, before) {
        Ok(()) => error,
        Err(undo) => Error::Verify(format!(
            "{error}; additionally, the registration this run made could not be undone: {undo}"
        )),
    }
}

fn run_registered(
    config: &Follow,
    client: &Client,
    anchor: &Anchor,
    dir: &Path,
    log_id: &str,
) -> Result<SyncReport> {
    let before = registry::held(dir);
    let entry = register(dir, config, log_id)?;
    let witnesses = parse_roster(&entry.witnesses)?;
    let mut bases = vec![crate::fetch::parse_base(&entry.base)?];
    for mirror in &entry.mirrors {
        bases.push(crate::fetch::parse_base(mirror)?);
    }
    let sources = Sources::new(client, bases);

    let log_dir = registry::log_dir(dir, log_id);
    std::fs::create_dir_all(&log_dir)?;
    // WIST-3 §5.
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
        anchor,
        log_dir: &log_dir,
        sync_path: &sync_path,
        tier1: entry.tier1,
        payload_fetches: config.payload_fetches,
        subscriptions: &subscriptions,
    };
    if synced {
        return run_incremental(
            &context,
            entry.catch_up_epochs.unwrap_or(DEFAULT_CATCH_UP_EPOCHS),
        );
    }
    run_cold_start(&context).map_err(|error| match holds_verified_head(&log_dir) {
        true => error,
        false => undo_registration(dir, before, error),
    })
}

struct SyncContext<'a> {
    sources: &'a Sources<'a>,
    log_id: &'a str,
    witnesses: &'a [WitnessKey],
    anchor: &'a Anchor,
    log_dir: &'a Path,
    sync_path: &'a Path,
    tier1: bool,
    payload_fetches: usize,
    subscriptions: &'a std::collections::BTreeSet<String>,
}

/// Restored from the committed index before every attempt, so nothing an Epoch above the adopted
/// Checkpoint establishes survives.
struct Restored {
    keys: Registry,
    chain: ChainState,
    replay: Replay,
    suffix_lists: SuffixLists,
    tree: Tree,
}

fn restore(
    conn: &Connection,
    context: &SyncContext,
    local: &SyncState,
    head: &Checkpoint,
) -> Result<Restored> {
    let replay = load_replay(conn, head, local.walk_floor)?;
    let accepted = replay.registry_updates().clone();
    let mut keys = load_aggregator_keys(conn, context.anchor, local.epoch_number)?;
    keys.hold_accepted_updates(accepted.clone());
    let mut chain = ChainState::restore(local, load_parameters(conn)?);
    chain.hold_accepted_updates(accepted.clone());
    let mut suffix_lists = SuffixLists::load(conn)?;
    suffix_lists.hold_accepted_updates(accepted);
    Ok(Restored {
        keys,
        chain,
        replay,
        suffix_lists,
        tree: Tree::load(conn)?,
    })
}

/// WIST-3 §5: a Checkpoint no source served ends the sequence.
#[derive(Default)]
struct Offered {
    checkpoints: Vec<Checkpoint>,
    stopped: Option<Stop>,
}

/// WIST-3 §8 continuous operation, steps 1–3.
fn offered_above(
    context: &SyncContext,
    conn: &Connection,
    head_epoch_number: u64,
    keys: &Registry,
) -> Result<Offered> {
    let Some(head) = checkpoints::offered_head(
        context.sources,
        context.log_dir,
        conn,
        context.log_id,
        head_epoch_number,
        keys,
    )?
    else {
        return Ok(Offered::default());
    };
    let mut checkpoints = Vec::new();
    for number in head_epoch_number + 1..head.epoch_number() {
        match checkpoints::archived_between(context.sources, number) {
            Ok(checkpoint) => checkpoints.push(checkpoint),
            // WIST-3 §9: chain divergence applies nothing; `WIST3-E01` and `WIST3-E03` keep the
            // Epochs below it (§8 step 8).
            Err(error) => {
                if error.code().as_deref() == Some("WIST3-E02") {
                    return Err(error);
                }
                return Ok(Offered {
                    checkpoints,
                    stopped: Some(Stop {
                        epoch_number: number,
                        error,
                    }),
                });
            }
        }
    }
    checkpoints.push(head);
    Ok(Offered {
        checkpoints,
        stopped: None,
    })
}

/// WIST-3 §8 step 8.
fn stopped_run(report: &SyncReport, stop: Stop) -> Error {
    eprintln!("{report}");
    Error::Verify(format!(
        "{}; this sync stopped at epoch {} and its verified head is epoch {}",
        stop.error, stop.epoch_number, report.head
    ))
}

fn first_stop(fetching: Option<Stop>, walking: Option<Stop>) -> Option<Stop> {
    match (fetching, walking) {
        (Some(fetching), Some(walking)) => {
            Some(match walking.epoch_number < fetching.epoch_number {
                true => walking,
                false => fetching,
            })
        }
        (fetching, walking) => fetching.or(walking),
    }
}

struct Walked {
    adopted: Option<(Restored, Walk, Checkpoint, bool)>,
    stopped: Option<Stop>,
}

/// Entries above the newest Checkpoint the quorum admits never reach the index.
fn walk_to_adoption(
    context: &SyncContext,
    conn: &Connection,
    local: &SyncState,
    head: &Checkpoint,
    offered: &[Checkpoint],
) -> Result<Walked> {
    let mut end = offered.len();
    let mut stopped: Option<Stop> = None;
    while end > 0 {
        let mut restored = restore(conn, context, local, head)?;
        let mut state = WalkState {
            keys: &mut restored.keys,
            chain: &mut restored.chain,
            replay: &mut restored.replay,
            suffix_lists: &mut restored.suffix_lists,
            tree: &mut restored.tree,
        };
        let inputs = WalkInputs {
            sources: context.sources,
            log_id: context.log_id,
            witnesses: context.witnesses,
            log_dir: context.log_dir,
        };
        let mut walk = walk_checkpoints(&inputs, &mut state, head, &offered[..end])?;
        // WIST-3 §8 step 8: the failing Epoch may have applied part of its Registry Updates, so the
        // Epochs below it are walked again from the committed state.
        if let Some(stop) = walk.stopped.take() {
            end = offered
                .iter()
                .position(|c| c.epoch_number() == stop.epoch_number)
                .unwrap_or(0);
            stopped = Some(stop);
            continue;
        }
        match walk.adopted() {
            None => {
                return Ok(Walked {
                    adopted: None,
                    stopped,
                })
            }
            Some(adopted) => {
                let number = adopted.checkpoint.epoch_number();
                let unwitnessed =
                    matches!(adopted.adoption, Adoption::Adopted { unwitnessed: true });
                if number == offered[end - 1].epoch_number() {
                    let checkpoint = adopted.checkpoint.clone();
                    return Ok(Walked {
                        adopted: Some((restored, walk, checkpoint, unwitnessed)),
                        stopped,
                    });
                }
                end = offered
                    .iter()
                    .position(|c| c.epoch_number() == number)
                    .map(|index| index + 1)
                    .unwrap_or(0);
            }
        }
    }
    Ok(Walked {
        adopted: None,
        stopped,
    })
}

struct Held {
    keys: Registry,
    tree: Tree,
    head: Checkpoint,
}

fn run_incremental(context: &SyncContext, catch_up_epochs: u64) -> Result<SyncReport> {
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

    let keys = load_aggregator_keys(&conn, context.anchor, local.epoch_number)?;
    let offered = match offered_above(context, &conn, local.epoch_number, &keys) {
        Ok(offered) => offered,
        // WIST-3 §5: with no head served, staleness is judged on the verified head.
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
    let walk = Incremental {
        local: &local,
        head: &head,
        cadence,
    };
    let newest = offered
        .checkpoints
        .last()
        .map_or(local.epoch_number, Checkpoint::epoch_number);
    // WIST-3 §8 "Catch-up decision".
    let Some(floor) = local
        .epoch_number
        .checked_add(catch_up_epochs)
        .filter(|floor| newest >= *floor)
    else {
        return walk_incremental(context, &conn, &walk, offered, None);
    };
    let snapshot_epoch = match newest_snapshot_epoch(context.sources) {
        Ok(epoch_number) => epoch_number,
        Err(error) => {
            eprintln!(
                "log {}: {error}; no Snapshot index is readable, so the sync walks from the verified head",
                context.log_id
            );
            return walk_incremental(context, &conn, &walk, offered, None);
        }
    };
    if snapshot_epoch < floor {
        return walk_incremental(context, &conn, &walk, offered, None);
    }
    let held = Held {
        keys,
        tree: Tree::load(&conn)?,
        head: head.clone(),
    };
    drop(conn);
    let snapshot_rejected = match snapshot_sync(context, Some(&held)) {
        Ok(Installed::Done(report)) => return report,
        Ok(Installed::Behind(epoch_number)) => {
            eprintln!(
                "log {}: the newest Snapshot now stands at epoch {epoch_number}, below the verified head at epoch {}; walking instead",
                context.log_id, local.epoch_number
            );
            None
        }
        Err(error) if error.code().as_deref() == Some("WIST3-E02") => return Err(error),
        Err(error) => {
            eprintln!(
                "log {}: {error}; walking from the verified head instead of catching up through the Snapshot",
                context.log_id
            );
            Some(error.to_string())
        }
    };
    let conn = Connection::open(&index_sqlite_path)?;
    walk_incremental(context, &conn, &walk, offered, snapshot_rejected)
}

struct Incremental<'a> {
    local: &'a SyncState,
    head: &'a Checkpoint,
    cadence: i64,
}

fn walk_incremental(
    context: &SyncContext,
    conn: &Connection,
    walk_from: &Incremental,
    offered: Offered,
    snapshot_rejected: Option<String>,
) -> Result<SyncReport> {
    let Incremental {
        local,
        head,
        cadence,
    } = *walk_from;
    let unchanged = |stale: bool| SyncReport {
        log_id: context.log_id.to_string(),
        epoch_number_before: Some(local.epoch_number),
        head: local.epoch_number,
        tree_size: local.tree_size,
        root: local.root.clone(),
        unwitnessed: local.unwitnessed,
        stale,
        withdrawn: 0,
        rejected: Vec::new(),
        snapshot_rejected: snapshot_rejected.clone(),
    };
    if offered.checkpoints.is_empty() {
        let report = unchanged(checkpoints::warn_if_stale(context.log_id, head, cadence));
        return match offered.stopped {
            None => Ok(report),
            Some(stop) => Err(stopped_run(&report, stop)),
        };
    }

    let walked = walk_to_adoption(context, conn, local, head, &offered.checkpoints)?;
    let stopped = first_stop(offered.stopped, walked.stopped);
    let Some((restored, walk, adopted, unwitnessed)) = walked.adopted else {
        if stopped.is_none() {
            eprintln!(
                "log {}: no Checkpoint above epoch {} carries the Witness quorum in force; keeping the verified head",
                context.log_id, local.epoch_number
            );
        }
        let report = unchanged(checkpoints::warn_if_stale(context.log_id, head, cadence));
        return match stopped {
            None => Ok(report),
            Some(stop) => Err(stopped_run(&report, stop)),
        };
    };

    let Restored {
        keys,
        chain,
        replay,
        suffix_lists,
        tree,
    } = restored;
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
        &replay,
        &walk.events,
        &Materializer {
            sources: context.sources,
            chain: &chain,
            tier1: context.tier1,
            payload_fetches: context.payload_fetches,
        },
    )?;
    fetch_definitions(
        &tx,
        context.sources.client(),
        &KeyHistory::from_declarations(replay.declarations().clone()),
        context.subscriptions,
    )?;
    tx.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    if context.tier1 {
        tx.execute(
            "INSERT INTO extracts_fts(extracts_fts) VALUES('rebuild')",
            [],
        )?;
    }
    let rejected = rejected_in(&walk.events);
    let sync_state = SyncState {
        format: SYNC_STATE_FORMAT,
        tree_size: adopted.tree_size(),
        epoch_number: adopted.epoch_number(),
        root: adopted.root_token(),
        unwitnessed,
        content_digest: local.content_digest.clone(),
        snapshot_tree_size: local.snapshot_tree_size,
        schedule_first_s: chain.schedule_first_s(),
        prior_sealed_at_s: chain.prior_at(),
        largest_epoch_bytes: chain.largest(),
        walk_floor: local.walk_floor,
        rejected_epochs: [local.rejected_epochs.clone(), rejected.clone()].concat(),
    };
    save_sync_state(&tx, &sync_state)?;
    tx.commit()?;
    mirror_sync_state(context.sync_path, &sync_state);
    let stale = checkpoints::warn_if_stale(context.log_id, &adopted, chain.cadence());

    let report = SyncReport {
        log_id: context.log_id.to_string(),
        epoch_number_before: Some(local.epoch_number),
        head: sync_state.epoch_number,
        tree_size: sync_state.tree_size,
        root: sync_state.root.clone(),
        unwitnessed,
        stale,
        withdrawn: stats.withdrawn,
        rejected,
        snapshot_rejected,
    };
    match stopped {
        None => Ok(report),
        Some(stop) => Err(stopped_run(&report, stop)),
    }
}

/// WIST-3 §9 `WIST3-E04`: "reject the entire Snapshot and re-fetch, from another Mirror if needed".
enum ColdStart {
    Installed(Installed),
    Rejected { error: Error, next: usize },
}

enum Installed {
    Done(Result<SyncReport>),
    Behind(u64),
}

fn run_cold_start(context: &SyncContext) -> Result<SyncReport> {
    match snapshot_sync(context, None)? {
        Installed::Done(report) => report,
        Installed::Behind(epoch_number) => Err(Error::Verify(format!(
            "the Snapshot at epoch {epoch_number} stands below the verified head"
        ))),
    }
}

fn snapshot_sync(context: &SyncContext, held: Option<&Held>) -> Result<Installed> {
    let mut from = 0;
    loop {
        match cold_start_at(context, held, from)? {
            ColdStart::Installed(installed) => return Ok(installed),
            ColdStart::Rejected { error, next } => {
                if next >= context.sources.count() {
                    return Err(error);
                }
                eprintln!(
                    "log {}: {error}; re-fetching the Snapshot from another source",
                    context.log_id
                );
                from = next;
            }
        }
    }
}

/// WIST-3 §8 step 8: verified under the keys valid at the adopted Checkpoint's height.
fn verify_unsealed(
    installed: &install::Installation,
    keys: &Registry,
    adopted: &Checkpoint,
) -> Result<()> {
    for unsealed in &installed.unsealed {
        wist_core::unsealed::verify(
            unsealed.document,
            &unsealed.envelope,
            keys,
            adopted.epoch_number(),
        )
        .map_err(|error| Error::Verify(format!("{error}, served from {}", unsealed.url)))?;
    }
    Ok(())
}

// WIST-3 §8 step 5: a Snapshot's Checkpoint not extending the verified head is `WIST3-E02`.
fn extended_tree(context: &SyncContext, held: &Held, offered: &Checkpoint) -> Result<Tree> {
    let head = &held.head;
    let diverged = |detail: &str, tiles: Option<&Tree>| {
        checkpoints::divergence(
            context.log_dir,
            context.log_id,
            &held.keys,
            head.epoch_number(),
            Some(head),
            offered,
            tiles,
            detail,
        )
    };
    if offered.tree_size() < head.tree_size() {
        return Err(diverged(
            "the Snapshot's Checkpoint states a smaller tree than the verified head's",
            None,
        ));
    }
    let mut tree = held.tree.clone();
    match tree::extend(
        context.sources,
        &mut tree,
        head.tree_size(),
        offered.tree_size(),
        offered.root(),
    ) {
        Ok(()) => {
            if wist_core::tiles::check_tree(tree.reader(), head.tree_size(), head.root()).is_err() {
                return Err(diverged(
                    "the tree the Snapshot's Checkpoint states does not extend the verified head's",
                    Some(&tree),
                ));
            }
            Ok(tree)
        }
        Err(range_error) => {
            match tree::offered_tree(context.sources, offered.tree_size(), offered.root())? {
                Some(offered_tree) => {
                    let prefix =
                        wist_core::merkle::root_from(offered_tree.reader(), head.tree_size())?;
                    if prefix != *head.root() {
                        return Err(diverged(
                            "the tree the Snapshot's Checkpoint states does not extend the verified head's",
                            Some(&offered_tree),
                        ));
                    }
                    Ok(offered_tree)
                }
                None => Err(range_error),
            }
        }
    }
}

fn cold_start_at(context: &SyncContext, held: Option<&Held>, from: usize) -> Result<ColdStart> {
    let mut installed = install::snapshot(
        context.sources,
        context.anchor,
        context.log_dir,
        context.tier1,
        from,
    )?;
    let next_source = installed.source + 1;
    if let Some(held) = held {
        // WIST-3 §7: rejected as soon as the tuples are authenticated.
        if let Err(error) = wist_core::aggregator_keys::check_catch_up(
            &held.keys,
            held.head.epoch_number(),
            &installed.aggregator_keys,
        ) {
            return Ok(ColdStart::Rejected {
                error: error.into(),
                next: next_source,
            });
        }
        if installed.manifest.epoch_number < held.head.epoch_number() {
            return Ok(ColdStart::Installed(Installed::Behind(
                installed.manifest.epoch_number,
            )));
        }
    }
    // WIST-3 §8 steps 4–5.
    let (anchor, verification) = checkpoints::manifest_anchor(
        context.sources,
        &installed.manifest,
        installed.state_tree_size,
        context.log_id,
        &installed
            .aggregator_keys
            .valid_at(installed.manifest.epoch_number),
        context.witnesses,
    )?;
    if let Some(held) = held.filter(|held| held.head.epoch_number() == anchor.epoch_number()) {
        checkpoints::agrees_with_retained(
            context.log_dir,
            context.log_id,
            &held.keys,
            &held.head,
            &anchor,
        )?;
    }
    checkpoints::manifest_agrees(
        context.log_dir,
        &installed.manifest,
        &installed.manifest_bytes,
        &anchor,
    )?;
    let sealed_at_s = anchor.sealed_at_s()?;
    installed.chain.seed_prior(sealed_at_s);
    let anchor_adoption =
        wist_core::checkpoint::adoption(&verification, installed.chain.quorum_at(sealed_at_s));
    installed.history.seed_head(
        anchor.epoch_number(),
        &anchor.root_token(),
        Some(sealed_at_s),
    );
    save_history(&installed.conn, &installed.history)?;
    let tree = match held {
        Some(held) => extended_tree(context, held, &anchor)?,
        None => {
            let mut tree = Tree::new();
            tree::seed(
                context.sources,
                &mut tree,
                anchor.tree_size(),
                anchor.root(),
            )?;
            tree
        }
    };
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
        snapshot_tree_size: Some(anchor.tree_size()),
        schedule_first_s: installed.chain.schedule_first_s(),
        prior_sealed_at_s: installed.chain.prior_at(),
        largest_epoch_bytes: installed.chain.largest(),
        walk_floor: Some(anchor.epoch_number()),
        rejected_epochs: Vec::new(),
    };
    save_sync_state(&installed.conn, &anchor_state)?;
    let resumed = load_replay(&installed.conn, &anchor, anchor_state.walk_floor)?;
    install::materialize_tuples(&installed.conn, &resumed, anchor.epoch_number())?;
    let cadence = installed.chain.cadence();
    let offered = offered_above(
        context,
        &installed.conn,
        anchor.epoch_number(),
        &installed.aggregator_keys,
    )?;

    let walked = if offered.checkpoints.is_empty() {
        Walked {
            adopted: None,
            stopped: None,
        }
    } else {
        walk_to_adoption(
            context,
            &installed.conn,
            &anchor_state,
            &anchor,
            &offered.checkpoints,
        )?
    };
    let stopped = first_stop(offered.stopped, walked.stopped);

    let (adopted, unwitnessed, events, verified, state) = match walked.adopted {
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

    // WIST-3 §8 step 8: the signatures are judged at the adopted height before anything the
    // Snapshot carries is written.
    let walked_keys = match &state {
        Some(state) => &state.keys,
        None => &installed.aggregator_keys,
    };
    if let Err(error) = verify_unsealed(&installed, walked_keys, &adopted) {
        return Ok(ColdStart::Rejected {
            error,
            next: next_source,
        });
    }

    let replay = match state {
        Some(state) => {
            save_parameters(&installed.conn, &state.chain)?;
            state.suffix_lists.save(&installed.conn)?;
            save_aggregator_keys(&installed.conn, &state.keys)?;
            state.tree.save(&installed.conn)?;
            installed.chain = state.chain;
            state.replay
        }
        None => resumed,
    };
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
        &replay,
        &events,
        &Materializer {
            sources: context.sources,
            chain: &installed.chain,
            tier1: context.tier1,
            payload_fetches: context.payload_fetches,
        },
    )?;
    fetch_definitions(
        &installed.conn,
        context.sources.client(),
        &KeyHistory::from_declarations(replay.declarations().clone()),
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
    let rejected = rejected_in(&events);
    let sync_state = SyncState {
        format: SYNC_STATE_FORMAT,
        tree_size: adopted.tree_size(),
        epoch_number: adopted.epoch_number(),
        root: adopted.root_token(),
        unwitnessed,
        content_digest: Some(installed.content_digest.clone()),
        snapshot_tree_size: anchor_state.snapshot_tree_size,
        schedule_first_s: installed.chain.schedule_first_s(),
        prior_sealed_at_s: installed.chain.prior_at(),
        largest_epoch_bytes: installed.chain.largest(),
        walk_floor: anchor_state.walk_floor,
        rejected_epochs: rejected.clone(),
    };
    save_sync_state(&installed.conn, &sync_state)?;
    installed.commit(context.log_dir)?;
    mirror_sync_state(context.sync_path, &sync_state);
    let stale = checkpoints::warn_if_stale(context.log_id, &adopted, cadence);

    let report = SyncReport {
        log_id: context.log_id.to_string(),
        epoch_number_before: held.map(|held| held.head.epoch_number()),
        head: sync_state.epoch_number,
        tree_size: sync_state.tree_size,
        root: sync_state.root.clone(),
        unwitnessed,
        stale,
        withdrawn: stats.withdrawn,
        rejected,
        snapshot_rejected: None,
    };
    Ok(ColdStart::Installed(Installed::Done(match stopped {
        None => Ok(report),
        Some(stop) => Err(stopped_run(&report, stop)),
    })))
}

/// The index row is authoritative; this file is advisory.
fn mirror_sync_state(sync_path: &Path, state: &SyncState) {
    if let Ok(bytes) = serde_json::to_vec(state) {
        let _ = std::fs::write(sync_path, bytes);
    }
}
