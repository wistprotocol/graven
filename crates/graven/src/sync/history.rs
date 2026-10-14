use super::persist::{record_sealed, record_withdrawal, save_history, save_state_tuples};
use super::source::Sources;
use super::tree::Tree;
use super::SyncState;
use crate::error::{Error, Result};
use crate::keyset::KeyHistory;
use crate::store::{table_exists, CREATE_TIER1};
use rusqlite::Connection;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use wist_core::aggregator_keys::Registry;
use wist_core::checkpoint::{self, check_consistency, Adoption, Checkpoint, WitnessKey};
use wist_core::declaration::url_host;
use wist_core::item::{judge_payload_octets, Kind, SizeCaps};
use wist_core::label::{SealedDispute, SealedLabel};
use wist_core::merkle::consistency_proof_from;
use wist_core::objects::{PageItem, Payload, PublisherEnvelope};
use wist_core::parameters::{ActPosition, Amendment, Disposition as ScheduleDisposition, Schedule};
use wist_core::registry_updates::AcceptedUpdates;
use wist_core::sealing::{
    carried_label_ids, Epoch, Judgment, Outcome, Parameters, Removed, Replay,
};
use wist_core::timestamp::log_seconds;

/// WIST-4 §9 and ADR-0020.
pub struct ChainState {
    schedule: Option<Schedule>,
    adopted: Vec<Amendment>,
    largest: u64,
    prior_at: Option<i64>,
    updates: AcceptedUpdates,
}

impl ChainState {
    pub fn fresh() -> Self {
        Self {
            schedule: None,
            adopted: Vec::new(),
            largest: 0,
            prior_at: None,
            updates: AcceptedUpdates::new(),
        }
    }

    /// WIST-3 §7: accepted amendments these tuples restore are adopted before the first walked
    /// Epoch.
    pub fn from_tuples(tuples: &[(String, String, i64)]) -> Result<Self> {
        let adopted = tuples
            .iter()
            .enumerate()
            .map(|(index, (name, effective_at, value))| {
                let effective_at_s = log_seconds(effective_at)
                    .map_err(|e| Error::Verify(format!("parameter tuple {name}: {e}")))?;
                Ok(Amendment {
                    parameter: name.clone(),
                    value: *value,
                    epoch_number: 0,
                    entry_index: index as u64,
                    sealed_at_s: effective_at_s,
                    effective_at_s,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            schedule: None,
            adopted,
            largest: 0,
            prior_at: None,
            updates: AcceptedUpdates::new(),
        })
    }

    pub fn restore(state: &SyncState, accepted: Vec<Amendment>) -> Self {
        let schedule = state.schedule_first_s.map(|first| {
            let mut schedule = Schedule::new(first);
            for amendment in accepted {
                schedule.adopt(amendment);
            }
            schedule
        });
        Self {
            schedule,
            adopted: Vec::new(),
            largest: state.largest_epoch_bytes,
            prior_at: state.prior_sealed_at_s,
            updates: AcceptedUpdates::new(),
        }
    }

    /// WIST-4 §5.1: the Registry Update IDs accepted below the first Epoch this state walks.
    pub fn hold_accepted_updates(&mut self, updates: AcceptedUpdates) {
        if let Some(schedule) = &mut self.schedule {
            schedule.hold_accepted_updates(updates.clone());
        }
        self.updates = updates;
    }

    fn schedule_at(&mut self, at: i64) -> &mut Schedule {
        if self.schedule.is_none() {
            let mut schedule = Schedule::new(at);
            for amendment in self.adopted.drain(..) {
                schedule.adopt(amendment);
            }
            schedule.hold_accepted_updates(self.updates.clone());
            self.schedule = Some(schedule);
        }
        self.schedule.as_mut().unwrap()
    }

    /// WIST-3 §6: the greatest `epoch_cap_bytes` at the last verified `sealed_at` and at every
    /// accepted future effective instant.
    pub fn transport_bound(&self) -> u64 {
        match (&self.schedule, self.prior_at) {
            (Some(schedule), Some(at)) => schedule.epoch_size_bounds(at).1,
            _ => default_of("epoch_cap_bytes"),
        }
    }

    /// WIST-3 §3.1: the cadence in force at the previous Epoch's `sealed_at`.
    pub fn cadence(&self) -> i64 {
        match (&self.schedule, self.prior_at) {
            (Some(schedule), Some(at)) => schedule.value_at("epoch_cadence_seconds", at),
            _ => None,
        }
        .unwrap_or_else(|| default_of("epoch_cadence_seconds") as i64)
    }

    /// WIST-3 §5 and WIST-4 §5.
    pub fn quorum_at(&self, at: i64) -> u64 {
        self.schedule
            .as_ref()
            .and_then(|schedule| schedule.value_at("checkpoint_witness_quorum", at))
            .unwrap_or_else(|| default_of("checkpoint_witness_quorum") as i64)
            .max(0) as u64
    }

    pub fn accepted(&self) -> Vec<Amendment> {
        self.schedule
            .as_ref()
            .map(|s| s.accepted().to_vec())
            .unwrap_or_default()
    }

    pub fn schedule_first_s(&self) -> Option<i64> {
        self.schedule.as_ref().map(|s| s.first_epoch_s())
    }

    pub fn prior_at(&self) -> Option<i64> {
        self.prior_at
    }

    /// WIST-3 §§5, 6: the cadence grid, transport bound and Witness quorum are read from the prefix
    /// a Snapshot resumes at.
    pub fn seed_prior(&mut self, at: i64) {
        self.prior_at = Some(at);
        self.schedule_at(at);
    }

    pub fn largest(&self) -> u64 {
        self.largest
    }

    pub fn size_caps_at(&self, at: i64) -> Option<SizeCaps> {
        let parameters = Parameters::from_schedule(self.schedule.as_ref()?, at).ok()?;
        SizeCaps::new(
            parameters.get("url_cap_bytes"),
            parameters.get("extract_cap_bytes"),
            parameters.get("links_cap_bytes"),
            parameters.get("link_url_cap_bytes"),
            parameters.get("summary_cap_bytes"),
        )
        .ok()
    }
}

fn default_of(parameter: &str) -> u64 {
    wist_core::parameters::spec(parameter)
        .and_then(|p| p.default)
        .unwrap_or(0)
        .max(0) as u64
}

pub struct EpochEvent {
    pub height: u64,
    pub sealed_at: String,
    /// WIST-1 §5.2: in force at `sealed_at`; freezes the end of a recovery window opened in this
    /// Epoch.
    pub recovery_window_days: i64,
    /// In canonical Epoch order.
    pub declarations: Vec<Value>,
    /// WIST-3 §6.2: (withdrawn Item ID, Publisher, earliest withdrawing Epoch).
    pub withdrawals: Vec<(String, String, u64)>,
    pub publishers: Vec<String>,
    pub labels: Vec<SealedLabel>,
    pub disputes: Vec<SealedDispute>,
    /// WIST-3 §3.2: valid or ignored.
    pub label_ids: Vec<String>,
    /// WIST-3 §7.
    pub materialized: Vec<(String, Option<MaterializedRow>)>,
    /// WIST-4 §5.1: (Item ID, Publisher of its named Catalog, kind) of each valid `publisher_item`
    /// Entry.
    pub sightings: Vec<(String, String, Kind)>,
    pub rejected: Option<Vec<String>>,
}

impl EpochEvent {
    fn rejected(height: u64, sealed_at: String, codes: Vec<String>) -> Self {
        EpochEvent {
            height,
            sealed_at,
            recovery_window_days: default_recovery_window_days(),
            declarations: Vec::new(),
            withdrawals: Vec::new(),
            publishers: Vec::new(),
            labels: Vec::new(),
            disputes: Vec::new(),
            label_ids: Vec::new(),
            materialized: Vec::new(),
            sightings: Vec::new(),
            rejected: Some(codes),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaterializedRow {
    pub publisher: String,
    pub item_id: String,
    pub item: Value,
    pub collection: String,
    pub generated_at: String,
}

impl MaterializedRow {
    fn key(&self) -> RowKey {
        RowKey {
            publisher: self.publisher.clone(),
            item_id: self.item_id.clone(),
            collection: Some(self.collection.clone()),
            generated_at: Some(self.generated_at.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RowKey {
    publisher: String,
    item_id: String,
    collection: Option<String>,
    generated_at: Option<String>,
}

/// WIST-3 §7, One URL, one Publisher.
fn affected_urls(
    replay: &Replay,
    entries: &[Value],
    judged: &[Option<Judgment>],
    removed: &[Removed],
    withdrawn: &[(String, String, u64)],
) -> BTreeSet<String> {
    let mut urls: BTreeSet<String> = removed.iter().map(|r| r.url.clone()).collect();
    let mut hosts: BTreeSet<&str> = BTreeSet::new();
    for (entry, judgment) in entries.iter().zip(judged) {
        match entry["type"].as_str() {
            Some("publisher_item") if matches!(judgment, Some(Judgment::Valid)) => {
                if let Some(url) = entry["body"]["item"]["url"].as_str() {
                    urls.insert(url.to_owned());
                }
            }
            Some("publisher_declaration") => {
                if let Some(domain) = entry["body"]["publisher"]["domain"].as_str() {
                    hosts.insert(domain);
                }
            }
            _ => {}
        }
    }
    for (_, url, record) in replay.records().records() {
        if hosts.contains(url_host(url))
            || withdrawn
                .iter()
                .any(|(item_id, _, _)| *item_id == record.item_id)
        {
            urls.insert(url.to_owned());
        }
    }
    urls
}

fn materialized_row(replay: &Replay, url: &str) -> Option<MaterializedRow> {
    replay
        .materialized_record(url)
        .map(|(publisher, record)| MaterializedRow {
            publisher: publisher.to_owned(),
            item_id: record.item_id.clone(),
            item: record.item.clone(),
            collection: record.collection.clone(),
            generated_at: record.generated_at.clone(),
        })
}

pub struct ApplyStats {
    pub withdrawn: u64,
    pub labels: u64,
}

pub struct Verified {
    pub checkpoint: Checkpoint,
    pub adoption: Adoption,
}

/// WIST-3 §8 step 8: a failing Checkpoint ends the walk; the Epochs verified below it are still
/// adopted.
pub struct Stop {
    pub epoch_number: u64,
    pub error: Error,
}

pub struct Walk {
    pub events: Vec<EpochEvent>,
    pub verified: Vec<Verified>,
    pub stopped: Option<Stop>,
}

impl Walk {
    /// WIST-3 §8 step 8: quorum as in force at the Checkpoint's own `sealed_at`.
    pub fn adopted(&self) -> Option<&Verified> {
        self.verified
            .iter()
            .rev()
            .find(|v| matches!(v.adoption, Adoption::Adopted { .. }))
    }
}

pub struct WalkInputs<'a> {
    pub sources: &'a Sources<'a>,
    pub log_id: &'a str,
    pub witnesses: &'a [WitnessKey],
    pub log_dir: &'a std::path::Path,
}

pub struct WalkState<'a> {
    pub keys: &'a mut Registry,
    pub chain: &'a mut ChainState,
    pub replay: &'a mut Replay,
    pub suffix_lists: &'a mut super::suffix::SuffixLists,
    pub tree: &'a mut Tree,
}

/// WIST-3 §5 and §8 steps 6–8.
pub fn walk_checkpoints(
    inputs: &WalkInputs,
    state: &mut WalkState,
    head: &Checkpoint,
    offered: &[Checkpoint],
) -> Result<Walk> {
    let mut events: Vec<EpochEvent> = Vec::new();
    let mut verified: Vec<Verified> = Vec::new();
    let mut previous = head.clone();
    let reached = head.epoch_number();
    let mut stopped: Option<Stop> = None;
    for checkpoint in offered {
        match verify_checkpoint(inputs, state, reached, &previous, checkpoint) {
            Ok((event, adoption)) => {
                verified.push(Verified {
                    checkpoint: checkpoint.clone(),
                    adoption,
                });
                events.push(event);
                previous = checkpoint.clone();
            }
            // WIST-3 §5 and §9: chain divergence applies nothing; any other failure keeps the
            // Epochs verified below it (§8 step 8).
            Err(error) => {
                if error.code().as_deref() == Some("WIST3-E02") {
                    return Err(error);
                }
                stopped = Some(Stop {
                    epoch_number: checkpoint.epoch_number(),
                    error,
                });
                break;
            }
        }
    }
    Ok(Walk {
        events,
        verified,
        stopped,
    })
}

fn registry_update_id(body: &Value) -> Option<String> {
    wist_core::registry_updates::update_id(body).ok()
}

fn act_of<'v>(entry: &'v Value, eligible: bool, actions: &[&str]) -> Option<&'v Value> {
    let body = &entry["body"];
    (eligible
        && entry["type"] == "registry_update"
        && body["update"]["action"]
            .as_str()
            .is_some_and(|action| actions.contains(&action)))
    .then_some(body)
}

/// WIST-3 §5 order: sequence rules, Entries, Consistency Proof, Registry Updates, then the
/// signature.
fn verify_checkpoint(
    inputs: &WalkInputs,
    state: &mut WalkState,
    reached: u64,
    previous: &Checkpoint,
    checkpoint: &Checkpoint,
) -> Result<(EpochEvent, Adoption)> {
    let WalkState {
        keys,
        chain,
        replay,
        suffix_lists,
        tree,
    } = state;
    let n = checkpoint.epoch_number();
    let diverged = |detail: &str, tiles: Option<&Tree>| {
        super::checkpoints::divergence(
            inputs.log_dir,
            inputs.log_id,
            keys,
            reached,
            Some(previous),
            checkpoint,
            tiles,
            detail,
        )
    };
    // WIST-3 §5, the first Equivocation form: the two notes are the whole evidence.
    if matches!(
        checkpoint::equivocation(previous, checkpoint),
        Some(checkpoint::Equivocation::SameSizeDifferentRoot)
    ) {
        return Err(diverged(
            "two Checkpoints of one Log state one tree size and different root hashes",
            None,
        ));
    }
    // WIST-3 §3.1: judged under the key set valid at the previous height.
    if let Err(error) = super::checkpoints::sequence_at_head(
        inputs.log_dir,
        inputs.log_id,
        keys,
        reached,
        previous,
        checkpoint,
        chain.cadence(),
        Some(tree),
    ) {
        if error.code().as_deref() == Some("WIST3-E02") {
            return Err(error);
        }
        return Err(Error::Verify(format!("epoch {n}: {error}")));
    }
    let previous_size = previous.tree_size();
    let tree_size = checkpoint.tree_size();
    // WIST-3 §4: an empty Consistency Proof exempts no root from comparison.
    if tree_size == 0 && *checkpoint.root() != wist_core::merkle::EMPTY_ROOT {
        return Err(super::checkpoints::divergence(
            inputs.log_dir,
            inputs.log_id,
            keys,
            reached,
            None,
            checkpoint,
            None,
            "a Checkpoint states tree size 0 with another root than the empty tree's",
        ));
    }
    if let Err(range_error) = super::tree::extend(
        inputs.sources,
        tree,
        previous_size,
        tree_size,
        checkpoint.root(),
    ) {
        // Fetched into a scratch tree, never over the tiles the Consumer has verified.
        match super::tree::offered_tree(inputs.sources, tree_size, checkpoint.root())? {
            Some(offered_tree) => {
                let prefix = wist_core::merkle::root_from(offered_tree.reader(), previous_size)?;
                if prefix != *previous.root() {
                    return Err(diverged(
                        "the tree a Checkpoint states does not extend the verified head's",
                        Some(&offered_tree),
                    ));
                }
                **tree = offered_tree;
            }
            None => return Err(Error::Verify(format!("epoch {n}: {range_error}"))),
        }
    }
    let proof = consistency_proof_from(tree.reader(), previous_size, tree_size)?;
    if let Err(error) = check_consistency(previous, checkpoint, &proof) {
        return Err(diverged(&error.to_string(), Some(tree)));
    }
    let leaves = super::tree::epoch_leaves(
        inputs.sources,
        tree,
        previous_size,
        tree_size,
        chain.transport_bound(),
    )
    .map_err(|e| Error::Verify(format!("epoch {n}: {e}")))?;
    let entries = &leaves.entries;
    // WIST-3 §3.3: every leaf is authenticated by its entry bundle against the verified tiles, so
    // the Entry form, canonical order and the 65 535-octet bound are left to the Replay, which
    // rejects the Epoch for them.
    let octets = leaves.octets;

    // WIST-3 §§3.3, 3.4: key acts apply first, in ascending leaf index, under the keys valid at
    // N−1, in every Epoch a rejected one included; a failing key act is ignored.
    let mut key_acts: Vec<String> = Vec::new();
    for (entry, eligible) in entries.iter().zip(&leaves.body_eligible) {
        let Some(body) = act_of(
            entry,
            *eligible,
            &["aggregator_key_add", "aggregator_key_remove"],
        ) else {
            continue;
        };
        for outcome in keys.apply_epoch(n, [body]) {
            if let Some(code) = outcome.code() {
                eprintln!("ignoring an Aggregator key act at height {n}: {code}");
            }
            if outcome.is_accepted() {
                key_acts.extend(registry_update_id(body));
            }
        }
    }
    // Authenticated under the keys valid at N, after this Epoch's key acts.
    let authenticators = keys.valid_at(n);
    let log_key = |key_id: &str| {
        authenticators
            .iter()
            .find(|key| key.key_id == key_id)
            .map(|key| key.public_key.clone())
    };

    let sealed_at = checkpoint.sealed_at().to_string();
    let at = checkpoint
        .sealed_at_s()
        .map_err(|e| Error::Verify(format!("epoch {n}: WIST3-E03 {e}")))?;
    // WIST-4 §5: an Epoch's size enters M unless the Epoch is rejected for its size.
    let largest = chain.largest.max(octets);
    let mut candidate = chain.schedule_at(at).clone();
    let mut parameter_acts: Vec<String> = Vec::new();
    for (index, (entry, eligible)) in entries.iter().zip(&leaves.body_eligible).enumerate() {
        let Some(body) = act_of(entry, *eligible, &["parameter_change"]) else {
            continue;
        };
        let position = ActPosition {
            epoch_number: n,
            entry_index: index as u64,
            sealed_at_s: at,
        };
        match candidate.apply_act(body, position, largest, log_key) {
            ScheduleDisposition::Accepted(_) => parameter_acts.extend(registry_update_id(body)),
            ScheduleDisposition::Rejected { code, .. } => {
                eprintln!("ignoring a parameter_change at height {n}: {code}");
            }
            ScheduleDisposition::Repeated { .. } | ScheduleDisposition::NotParameterChange => {}
        }
    }
    let parameters = Parameters::from_schedule(chain.schedule_at(at), at)
        .map_err(|e| Error::Verify(format!("epoch {n}: {e}")))?;
    let recovery_window_days = parameters.get("recovery_window_days");
    let suffix_list = suffix_lists.in_force_at_epoch(n)?;
    let size_rejected = octets > candidate.epoch_size_bounds(at).0;
    if !size_rejected {
        chain.largest = largest;
    }
    chain.prior_at = Some(at);

    let root = checkpoint.root_token();
    let stored: Vec<(usize, &[u8])> = leaves
        .stored
        .iter()
        .map(|(index, octets)| (*index, octets.as_slice()))
        .collect();
    let epoch = Epoch {
        height: n,
        root: &root,
        sealed_at: &sealed_at,
        parameters: &parameters,
        suffix_list: suffix_list.as_deref(),
        log_key: &log_key,
        entries,
    };
    // WIST-4 §5 and WIST-3 §6: an Epoch over the smallest cap at its `sealed_at` and at every
    // accepted later `effective_at` is rejected whole.
    let outcome = if size_rejected {
        replay.reject_epoch(&epoch, vec!["WIST3-E03".to_owned()])
    } else {
        replay.epoch_stored(&epoch, &stored)
    }
    .map_err(|e| Error::Verify(format!("epoch {n}: {e}")))?;
    let (judged, records_removed) = match outcome {
        // WIST-3 §3.3, Rejected Epochs: of a rejected Epoch only the key acts apply, and their IDs
        // alone are accepted; its Checkpoint is judged under the keys they leave valid.
        Outcome::Rejected { codes } => {
            eprintln!(
                "rejecting the Epoch at height {n}, which applies its key acts alone: {}",
                codes.join(", ")
            );
            for id in &key_acts {
                replay.accept_registry_update(id, n);
            }
            let adoption = super::checkpoints::decide(
                checkpoint,
                inputs.log_id,
                &authenticators,
                inputs.witnesses,
                chain.quorum_at(at),
            )
            .map_err(|e| Error::Verify(format!("epoch {n}: {e}")))?;
            return Ok((EpochEvent::rejected(n, sealed_at, codes), adoption));
        }
        Outcome::Accepted {
            entries,
            records_removed,
        } => (entries, records_removed),
    };
    *chain.schedule_at(at) = candidate;
    let mut accepted_here = key_acts;
    accepted_here.extend(parameter_acts);
    for (entry, eligible) in entries.iter().zip(&leaves.body_eligible) {
        let Some(body) = act_of(entry, *eligible, &["suffix_list_update"]) else {
            continue;
        };
        if suffix_lists.apply_act(inputs.sources, n, body, log_key)? {
            accepted_here.extend(registry_update_id(body));
        }
    }
    for id in &accepted_here {
        replay.accept_registry_update(id, n);
    }
    let label_ids = carried_label_ids(entries, &stored)
        .map_err(|e| Error::Verify(format!("epoch {n}: {e}")))?;
    for (entry, judgment) in entries.iter().zip(&judged) {
        if let Some(Judgment::Ignored(failures)) = judgment {
            let codes: Vec<&str> = failures.iter().map(|failure| failure.code).collect();
            eprintln!(
                "ignoring a {} Entry at height {n}: {}",
                entry["type"].as_str().unwrap_or("malformed"),
                codes.join(", ")
            );
        }
    }

    // WIST-3 §5: the signature is checked only after this Epoch's Registry Updates apply.
    let adoption = super::checkpoints::decide(
        checkpoint,
        inputs.log_id,
        &authenticators,
        inputs.witnesses,
        chain.quorum_at(at),
    )
    .map_err(|e| Error::Verify(format!("epoch {n}: {e}")))?;

    let withdrawals: Vec<(String, String, u64)> = replay
        .withdrawals()
        .entries()
        .into_iter()
        .filter(|withdrawal| withdrawal.sealing_height == n)
        .map(|withdrawal| (withdrawal.item_id, withdrawal.publisher, n))
        .collect();
    let materialized = affected_urls(replay, entries, &judged, &records_removed, &withdrawals)
        .into_iter()
        .map(|url| {
            let row = materialized_row(replay, &url);
            (url, row)
        })
        .collect();
    let event = EpochEvent {
        height: n,
        sealed_at,
        recovery_window_days,
        declarations: entries
            .iter()
            .filter(|entry| entry["type"] == "publisher_declaration")
            .cloned()
            .collect(),
        withdrawals,
        publishers: entries
            .iter()
            .filter_map(|entry| match entry["type"].as_str() {
                Some("publisher_catalog") => entry["body"]["catalog"]["publisher"].as_str(),
                Some("publisher_item") => entry["body"]["item"]["publisher"].as_str(),
                _ => None,
            })
            .map(str::to_owned)
            .collect(),
        labels: replay
            .labels()
            .filter(|label| label.height == n)
            .cloned()
            .collect(),
        disputes: replay
            .disputes()
            .filter(|dispute| dispute.height == n)
            .cloned()
            .collect(),
        label_ids,
        materialized,
        sightings: sightings(replay, entries, &judged)?,
        rejected: None,
    };
    Ok((event, adoption))
}

fn sightings(
    replay: &Replay,
    entries: &[Value],
    judged: &[Option<Judgment>],
) -> Result<Vec<(String, String, Kind)>> {
    let mut sightings = Vec::new();
    for (entry, judgment) in entries.iter().zip(judged) {
        if entry["type"] != "publisher_item" || !matches!(judgment, Some(Judgment::Valid)) {
            continue;
        }
        let item = &entry["body"]["item"];
        let named = entry["body"]["catalog"].as_str();
        let Some((publisher, _, _)) = replay
            .latest_catalogs()
            .find(|(_, _, latest)| Some(latest.catalog_id.as_str()) == named)
        else {
            continue;
        };
        sightings.push((
            wist_core::item::item_id(item)?,
            publisher.to_owned(),
            wist_core::item::kind(item),
        ));
    }
    Ok(sightings)
}

pub(super) fn default_recovery_window_days() -> i64 {
    wist_core::parameters::spec("recovery_window_days")
        .and_then(|p| p.default)
        .unwrap_or(7)
}

pub(super) fn persist_declaration(
    conn: &Connection,
    height: u64,
    sealed_at: &str,
    baseline: bool,
    recovery_window_days: i64,
    envelope: &Value,
) -> Result<()> {
    let env: PublisherEnvelope = serde_json::from_value(envelope.clone())?;
    // WIST-3 §7: several tuples of one Snapshot can name one Declaration.
    conn.execute(
        "INSERT OR IGNORE INTO declarations(domain, seq, height, sealed_at, baseline, envelope, recovery_window_days) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        (
            env.publisher.domain,
            env.publisher.seq as i64,
            height as i64,
            sealed_at,
            baseline as i64,
            serde_json::to_string(envelope)?,
            recovery_window_days,
        ),
    )?;
    Ok(())
}

pub(super) fn remove_derived(conn: &Connection, item_id: &str, url: &str) -> Result<()> {
    if table_exists(conn, "extracts")? {
        conn.execute("DELETE FROM extracts WHERE item_id = ?1", [item_id])?;
    }
    if table_exists(conn, "links")? {
        conn.execute("DELETE FROM links WHERE source_url = ?1", [url])?;
    }
    if table_exists(conn, "embeddings")? {
        conn.execute("DELETE FROM embeddings WHERE item_id = ?1", [item_id])?;
    }
    Ok(())
}

/// WIST-3 §7: the links a removed record withdraws count as in-link deaths at the removing height.
fn remove_ranking_bookkeeping(
    conn: &Connection,
    url: &str,
    publisher: &str,
    height: u64,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_RANKING)?;
    conn.execute(
        "DELETE FROM record_heights WHERE url = ?1 AND publisher = ?2",
        (url, publisher),
    )?;
    super::persist::replace_inlinks(conn, url, publisher, None, &[], height)
}

struct StoredRow {
    key: RowKey,
    content: bool,
}

fn stored_rows(conn: &Connection, url: &str) -> Result<Vec<StoredRow>> {
    let mut stmt = conn.prepare(
        "SELECT publisher, item_id, collection, generated_at, title IS NOT NULL FROM records WHERE url = ?1",
    )?;
    let rows = stmt
        .query_map([url], |row| {
            Ok(StoredRow {
                key: RowKey {
                    publisher: row.get(0)?,
                    item_id: row.get(1)?,
                    collection: row.get(2)?,
                    generated_at: row.get(3)?,
                },
                content: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn single_key(rows: &[StoredRow]) -> Option<Option<RowKey>> {
    match rows {
        [] => Some(None),
        [row] => Some(Some(row.key.clone())),
        _ => None,
    }
}

struct Content {
    title: String,
    r#abstract: Option<String>,
    extract: String,
    links: Vec<String>,
}

pub struct Materializer<'a> {
    pub sources: &'a Sources<'a>,
    pub chain: &'a ChainState,
    pub tier1: bool,
}

impl Materializer<'_> {
    /// WIST-1 §3.6: a Payload read for a sealed Item keeps the parameter profile of the Epoch
    /// that first sealed the Item, dated by the earliest sighting the store holds.
    fn caps(&self, conn: &Connection, row: &MaterializedRow) -> SizeCaps {
        let height = super::persist::earliest_sighting(conn, &row.item_id, &row.publisher)
            .ok()
            .flatten();
        let sealed_at = height
            .and_then(|height| super::checkpoints::retained(conn, height).ok().flatten())
            .and_then(|checkpoint| checkpoint.sealed_at_s().ok())
            .or(self.chain.prior_at());
        sealed_at
            .and_then(|at| self.chain.size_caps_at(at))
            .unwrap_or_else(SizeCaps::suite)
    }

    /// WIST-3 §6.1 and §8.
    fn content(&self, conn: &Connection, url: &str, row: &MaterializedRow) -> Option<Content> {
        let caps = self.caps(conn, row);
        let page: PageItem = serde_json::from_value(row.item.clone()).ok()?;
        let hex = row.item_id.strip_prefix("sha256:")?;
        let bound = caps.extract_cap_bytes()
            + caps.links_cap_bytes()
            + caps.summary_cap_bytes()
            + PAYLOAD_FRAMING_BYTES;
        let fetched = self
            .sources
            .verified(&format!("/payloads/{hex}.json"), bound, |octets| {
                judge_payload_octets(&page, octets, &caps)
                    .map_err(|code| Error::Verify(format!("{code} the Payload of {url}")))
            });
        let octets = match fetched {
            Ok(octets) => octets,
            Err(error) => {
                eprintln!("materializing {url} without content: {error}");
                return None;
            }
        };
        let payload: Payload =
            serde_json::from_value(wist_core::json::parse(&octets).ok()?).ok()?;
        Some(Content {
            title: payload.content.summary.title,
            r#abstract: payload.content.summary.r#abstract,
            extract: payload.content.extract,
            links: payload.content.links.urls,
        })
    }

    fn write_content(
        &self,
        conn: &Connection,
        url: &str,
        row: &MaterializedRow,
        content: Option<&Content>,
        height: u64,
    ) -> Result<()> {
        if let Some(content) = content {
            conn.execute(
                "UPDATE records SET title = ?3, abstract = ?4 WHERE url = ?1 AND publisher = ?2",
                (url, &row.publisher, &content.title, &content.r#abstract),
            )?;
        }
        if !self.tier1 {
            return Ok(());
        }
        let links = content.map_or(&[][..], |content| &content.links[..]);
        if let Some(content) = content {
            conn.execute(
                "INSERT INTO extracts(url, publisher, item_id, extract, collection) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(url, publisher) DO UPDATE SET item_id = excluded.item_id, extract = excluded.extract, collection = excluded.collection",
                (url, &row.publisher, &row.item_id, &content.extract, &row.collection),
            )?;
            conn.execute("DELETE FROM links WHERE source_url = ?1", [url])?;
            for (position, target_url) in links.iter().enumerate() {
                conn.execute(
                    "INSERT INTO links(source_url, target_url, position) VALUES (?1, ?2, ?3)",
                    (url, target_url, position as i64),
                )?;
            }
        }
        super::persist::replace_inlinks(
            conn,
            url,
            &row.publisher,
            Some(&row.item_id),
            links,
            height,
        )
    }

    fn remove(
        &self,
        conn: &Connection,
        replay: &Replay,
        url: &str,
        stored: &StoredRow,
        replaced_by: Option<&MaterializedRow>,
        height: u64,
    ) -> Result<()> {
        conn.execute(
            "DELETE FROM records WHERE url = ?1 AND publisher = ?2",
            (url, &stored.key.publisher),
        )?;
        remove_derived(conn, &stored.key.item_id, url)?;
        if replay.withdrawals().is_withdrawn(&stored.key.item_id) {
            conn.execute_batch(crate::store::CREATE_RANKING)?;
            conn.execute(
                "DELETE FROM record_heights WHERE url = ?1 AND publisher = ?2",
                (url, &stored.key.publisher),
            )?;
            return super::persist::retract_links(conn, &stored.key.item_id);
        }
        if replaced_by.is_none_or(|row| row.publisher != stored.key.publisher) {
            remove_ranking_bookkeeping(conn, url, &stored.key.publisher, height)?;
        }
        Ok(())
    }

    fn insert(
        &self,
        conn: &Connection,
        url: &str,
        row: &MaterializedRow,
        height: u64,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO records(url, publisher, item_id, observed_at, attested_at, title, abstract, lang, collection, generated_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7, ?8)",
            (
                url,
                &row.publisher,
                &row.item_id,
                row.item["observed_at"].as_str(),
                &row.generated_at,
                row.item["meta"]["lang"].as_str(),
                &row.collection,
                &row.generated_at,
            ),
        )?;
        record_height(conn, url, &row.publisher, height)?;
        let content = self.content(conn, url, row);
        self.write_content(conn, url, row, content.as_ref(), height)
    }

    /// WIST-3 §7.
    fn reattest(
        &self,
        conn: &Connection,
        url: &str,
        row: &MaterializedRow,
        height: u64,
    ) -> Result<()> {
        conn.execute(
            "UPDATE records SET attested_at = ?3, collection = ?4, generated_at = ?3 WHERE url = ?1 AND publisher = ?2",
            (url, &row.publisher, &row.generated_at, &row.collection),
        )?;
        if table_exists(conn, "extracts")? {
            conn.execute(
                "UPDATE extracts SET collection = ?3 WHERE url = ?1 AND publisher = ?2",
                (url, &row.publisher, &row.collection),
            )?;
        }
        record_height(conn, url, &row.publisher, height)
    }

    /// WIST-3 §7.
    fn apply(
        &self,
        conn: &Connection,
        replay: &Replay,
        events: &[EpochEvent],
        stats: &mut ApplyStats,
    ) -> Result<BTreeSet<String>> {
        let mut decided: BTreeMap<String, (Option<MaterializedRow>, u64)> = BTreeMap::new();
        for event in events {
            for (url, row) in &event.materialized {
                let previous = match decided.get(url.as_str()) {
                    Some((held, _)) => Some(held.as_ref().map(MaterializedRow::key)),
                    None => single_key(&stored_rows(conn, url)?),
                };
                if previous != Some(row.as_ref().map(MaterializedRow::key)) {
                    decided.insert(url.clone(), (row.clone(), event.height));
                }
            }
        }
        let mut written = BTreeSet::new();
        for (url, (row, height)) in &decided {
            let (url, row, height) = (url.as_str(), row.as_ref(), *height);
            let stored = stored_rows(conn, url)?;
            let wanted = row.map(MaterializedRow::key);
            if single_key(&stored) == Some(wanted.clone()) {
                continue;
            }
            written.insert(url.to_owned());
            let same_item = |held: &StoredRow| {
                row.is_some_and(|row| {
                    held.key.publisher == row.publisher && held.key.item_id == row.item_id
                })
            };
            for held in &stored {
                if !(same_item(held) && stored.len() == 1) {
                    self.remove(conn, replay, url, held, row, height)?;
                    if replay.withdrawals().is_withdrawn(&held.key.item_id) {
                        stats.withdrawn += 1;
                    }
                }
            }
            let Some(row) = row else {
                continue;
            };
            match stored.as_slice() {
                [held] if same_item(held) => {
                    self.reattest(conn, url, row, height)?;
                    if !held.content {
                        written.remove(url);
                    }
                }
                _ => self.insert(conn, url, row, height)?,
            }
        }
        Ok(written)
    }

    /// WIST-3 §8 cold start step 9.
    fn retry(&self, conn: &Connection, replay: &Replay, written: &BTreeSet<String>) -> Result<()> {
        let mut stmt = conn.prepare(
            "SELECT r.url, r.publisher, r.item_id, h.height FROM records r
             LEFT JOIN record_heights h ON h.url = r.url AND h.publisher = r.publisher
             WHERE r.title IS NULL",
        )?;
        let missing = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (url, publisher, item_id, height) in missing {
            if written.contains(&url) {
                continue;
            }
            let Some(row) = materialized_row(replay, &url)
                .filter(|row| row.publisher == publisher && row.item_id == item_id)
            else {
                continue;
            };
            if let Some(content) = self.content(conn, &url, &row) {
                let height = height.map_or(0, |height| height.max(0) as u64);
                self.write_content(conn, &url, &row, Some(&content), height)?;
            }
        }
        Ok(())
    }
}

const PAYLOAD_FRAMING_BYTES: u64 = 4096;

fn record_height(conn: &Connection, url: &str, publisher: &str, height: u64) -> Result<()> {
    conn.execute(
        "INSERT INTO record_heights(url, publisher, height) VALUES (?1, ?2, ?3)
         ON CONFLICT(url, publisher) DO UPDATE SET height = excluded.height",
        (url, publisher, height as i64),
    )?;
    Ok(())
}

pub fn apply_events(
    conn: &Connection,
    replay: &Replay,
    events: &[EpochEvent],
    materializer: &Materializer,
) -> Result<ApplyStats> {
    let mut stats = ApplyStats {
        withdrawn: 0,
        labels: 0,
    };
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    conn.execute_batch(crate::store::CREATE_RANKING)?;
    crate::store::add_record_columns(conn)?;
    if materializer.tier1 {
        conn.execute_batch(CREATE_TIER1)?;
    }
    let items: Vec<(String, String, Kind, u64)> = events
        .iter()
        .flat_map(|event| {
            event.sightings.iter().map(|(item_id, publisher, kind)| {
                (item_id.clone(), publisher.clone(), *kind, event.height)
            })
        })
        .collect();
    record_sealed(conn, &[], &items)?;
    for event in events {
        if event.rejected.is_some() {
            continue;
        }
        for entry in &event.declarations {
            // WIST-4 §6: a Declaration counts as a Labeler's sealed Entry.
            if let Some(domain) = entry["body"]["publisher"]["domain"].as_str() {
                super::persist::touch_labeler(conn, domain, event.height)?;
            }
            persist_declaration(
                conn,
                event.height,
                &event.sealed_at,
                false,
                event.recovery_window_days,
                &entry["body"],
            )?;
        }
        for (item_id, publisher, height) in &event.withdrawals {
            record_withdrawal(conn, item_id, publisher, *height)?;
        }
        apply_labels(conn, event, &mut stats)?;
        let label_ids: Vec<(String, Option<String>)> = event
            .label_ids
            .iter()
            .map(|label_id| {
                let subject = event
                    .labels
                    .iter()
                    .find(|sealed| &sealed.label_id == label_id)
                    .map(|sealed| sealed.label.subject.clone());
                (label_id.clone(), subject)
            })
            .collect();
        record_sealed(conn, &label_ids, &[])?;
    }
    let written = materializer.apply(conn, replay, events, &mut stats)?;
    // WIST-3 §6.2: an Item withdrawn while no record materializes it leaves no link history either.
    for event in events {
        for (item_id, _, _) in &event.withdrawals {
            super::persist::retract_links(conn, item_id)?;
        }
    }
    materializer.retry(conn, replay, &written)?;
    let history = KeyHistory::from_declarations(replay.declarations().clone());
    record_identity_starts(conn, &history)?;
    save_history(conn, &history)?;
    save_state_tuples(conn, &replay.state_entries())?;
    Ok(stats)
}

/// WIST-4 §8: a fresh identity's activation height restarts the domain's history.
fn record_identity_starts(conn: &Connection, history: &KeyHistory) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_RANKING)?;
    for (domain, state) in history.declarations().domains() {
        let Some(reset) = state.reset() else {
            continue;
        };
        conn.execute(
            "INSERT INTO identity_starts(domain, height) VALUES (?1, ?2)
             ON CONFLICT(domain) DO UPDATE SET height = excluded.height",
            (domain, reset.epoch_number as i64),
        )?;
    }
    Ok(())
}

/// WIST-4 §6: every sealed Labeler Entry moves its last sealed height.
fn apply_labels(conn: &Connection, event: &EpochEvent, stats: &mut ApplyStats) -> Result<()> {
    for publisher in &event.publishers {
        super::persist::touch_labeler(conn, publisher, event.height)?;
    }
    for sealed in &event.labels {
        super::persist::record_label(
            conn,
            &sealed.label,
            &sealed.label_id,
            sealed.height,
            sealed.entry_index,
        )?;
        stats.labels += 1;
    }
    for sealed in &event.disputes {
        super::persist::record_dispute(
            conn,
            &sealed.dispute,
            &sealed.dispute_id,
            sealed.height,
            sealed.entry_index,
        )?;
        stats.labels += 1;
    }
    Ok(())
}
