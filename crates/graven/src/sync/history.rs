use super::persist::{record_withdrawal, save_history};
use super::source::Sources;
use super::tree::Tree;
use super::SyncState;
use crate::error::{Error, Result};
use crate::keyset::KeyHistory;
use crate::store::{table_exists, CREATE_TIER1};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use wist_core::aggregator_keys::Registry;
use wist_core::checkpoint::{self, check_consistency, Adoption, Checkpoint, WitnessKey};
use wist_core::collection::Limits;
use wist_core::epoch::verify_epoch;
use wist_core::merkle::consistency_proof_from;
use wist_core::objects::PublisherEnvelope;
use wist_core::parameters::{Amendment, Schedule};
use wist_core::suffix_list::EpochCaps;
use wist_core::timestamp::log_seconds;
use wist_core::withdrawal::{Disposition, SealedItems, WithdrawalReplay};

/// WIST-4 §9 and ADR-0020.
pub struct ChainState {
    schedule: Option<Schedule>,
    adopted: Vec<Amendment>,
    largest: u64,
    prior_at: Option<i64>,
}

impl ChainState {
    pub fn fresh() -> Self {
        Self {
            schedule: None,
            adopted: Vec::new(),
            largest: 0,
            prior_at: None,
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
        }
    }

    fn schedule_at(&mut self, at: i64) -> &mut Schedule {
        if self.schedule.is_none() {
            let mut schedule = Schedule::new(at);
            for amendment in self.adopted.drain(..) {
                schedule.adopt(amendment);
            }
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
}

fn default_of(parameter: &str) -> u64 {
    wist_core::parameters::spec(parameter)
        .and_then(|p| p.default)
        .unwrap_or(0)
        .max(0) as u64
}

pub struct EpochEvent {
    pub height: u64,
    /// The `sha256:` form of WIST-3 §3.1.
    pub epoch_root: String,
    pub sealed_at: String,
    pub sealed_at_s: i64,
    pub url_cap_bytes: i64,
    pub clock_skew_seconds: i64,
    /// WIST-1 §5.1: in force at `sealed_at`.
    pub limits: Limits,
    /// WIST-1 §5.2: in force at `sealed_at`; freezes the end of a recovery window opened in this
    /// Epoch.
    pub recovery_window_days: i64,
    /// WIST-1 §5.2: in force at `sealed_at`.
    pub declaration_activation_epochs: i64,
    /// In canonical Epoch order.
    pub declarations: Vec<Value>,
    /// WIST-3 §6.2: (withdrawn Item ID, Publisher, earliest withdrawing Epoch).
    pub withdrawals: Vec<(String, String, u64)>,
    pub publishers: Vec<String>,
    /// WIST-2 §3.3: paired with the canonical Entry index.
    pub labels: Vec<(u64, Value)>,
    pub disputes: Vec<(u64, Value)>,
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
    pub withdrawals_replay: &'a mut WithdrawalReplay,
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
        withdrawals_replay,
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
    let entries = super::tree::epoch_entries(
        inputs.sources,
        tree,
        previous_size,
        tree_size,
        chain.transport_bound(),
    )
    .map_err(|e| Error::Verify(format!("epoch {n}: {e}")))?;
    // WIST-3 §3.1 and §6: a failure of the Epoch's own Entries is an invalid object.
    let summary = verify_epoch(
        previous_size,
        checkpoint,
        &entries,
        tree.reader(),
        chain.transport_bound(),
    )
    .map_err(|error| Error::Verify(format!("epoch {n}: {error}")))?;

    // WIST-3 §3.3 and §3.4: key acts apply first, in canonical Entry index order, under the keys
    // valid at N−1; a failing key act is ignored.
    let key_acts: Vec<&Value> = entries
        .iter()
        .filter(|entry| entry["type"] == "registry_update")
        .map(|entry| &entry["body"])
        .filter(|body| {
            matches!(
                body["update"]["action"].as_str(),
                Some("aggregator_key_add" | "aggregator_key_remove")
            )
        })
        .collect();
    for outcome in keys.apply_epoch(n, key_acts) {
        if let Some(code) = outcome.code() {
            eprintln!("ignoring an Aggregator key act at height {n}: {code}");
        }
    }
    // Authenticated under the keys valid at N, after this Epoch's key acts.
    let authenticators = keys.valid_at(n);
    let authentic =
        |body: &Value| wist_core::aggregator_keys::authenticate(body, &authenticators).is_ok();

    let sealed_at = checkpoint.sealed_at().to_string();
    let at = checkpoint
        .sealed_at_s()
        .map_err(|e| Error::Verify(format!("epoch {n}: WIST3-E03 {e}")))?;
    let largest = chain.largest.max(summary.octets);
    let schedule = chain.schedule_at(at);
    for (index, entry) in entries.iter().enumerate() {
        let update = &entry["body"]["update"];
        if entry["type"] != "registry_update" || update["action"] != "parameter_change" {
            continue;
        }
        let (Some(parameter), Some(value), Some(effective_at)) = (
            update["details"]["parameter"].as_str(),
            update["details"]["value"].as_i64(),
            update["effective_at"].as_str(),
        ) else {
            continue;
        };
        let Ok(effective_at_s) = log_seconds(effective_at) else {
            continue;
        };
        // WIST-4 §5.1: `WIST4-E11`, changing nothing.
        if !authentic(&entry["body"]) {
            eprintln!("ignoring a parameter_change at height {n}: WIST4-E11");
            continue;
        }
        let _ = schedule.try_accept_with_epoch_size(
            Amendment {
                parameter: parameter.to_owned(),
                value,
                epoch_number: n,
                entry_index: index as u64,
                sealed_at_s: at,
                effective_at_s,
            },
            largest,
        );
    }
    if largest > schedule.epoch_size_bounds(at).0 {
        return Err(Error::Verify(format!(
            "epoch {n}: WIST3-E03 Epoch exceeds the accepted size schedule"
        )));
    }
    let in_force = |name: &str| {
        schedule
            .value_at(name, at)
            .ok_or_else(|| Error::Verify(format!("epoch {n}: no value of {name} is in force")))
    };
    let url_cap_bytes = in_force("url_cap_bytes")?;
    let clock_skew_seconds = in_force("clock_skew_seconds")?;
    let limits = Limits::new(
        in_force("collections_max")?,
        in_force("scope_entries_max")?,
        url_cap_bytes,
    )
    .map_err(|e| Error::Verify(format!("epoch {n}: {e}")))?;
    let recovery_window_days = schedule.value_at("recovery_window_days", at).unwrap();
    let declaration_activation_epochs = schedule
        .value_at("declaration_activation_epochs", at)
        .unwrap();
    let caps = EpochCaps {
        domain_epoch_entries_max: schedule
            .value_at("domain_epoch_entries_max", at)
            .unwrap()
            .max(0) as u64,
        labeler_epoch_entries_max: schedule
            .value_at("labeler_epoch_entries_max", at)
            .unwrap()
            .max(0) as u64,
    };
    suffix_lists.check_capacity(n, &entries, caps)?;
    for entry in entries.iter().filter(|e| e["type"] == "registry_update") {
        let body = &entry["body"];
        if body["update"]["action"] == "suffix_list_update" {
            suffix_lists.apply_act(
                inputs.sources.client(),
                inputs.sources.primary(),
                n,
                body,
                |key_id| {
                    authenticators
                        .iter()
                        .find(|key| key.key_id == key_id)
                        .map(|key| key.public_key.clone())
                },
            )?;
        }
    }
    chain.largest = largest;
    chain.prior_at = Some(at);

    let mut declarations = Vec::new();
    let mut withdrawal_acts = Vec::new();
    let mut publishers = Vec::new();
    let mut labels = Vec::new();
    let mut disputes = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        match entry.get("type").and_then(Value::as_str) {
            Some("label") => labels.push((index as u64, entry["body"].clone())),
            Some("dispute") => disputes.push((index as u64, entry["body"].clone())),
            Some("publisher_declaration") => {
                if entry.get("body").is_none() {
                    return Err(Error::Verify(format!(
                        "epoch {n}: publisher_declaration entry missing body"
                    )));
                }
                declarations.push(entry.clone());
            }
            Some("registry_update") => {
                let body = entry.get("body").ok_or_else(|| {
                    Error::Verify(format!("epoch {n}: registry_update entry missing body"))
                })?;
                if body["update"]["action"] == "payload_withdrawal" {
                    withdrawal_acts.push(body.clone());
                }
            }
            Some(kind @ ("publisher_catalog" | "publisher_item")) => {
                let outer = kind.trim_start_matches("publisher_");
                if let Some(publisher) = entry["body"][outer]["publisher"].as_str() {
                    publishers.push(publisher.to_owned());
                }
            }
            _ => {}
        }
    }
    let sealed_items = SealedItems::resumed();
    let mut withdrawals = Vec::new();
    for body in &withdrawal_acts {
        let disposition = withdrawals_replay.apply(
            n,
            body,
            |key_id| {
                authenticators
                    .iter()
                    .find(|key| key.key_id == key_id)
                    .map(|key| key.public_key.clone())
            },
            &sealed_items,
        );
        match disposition {
            Disposition::Accepted {
                item_id,
                publisher,
                withdrawn_height,
                ..
            } => withdrawals.push((item_id, publisher, withdrawn_height)),
            Disposition::Rejected(code) => {
                eprintln!("ignoring a payload_withdrawal at height {n}: {code}");
            }
            Disposition::Repeated { .. } | Disposition::NotWithdrawal => {}
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

    let event = EpochEvent {
        height: n,
        epoch_root: checkpoint.root_token(),
        sealed_at,
        sealed_at_s: at,
        url_cap_bytes,
        clock_skew_seconds,
        limits,
        recovery_window_days,
        declaration_activation_epochs,
        declarations,
        withdrawals,
        publishers,
        labels,
        disputes,
    };
    Ok((event, adoption))
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
    super::persist::replace_inlinks(conn, url, publisher, &[], height)
}

pub(super) fn remove_by_item_id(
    conn: &Connection,
    item_id: &str,
    height: u64,
) -> Result<Option<String>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT url, publisher FROM records WHERE item_id = ?1",
            [item_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((url, publisher)) = row else {
        return Ok(None);
    };
    conn.execute("DELETE FROM records WHERE item_id = ?1", [item_id])?;
    remove_derived(conn, item_id, &url)?;
    remove_ranking_bookkeeping(conn, &url, &publisher, height)?;
    Ok(Some(url))
}

pub fn apply_events(
    conn: &Connection,
    history: &mut KeyHistory,
    events: &[EpochEvent],
    tier1: bool,
    walk_floor: u64,
) -> Result<ApplyStats> {
    let mut stats = ApplyStats {
        withdrawn: 0,
        labels: 0,
    };
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    if tier1 {
        conn.execute_batch(CREATE_TIER1)?;
    }
    for event in events {
        history.apply_epoch(
            event.height,
            &event.epoch_root,
            &event.sealed_at,
            event.recovery_window_days,
            event.declaration_activation_epochs,
            &event.limits,
            &event.declarations,
        )?;
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
            if remove_by_item_id(conn, item_id, *height)?.is_some() {
                stats.withdrawn += 1;
            }
        }
        apply_labels(conn, history, event, walk_floor, &mut stats)?;
    }
    record_identity_starts(conn, history)?;
    save_history(conn, history)?;
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

/// WIST-2 §3.3 and WIST-3 §3.3: a failing Entry is ignored. Every sealed Labeler Entry moves its
/// last sealed height (WIST-4 §6).
pub(super) fn apply_labels(
    conn: &Connection,
    history: &KeyHistory,
    event: &EpochEvent,
    walk_floor: u64,
    stats: &mut ApplyStats,
) -> Result<()> {
    for publisher in &event.publishers {
        super::persist::touch_labeler(conn, publisher, event.height)?;
    }
    for (index, body) in &event.labels {
        let labeler = body["label"]["labeler"].as_str().unwrap_or_default();
        let Some(declaration) = history.declaration_for(labeler) else {
            eprintln!(
                "ignoring a Label at height {}: no Declaration for {labeler}",
                event.height
            );
            continue;
        };
        match wist_core::label::validate_label(
            body,
            &declaration,
            event.url_cap_bytes,
            event.sealed_at_s,
            event.clock_skew_seconds,
        ) {
            Ok(envelope) => {
                let id = wist_core::label::label_id(&body["label"])
                    .map_err(|r| Error::Verify(format!("label id: {r:?}")))?;
                super::persist::record_label(conn, &envelope.label, &id, event.height, *index)?;
                stats.labels += 1;
            }
            Err(rejection) => eprintln!(
                "ignoring a Label at height {}: {}",
                event.height,
                rejection.code()
            ),
        }
    }
    for (index, body) in &event.disputes {
        let disputant = body["dispute"]["disputant"].as_str().unwrap_or_default();
        let Some(declaration) = history.declaration_for(disputant) else {
            eprintln!(
                "ignoring a dispute at height {}: no Declaration for {disputant}",
                event.height
            );
            continue;
        };
        // WIST-3 §7: a Snapshot carries only the current Label, so only a miss above the walk floor
        // is genuinely absent.
        let dispute_height = body["dispute"]["height"].as_u64().unwrap_or(u64::MAX);
        let sealed = |label_id: &str| match super::persist::sealed_label_subject(conn, label_id)
            .ok()
            .flatten()
        {
            Some(subject) => wist_core::label::LabelLookup::Known { subject },
            None if dispute_height <= walk_floor => wist_core::label::LabelLookup::Unverifiable,
            None => wist_core::label::LabelLookup::Absent,
        };
        match wist_core::label::validate_dispute(
            body,
            &declaration,
            sealed,
            event.sealed_at_s,
            event.clock_skew_seconds,
        ) {
            Ok(envelope) => {
                let id = wist_core::label::dispute_id(&body["dispute"])
                    .map_err(|r| Error::Verify(format!("dispute id: {r:?}")))?;
                super::persist::record_dispute(conn, &envelope.dispute, &id, event.height, *index)?;
                stats.labels += 1;
            }
            Err(rejection) => eprintln!(
                "ignoring a dispute at height {}: {}",
                event.height,
                rejection.code()
            ),
        }
    }
    Ok(())
}
