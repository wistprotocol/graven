use super::persist::{
    load_chain_tips, load_withdrawn, record_withdrawal, save_chain_tips, save_history,
};
use super::source::Sources;
use super::tree::Tree;
use super::SyncState;
use crate::error::{Error, Result};
use crate::fetch::{resolve, Client};
use crate::keyset::{DeltaProfile, KeyHistory};
use crate::store::{table_exists, CREATE_TIER1};
use reqwest::Url;
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use wist_core::aggregator_keys::Registry;
use wist_core::checkpoint::{self, check_consistency, Adoption, Checkpoint, WitnessKey};
use wist_core::delta::{content_bytes, verify_commitment};
use wist_core::epoch::verify_epoch;
use wist_core::merkle::consistency_proof_from;
use wist_core::objects::{
    ChangeType, DeltaEnvelope, DeltaPayloadCommitment, Payload, PublisherEnvelope,
};
use wist_core::parameters::{Amendment, Schedule};
use wist_core::suffix_list::EpochCaps;
use wist_core::timestamp::log_seconds;
use wist_core::withdrawal::{Disposition, SealedDelta, WithdrawalReplay};

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
    /// WIST-1 §3.4: accepted at `sealed_at`.
    pub profile: DeltaProfile,
    /// WIST-1 §5.2: in force at `sealed_at`; freezes the end of a recovery window opened in this
    /// Epoch.
    pub recovery_window_days: i64,
    /// WIST-1 §5.2: in force at `sealed_at`.
    pub declaration_activation_epochs: i64,
    /// In canonical Epoch order.
    pub declarations: Vec<Value>,
    /// WIST-3 §6.2: (withdrawn Delta ID, Publisher, earliest withdrawing Epoch).
    pub withdrawals: Vec<(String, String, u64)>,
    pub delta_bodies: Vec<Value>,
    /// WIST-2 §3.3: paired with the canonical Entry index.
    pub labels: Vec<(u64, Value)>,
    pub disputes: Vec<(u64, Value)>,
}

pub struct ApplyStats {
    pub applied: u64,
    pub withdrawn: u64,
    pub labels: u64,
}

pub(super) struct PayloadFields {
    title: String,
    abstract_text: Option<String>,
    extract: Option<String>,
    links: Vec<String>,
}

pub(super) fn fetch_payload(
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
    let mut walked_deltas: BTreeMap<String, (String, u64)> = BTreeMap::new();
    let mut previous = head.clone();
    let reached = head.epoch_number();
    let mut stopped: Option<Stop> = None;
    for checkpoint in offered {
        match verify_checkpoint(
            inputs,
            state,
            reached,
            &previous,
            checkpoint,
            &mut walked_deltas,
        ) {
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
    walked_deltas: &mut BTreeMap<String, (String, u64)>,
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
    let profile = DeltaProfile::from_schedule(schedule, at);
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
    let mut delta_bodies = Vec::new();
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
            Some("publisher_delta") => {
                let body = entry.get("body").ok_or_else(|| {
                    Error::Verify(format!("epoch {n}: publisher_delta entry missing body"))
                })?;
                delta_bodies.push(body.clone());
            }
            _ => {}
        }
    }
    for body in &delta_bodies {
        if let (Ok(id), Some(publisher)) = (
            wist_core::delta::delta_id(&body["delta"]),
            body["delta"]["publisher"].as_str(),
        ) {
            walked_deltas
                .entry(id)
                .or_insert((publisher.to_string(), n));
        }
    }
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
            |delta_id| match walked_deltas.get(delta_id) {
                Some((publisher, height)) => SealedDelta::Known {
                    publisher: publisher.clone(),
                    height: *height,
                },
                None => SealedDelta::Unverifiable,
            },
        );
        match disposition {
            Disposition::Accepted {
                delta_id,
                publisher,
                withdrawn_height,
                ..
            } => withdrawals.push((delta_id, publisher, withdrawn_height)),
            Disposition::Rejected(code) => {
                eprintln!("ignoring a payload_withdrawal at height {n}: {code}");
            }
            Disposition::NotWithdrawal => {}
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
        profile,
        recovery_window_days,
        declaration_activation_epochs,
        declarations,
        withdrawals,
        delta_bodies,
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

pub(super) fn remove_derived(conn: &Connection, delta_id: &str, url: &str) -> Result<()> {
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

pub(super) fn remove_by_delta_id(
    conn: &Connection,
    delta_id: &str,
    height: u64,
) -> Result<Option<String>> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT url, publisher FROM records WHERE delta_id = ?1",
            [delta_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((url, publisher)) = row else {
        return Ok(None);
    };
    conn.execute("DELETE FROM records WHERE delta_id = ?1", [delta_id])?;
    remove_derived(conn, delta_id, &url)?;
    remove_ranking_bookkeeping(conn, &url, &publisher, height)?;
    Ok(Some(url))
}

pub(super) fn remove_by_url(
    conn: &Connection,
    url: &str,
    publisher: &str,
    height: u64,
) -> Result<()> {
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
    remove_ranking_bookkeeping(conn, url, publisher, height)?;
    Ok(())
}

/// WIST-3 §7: excluded records are candidates too.
fn candidates_for(conn: &Connection, url: &str) -> Result<Vec<String>> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut stmt = conn.prepare("SELECT publisher FROM records WHERE url = ?1")?;
    for row in stmt.query_map([url], |r| r.get::<_, String>(0))? {
        set.insert(row?);
    }
    drop(stmt);
    let mut stmt = conn.prepare("SELECT publisher FROM excluded_records WHERE url = ?1")?;
    for row in stmt.query_map([url], |r| r.get::<_, String>(0))? {
        set.insert(row?);
    }
    Ok(set.into_iter().collect())
}

struct ExcludedRow {
    delta_id: String,
    observed_at: String,
    title: String,
    abstract_text: Option<String>,
    lang: String,
    extract: Option<String>,
    links: Option<String>,
    height: u64,
}

fn fetch_excluded(conn: &Connection, url: &str, publisher: &str) -> Result<Option<ExcludedRow>> {
    conn.query_row(
        "SELECT delta_id, observed_at, title, abstract, lang, extract, links, height
         FROM excluded_records WHERE url = ?1 AND publisher = ?2",
        (url, publisher),
        |row| {
            Ok(ExcludedRow {
                delta_id: row.get(0)?,
                observed_at: row.get(1)?,
                title: row.get(2)?,
                abstract_text: row.get(3)?,
                lang: row.get(4)?,
                extract: row.get(5)?,
                links: row.get(6)?,
                height: row.get::<_, i64>(7)?.max(0) as u64,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
fn write_excluded(
    conn: &Connection,
    url: &str,
    publisher: &str,
    delta_id: &str,
    observed_at: &str,
    title: &str,
    abstract_text: &Option<String>,
    lang: &str,
    extract: Option<&str>,
    links: &[String],
    height: u64,
) -> Result<()> {
    let links_json = serde_json::to_string(links)?;
    conn.execute(
        "INSERT INTO excluded_records(url, publisher, delta_id, observed_at, title, abstract, lang, extract, links, height)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(url, publisher) DO UPDATE SET
            delta_id = excluded.delta_id, observed_at = excluded.observed_at, title = excluded.title,
            abstract = excluded.abstract, lang = excluded.lang, extract = excluded.extract,
            links = excluded.links, height = excluded.height",
        (
            url, publisher, delta_id, observed_at, title, abstract_text, lang, extract,
            &links_json, height as i64,
        ),
    )?;
    Ok(())
}

/// WIST-3 §7: the displaced record moves into `excluded_records` before the winner's record is
/// written.
fn shadow_into_excluded(
    conn: &Connection,
    url: &str,
    publisher: &str,
    tier1: bool,
    at_height: u64,
) -> Result<()> {
    let record: Option<(String, String, String, Option<String>, String)> = conn
        .query_row(
            "SELECT delta_id, observed_at, title, abstract, lang FROM records WHERE url = ?1 AND publisher = ?2",
            (url, publisher),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let Some((delta_id, observed_at, title, abstract_text, lang)) = record else {
        return Ok(());
    };
    let height: u64 = conn
        .query_row(
            "SELECT height FROM record_heights WHERE url = ?1 AND publisher = ?2",
            (url, publisher),
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0)
        .max(0) as u64;
    let extract: Option<String> = if tier1 {
        conn.query_row(
            "SELECT extract FROM extracts WHERE url = ?1 AND publisher = ?2",
            (url, publisher),
            |row| row.get(0),
        )
        .optional()?
    } else {
        None
    };
    let links_json: Option<String> = if tier1 {
        let mut stmt =
            conn.prepare("SELECT target_url FROM links WHERE source_url = ?1 ORDER BY position")?;
        let targets: Vec<String> = stmt
            .query_map([url], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Some(serde_json::to_string(&targets)?)
    } else {
        None
    };
    conn.execute(
        "INSERT INTO excluded_records(url, publisher, delta_id, observed_at, title, abstract, lang, extract, links, height)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(url, publisher) DO UPDATE SET
            delta_id = excluded.delta_id, observed_at = excluded.observed_at, title = excluded.title,
            abstract = excluded.abstract, lang = excluded.lang, extract = excluded.extract,
            links = excluded.links, height = excluded.height",
        (
            url, publisher, &delta_id, &observed_at, &title, &abstract_text, &lang, &extract,
            &links_json, height as i64,
        ),
    )?;
    remove_by_url(conn, url, publisher, at_height)
}

fn restore_excluded_row(
    conn: &Connection,
    url: &str,
    publisher: &str,
    row: &ExcludedRow,
    tier1: bool,
) -> Result<()> {
    conn.execute(
        "INSERT INTO records(url, publisher, delta_id, observed_at, title, abstract, lang)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(url, publisher) DO UPDATE SET
            delta_id = excluded.delta_id, observed_at = excluded.observed_at,
            title = excluded.title, abstract = excluded.abstract, lang = excluded.lang",
        (
            url,
            publisher,
            &row.delta_id,
            &row.observed_at,
            &row.title,
            &row.abstract_text,
            &row.lang,
        ),
    )?;
    super::persist::record_height(conn, url, publisher, row.height)?;
    if tier1 {
        if let Some(extract) = &row.extract {
            conn.execute(
                "INSERT INTO extracts(url, publisher, delta_id, extract) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(url, publisher) DO UPDATE SET delta_id = excluded.delta_id, extract = excluded.extract",
                (url, publisher, &row.delta_id, extract),
            )?;
        }
        let links: Vec<String> = row
            .links
            .as_deref()
            .map(|s| serde_json::from_str(s).unwrap_or_default())
            .unwrap_or_default();
        conn.execute("DELETE FROM links WHERE source_url = ?1", [url])?;
        for (position, target_url) in links.iter().enumerate() {
            conn.execute(
                "INSERT INTO links(source_url, target_url, position) VALUES (?1, ?2, ?3)",
                (url, target_url, position as i64),
            )?;
        }
        super::persist::replace_inlinks(conn, url, publisher, &links, row.height)?;
    }
    conn.execute(
        "DELETE FROM excluded_records WHERE url = ?1 AND publisher = ?2",
        (url, publisher),
    )?;
    Ok(())
}

/// WIST-3 §7.
fn recompute_and_restore(
    conn: &Connection,
    history: &KeyHistory,
    url: &str,
    tier1: bool,
) -> Result<()> {
    let host = wist_core::declaration::url_host(url);
    let self_declared = history.declared(host);
    let candidates = candidates_for(conn, url)?;
    let Some(winner) = wist_core::materialization::preferred(
        host,
        self_declared,
        candidates.iter().map(String::as_str),
    ) else {
        return Ok(());
    };
    let winner = winner.to_string();
    let already_live: bool = conn
        .query_row(
            "SELECT 1 FROM records WHERE url = ?1 AND publisher = ?2",
            (url, &winner),
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if already_live {
        return Ok(());
    }
    let Some(row) = fetch_excluded(conn, url, &winner)? else {
        return Ok(());
    };
    restore_excluded_row(conn, url, &winner, &row, tier1)
}

/// WIST-3 §7: at a domain's `seq`-0 Declaration height, other Publishers' records for its URLs are
/// excluded as by `delete`. Idempotent.
fn sweep_declared_domain(
    conn: &Connection,
    history: &KeyHistory,
    domain: &str,
    tier1: bool,
    height: u64,
) -> Result<()> {
    let prefix = format!("https://{domain}%");

    let mut estmt =
        conn.prepare("SELECT url, publisher FROM excluded_records WHERE url LIKE ?1")?;
    let excluded_rows: Vec<(String, String)> = estmt
        .query_map([&prefix], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    drop(estmt);
    for (url, publisher) in excluded_rows {
        if publisher != domain && wist_core::declaration::url_host(&url) == domain {
            conn.execute(
                "DELETE FROM excluded_records WHERE url = ?1 AND publisher = ?2",
                (&url, &publisher),
            )?;
        }
    }

    let mut stmt = conn.prepare("SELECT url, publisher FROM records WHERE url LIKE ?1")?;
    let rows: Vec<(String, String)> = stmt
        .query_map([&prefix], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);
    for (url, publisher) in rows {
        if publisher != domain && wist_core::declaration::url_host(&url) == domain {
            remove_by_url(conn, &url, &publisher, height)?;
            recompute_and_restore(conn, history, &url, tier1)?;
        }
    }
    Ok(())
}

fn remove_excluded_by_delta_id(conn: &Connection, delta_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM excluded_records WHERE delta_id = ?1",
        [delta_id],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn apply_events(
    conn: &Connection,
    client: &Client,
    base: &Url,
    history: &mut KeyHistory,
    events: &[EpochEvent],
    tier1: bool,
    walk_floor: u64,
) -> Result<ApplyStats> {
    let mut stats = ApplyStats {
        applied: 0,
        withdrawn: 0,
        labels: 0,
    };
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    if tier1 {
        conn.execute_batch(CREATE_TIER1)?;
    }
    conn.execute_batch(crate::store::CREATE_CHAIN_TIPS)?;
    conn.execute_batch(crate::store::CREATE_EXCLUDED_RECORDS)?;
    let mut tips = load_chain_tips(conn)?;
    let mut withdrawn = load_withdrawn(conn)?;
    for event in events {
        let sealed_at_s = event.sealed_at_s;
        history.apply_epoch(
            event.height,
            &event.epoch_root,
            &event.sealed_at,
            event.recovery_window_days,
            event.declaration_activation_epochs,
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
        for entry in &event.declarations {
            if let Some(domain) = entry["body"]["publisher"]["domain"].as_str() {
                sweep_declared_domain(conn, history, domain, tier1, event.height)?;
            }
        }
        for (delta_id, publisher, height) in &event.withdrawals {
            record_withdrawal(conn, delta_id, publisher, *height)?;
            withdrawn.adopt(delta_id, publisher, *height);
            if let Some(url) = remove_by_delta_id(conn, delta_id, *height)? {
                stats.withdrawn += 1;
                recompute_and_restore(conn, history, &url, tier1)?;
            }
            // WIST-3 §7: withdrawn content never materializes, so its excluded record never
            // returns.
            remove_excluded_by_delta_id(conn, delta_id)?;
        }

        for body in &event.delta_bodies {
            // WIST-3 §3.3: a Delta failing its Epoch's Key Set, fields, version, caps or clock is
            // ignored like a fork, never ending the sync.
            let verified =
                match history.verify_delta(event.height, sealed_at_s, &event.profile, body) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("ignoring a Delta at height {}: {e}", event.height);
                        continue;
                    }
                };
            let env: DeltaEnvelope = serde_json::from_value(body.clone())?;
            let id = verified.id;
            let publisher = verified.publisher;
            // WIST-1 §3.5: a `prev` other than the chain tip is a fork.
            if !tips.apply(&publisher, &env.delta.url, &id, env.delta.prev.as_deref()) {
                continue;
            }
            // WIST-3 §7: once a host self-declares, a parent's Deltas for its URLs move the chain
            // tip but never materialize.
            if verified.self_declared && publisher != verified.host {
                continue;
            }
            // WIST-3 §6.2: even when the withdrawal sealed in the same Epoch.
            if withdrawn.is_withdrawn(&id) {
                continue;
            }

            match env.delta.change_type {
                ChangeType::New | ChangeType::Update => {
                    let hex = id.trim_start_matches("sha256:");
                    let fields = match &env.delta.payload {
                        Some(commitment) => fetch_payload(client, base, hex, commitment).ok(),
                        None => None,
                    };
                    let title = fields.as_ref().map(|f| f.title.clone()).unwrap_or_default();
                    let abstract_text = fields.as_ref().and_then(|f| f.abstract_text.clone());
                    let extract = fields.as_ref().and_then(|f| f.extract.clone());
                    let links = fields.as_ref().map(|f| f.links.clone()).unwrap_or_default();

                    let mut candidates = candidates_for(conn, &env.delta.url)?;
                    if !candidates.contains(&publisher) {
                        candidates.push(publisher.clone());
                    }
                    let winner = wist_core::materialization::preferred(
                        &verified.host,
                        verified.self_declared,
                        candidates.iter().map(String::as_str),
                    )
                    .map(str::to_string);

                    if winner.as_deref() == Some(publisher.as_str()) {
                        let holder: Option<String> = conn
                            .query_row(
                                "SELECT publisher FROM records WHERE url = ?1 LIMIT 1",
                                [&env.delta.url],
                                |row| row.get(0),
                            )
                            .optional()?;
                        if let Some(holder) = &holder {
                            if holder != &publisher {
                                shadow_into_excluded(
                                    conn,
                                    &env.delta.url,
                                    holder,
                                    tier1,
                                    event.height,
                                )?;
                            }
                        }

                        conn.execute(
                            "INSERT INTO records(url, publisher, delta_id, observed_at, title, abstract, lang)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                             ON CONFLICT(url, publisher) DO UPDATE SET
                                delta_id = excluded.delta_id, observed_at = excluded.observed_at,
                                title = excluded.title, abstract = excluded.abstract,
                                lang = excluded.lang",
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
                        super::persist::record_height(
                            conn,
                            &env.delta.url,
                            &publisher,
                            event.height,
                        )?;
                        conn.execute(
                            "DELETE FROM excluded_records WHERE url = ?1 AND publisher = ?2",
                            (&env.delta.url, &publisher),
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
                                    super::persist::replace_inlinks(
                                        conn,
                                        &env.delta.url,
                                        &publisher,
                                        &f.links,
                                        event.height,
                                    )?;
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
                    } else {
                        write_excluded(
                            conn,
                            &env.delta.url,
                            &publisher,
                            &id,
                            &env.delta.observed_at,
                            &title,
                            &abstract_text,
                            &env.delta.meta.lang,
                            extract.as_deref(),
                            &links,
                            event.height,
                        )?;
                    }
                }
                ChangeType::Delete => {
                    remove_by_url(conn, &env.delta.url, &publisher, event.height)?;
                    conn.execute(
                        "DELETE FROM excluded_records WHERE url = ?1 AND publisher = ?2",
                        (&env.delta.url, &publisher),
                    )?;
                    recompute_and_restore(conn, history, &env.delta.url, tier1)?;
                }
                ChangeType::Attest => {
                    // WIST-3 §7: an attest refreshes `observed_at` and keeps its anchor Delta.
                    conn.execute(
                        "UPDATE records SET observed_at = ?3 WHERE url = ?1 AND publisher = ?2",
                        (&env.delta.url, &publisher, &env.delta.observed_at),
                    )?;
                    conn.execute(
                        "UPDATE excluded_records SET observed_at = ?3 WHERE url = ?1 AND publisher = ?2",
                        (&env.delta.url, &publisher, &env.delta.observed_at),
                    )?;
                }
            }
        }
        apply_labels(conn, history, event, walk_floor, &mut stats)?;
    }
    save_chain_tips(conn, &tips)?;
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

/// WIST-2 §3.3 and WIST-3 §3.3: applied after the Epoch's Deltas; a failing Entry is ignored like a
/// forked Delta. Every sealed Labeler Entry moves its last sealed height (WIST-4 §6).
pub(super) fn apply_labels(
    conn: &Connection,
    history: &KeyHistory,
    event: &EpochEvent,
    walk_floor: u64,
    stats: &mut ApplyStats,
) -> Result<()> {
    for body in &event.delta_bodies {
        if let Some(publisher) = body["delta"]["publisher"].as_str() {
            super::persist::touch_labeler(conn, publisher, event.height)?;
        }
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
            event.profile.url_cap_bytes,
            event.sealed_at_s,
            event.profile.clock_skew_seconds,
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
            event.profile.clock_skew_seconds,
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
