use super::persist::{
    load_chain_tips, load_withdrawn, record_withdrawal, save_chain_tips, save_history,
};
use super::SyncState;
use crate::error::{Error, Result};
use crate::fetch::{resolve, Client};
use crate::keyset::{DeltaProfile, KeyHistory};
use crate::store::{table_exists, CREATE_TIER1};
use reqwest::Url;
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use wist_core::block::{block_hash, verify_block, verify_chain_link};
use wist_core::crypto::PublicKey;
use wist_core::delta::{content_bytes, verify_commitment};
use wist_core::envelope::verify_envelope;
use wist_core::objects::{
    ChangeType, DeltaEnvelope, DeltaPayloadCommitment, Payload, PublisherEnvelope,
};
use wist_core::parameters::{Amendment, Schedule};
use wist_core::suffix_list::BlockCaps;
use wist_core::timestamp::log_seconds;
use wist_core::withdrawal::{Disposition, SealedDelta, WithdrawalReplay};

/// WIST-4 §9 and ADR-0020: the accepted parameter schedule, the largest
/// Block seen and the previous Block's instant, carried across the walk
/// and across restarts so amendments, size bounds and the cadence grid are
/// checked as a replaying Consumer checks them.
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

    /// The schedule a Snapshot's `parameter` tuples restore (WIST-3 §7):
    /// accepted amendments whose sealing position the Snapshot does not
    /// carry, adopted before the first walked Block.
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
                    block_number: 0,
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
            largest: state.largest_block_bytes,
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

    fn transport_bound(&self) -> u64 {
        match (&self.schedule, self.prior_at) {
            (Some(schedule), Some(at)) => schedule.block_size_bounds(at).1,
            _ => wist_core::parameters::spec("block_decompressed_cap_bytes")
                .and_then(|p| p.default)
                .unwrap_or(0) as u64,
        }
    }

    pub fn accepted(&self) -> Vec<Amendment> {
        self.schedule
            .as_ref()
            .map(|s| s.accepted().to_vec())
            .unwrap_or_default()
    }

    pub fn schedule_first_s(&self) -> Option<i64> {
        self.schedule.as_ref().map(|s| s.first_block_s())
    }

    pub fn prior_at(&self) -> Option<i64> {
        self.prior_at
    }

    pub fn largest(&self) -> u64 {
        self.largest
    }
}

pub struct BlockEvent {
    pub height: u64,
    pub block_hash: String,
    pub prev_block_hash: String,
    pub sealed_at: String,
    pub sealed_at_s: i64,
    /// The caps and clock allowance accepted at `sealed_at`, under which
    /// every Delta this Block seals is validated (WIST-1 §3.4).
    pub profile: DeltaProfile,
    /// `recovery_window_days` in force at `sealed_at`, which freezes the
    /// end of a recovery window opened in this Block (WIST-1 §5.2).
    pub recovery_window_days: i64,
    /// The `publisher_declaration` Entries in canonical Block order.
    pub declarations: Vec<Value>,
    /// Each `payload_withdrawal` this Block seals that core's replay
    /// accepted (WIST-4 §5.1): the withdrawn Delta ID, its Publisher and
    /// the earliest Block that withdrew it (WIST-3 §6.2).
    pub withdrawals: Vec<(String, String, u64)>,
    pub delta_bodies: Vec<Value>,
    /// The `label` Entries with their canonical Entry index (WIST-2 §3.3).
    pub labels: Vec<(u64, Value)>,
    /// The `dispute` Entries with their canonical Entry index.
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

/// WIST-3 §3.4: a Block sealed at height N MUST be signed by a key
/// valid at N — the genesis key, or one a validly-signed
/// `aggregator_key_add` sealed at a height ≤ N named and no
/// `aggregator_key_remove` has retired. Removal is permanent, so an
/// `aggregator_key_add` naming a removed `key_id` is rejected and
/// restores nothing.
pub struct AggregatorKeys {
    pub(super) valid: BTreeMap<String, PublicKey>,
    pub(super) removed: BTreeSet<String>,
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
pub(super) fn verify_checkpoint_signature(
    checkpoint_value: &Value,
    keys: &AggregatorKeys,
) -> Result<()> {
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

#[allow(clippy::too_many_arguments)]
pub fn walk_blocks(
    client: &Client,
    base: &Url,
    keys: &mut AggregatorKeys,
    chain: &mut ChainState,
    withdrawals_replay: &mut WithdrawalReplay,
    suffix_lists: &mut super::suffix::SuffixLists,
    start_number: u64,
    end_number: u64,
    start_hash: &str,
) -> Result<(Vec<BlockEvent>, Option<Value>)> {
    let mut prev_hash = start_hash.to_string();
    let mut last_block_value: Option<Value> = None;
    let mut events: Vec<BlockEvent> = Vec::new();
    let mut walked_deltas: BTreeMap<String, (String, u64)> = BTreeMap::new();
    for n in start_number..=end_number {
        let block_url = resolve(base, &format!("/log/blocks/{n:09}.json.zst"))?;
        let compressed = client.get_bytes(&block_url)?;
        let decompressed = wist_core::block_frames::decode(&compressed, chain.transport_bound())
            .map_err(|e| Error::Verify(format!("block {n}: {e}")))?;
        let block_value = wist_core::json::parse(&decompressed)
            .map_err(|e| Error::Verify(format!("block {n}: WIST3-E03 {e}")))?;
        if wist_core::jcs::canonicalize(&block_value)? != decompressed {
            return Err(Error::Verify(format!(
                "block {n}: WIST3-E03 Block file does not contain canonical JCS bytes"
            )));
        }
        wist_core::block::validate_entry_order(
            block_value["entries"]
                .as_array()
                .map_or(&[][..], Vec::as_slice),
        )
        .map_err(|e| Error::Verify(format!("block {n}: {e}")))?;
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
            if matches!(
                body["update"]["action"].as_str(),
                Some("aggregator_key_add" | "aggregator_key_remove")
            ) {
                let signer = keys.signer_of(body)?.clone();
                verify_envelope(body, "update", &signer)?;
                keys.apply(body)?;
            }
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
        let at = log_seconds(&sealed_at)
            .map_err(|e| Error::Verify(format!("block {n}: WIST3-E03 {e}")))?;
        if chain.prior_at.is_some_and(|prior| at <= prior) {
            return Err(Error::Verify(format!(
                "block {n}: WIST3-E03 Block timestamps are not strictly increasing"
            )));
        }
        let cadence_at = chain.prior_at.unwrap_or(at);
        let largest = chain.largest.max(decompressed.len() as u64);
        let schedule = chain.schedule_at(at);
        let cadence = schedule
            .value_at("block_cadence_seconds", cadence_at)
            .unwrap_or(1);
        if at.rem_euclid(cadence) != 0 {
            return Err(Error::Verify(format!(
                "block {n}: WIST3-E03 Block timestamp is off the accepted cadence grid"
            )));
        }
        for (index, entry) in block_value
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
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
            let _ = schedule.try_accept_with_block_size(
                Amendment {
                    parameter: parameter.to_owned(),
                    value,
                    block_number: n,
                    entry_index: index as u64,
                    sealed_at_s: at,
                    effective_at_s,
                },
                largest,
            );
        }
        if largest > schedule.block_size_bounds(at).0 {
            return Err(Error::Verify(format!(
                "block {n}: WIST3-E03 Block exceeds the accepted size schedule"
            )));
        }
        let profile = DeltaProfile::from_schedule(schedule, at);
        let recovery_window_days = schedule.value_at("recovery_window_days", at).unwrap();
        let caps = BlockCaps {
            domain_block_entries_max: schedule
                .value_at("domain_block_entries_max", at)
                .unwrap()
                .max(0) as u64,
            labeler_block_entries_max: schedule
                .value_at("labeler_block_entries_max", at)
                .unwrap()
                .max(0) as u64,
        };
        suffix_lists.check_capacity(n, &block_value, caps)?;
        for entry in block_value
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|e| e["type"] == "registry_update")
        {
            let body = &entry["body"];
            if body["update"]["action"] == "suffix_list_update" {
                suffix_lists
                    .apply_act(client, base, n, body, |key_id| keys.key(key_id).cloned())?;
            }
        }
        chain.largest = largest;
        chain.prior_at = Some(at);

        let mut declarations = Vec::new();
        let mut withdrawal_acts = Vec::new();
        let mut delta_bodies = Vec::new();
        let mut labels = Vec::new();
        let mut disputes = Vec::new();

        for (index, entry) in block_value
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            match entry.get("type").and_then(Value::as_str) {
                Some("label") => labels.push((index as u64, entry["body"].clone())),
                Some("dispute") => disputes.push((index as u64, entry["body"].clone())),
                Some("publisher_declaration") => {
                    if entry.get("body").is_none() {
                        return Err(Error::Verify(format!(
                            "block {n}: publisher_declaration entry missing body"
                        )));
                    }
                    declarations.push(entry.clone());
                }
                Some("registry_update") => {
                    let body = entry.get("body").ok_or_else(|| {
                        Error::Verify(format!("block {n}: registry_update entry missing body"))
                    })?;
                    if body["update"]["action"] == "payload_withdrawal" {
                        withdrawal_acts.push(body.clone());
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
                |key_id| keys.key(key_id).cloned(),
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

        events.push(BlockEvent {
            height: n,
            block_hash: wist_core::block::block_hash(&block_value["header"])?,
            prev_block_hash: block_value["header"]["prev_block_hash"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            sealed_at,
            sealed_at_s: at,
            profile,
            recovery_window_days,
            declarations,
            withdrawals,
            delta_bodies,
            labels,
            disputes,
        });
        last_block_value = Some(block_value);
    }
    Ok((events, last_block_value))
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
    conn.execute(
        "INSERT INTO declarations(domain, seq, height, sealed_at, baseline, envelope, recovery_window_days) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
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

pub(super) fn remove_by_delta_id(conn: &Connection, delta_id: &str) -> Result<bool> {
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

pub(super) fn remove_by_url(conn: &Connection, url: &str, publisher: &str) -> Result<()> {
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
        labels: 0,
    };
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    if tier1 {
        conn.execute_batch(CREATE_TIER1)?;
    }
    conn.execute_batch(crate::store::CREATE_CHAIN_TIPS)?;
    let mut tips = load_chain_tips(conn)?;
    let mut withdrawn = load_withdrawn(conn)?;
    for event in events {
        let sealed_at_s = event.sealed_at_s;
        history.apply_block(
            event.height,
            &event.prev_block_hash,
            &event.block_hash,
            &event.sealed_at,
            event.recovery_window_days,
            &event.declarations,
        )?;
        for entry in &event.declarations {
            persist_declaration(
                conn,
                event.height,
                &event.sealed_at,
                false,
                event.recovery_window_days,
                &entry["body"],
            )?;
        }
        for (delta_id, publisher, height) in &event.withdrawals {
            record_withdrawal(conn, delta_id, publisher, *height)?;
            withdrawn.adopt(delta_id, publisher, *height);
            if remove_by_delta_id(conn, delta_id)? {
                stats.withdrawn += 1;
            }
        }

        for body in &event.delta_bodies {
            // WIST-3 §3.3: a sealed Delta that fails the Key Set its own
            // Block resolves is ignored exactly as a fork is — applied to
            // nothing, moving no chain tip — never a reason to abandon
            // the sync; field, version, cap and clock failures share
            // that disposition.
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
            // WIST-1 §3.5: a Delta whose prev is not the chain tip the
            // state carries is a fork, and moves nothing.
            if !tips.apply(&publisher, &env.delta.url, &id, env.delta.prev.as_deref()) {
                continue;
            }
            if !verified.materializes {
                continue;
            }
            // WIST-3 §6.2: a withdrawn Delta's content never materializes,
            // even when the withdrawal sealed in the same Block.
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
        apply_labels(conn, history, event, &mut stats)?;
    }
    save_chain_tips(conn, &tips)?;
    save_history(conn, history)?;
    Ok(stats)
}

/// WIST-2 §3.3 and WIST-3 §3.3: applies a Block's `label` and `dispute`
/// Entries after its Deltas, each validated under its signer's Declaration
/// as the Aggregator validated it; one that fails is ignored like a
/// forked Delta. Every sealed Entry of a Labeler moves its last sealed
/// height (WIST-4 §6).
pub(super) fn apply_labels(
    conn: &Connection,
    history: &KeyHistory,
    event: &BlockEvent,
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
        match wist_core::label::validate_label(body, &declaration, event.profile.url_cap_bytes) {
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
        let sealed = |label_id: &str| {
            super::persist::sealed_label_subject(conn, label_id)
                .ok()
                .flatten()
                .map_or(wist_core::label::LabelLookup::Absent, |subject| {
                    wist_core::label::LabelLookup::Known { subject }
                })
        };
        match wist_core::label::validate_dispute(body, &declaration, sealed) {
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
