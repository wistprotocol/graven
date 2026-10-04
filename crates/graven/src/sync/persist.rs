use super::history::ChainState;
use super::SyncState;
use crate::error::{Error, Result};
use crate::keyset::KeyHistory;
use rusqlite::{Connection, OptionalExtension};
use wist_core::aggregator_keys::Registry;
use wist_core::checkpoint::Checkpoint;
use wist_core::item::Kind;
use wist_core::objects::{AggregatorKeyEntry, Anchor, StateEntry};
use wist_core::parameters::Amendment;
use wist_core::sealing::Replay;

/// WIST-3 §3.4 and §7: re-authenticated from the Anchor at `at` as a state file's tuples are, so a
/// reload never restores a retired key.
pub(super) fn load_aggregator_keys(
    conn: &Connection,
    anchor: &Anchor,
    at: u64,
) -> Result<Registry> {
    conn.execute_batch(crate::store::CREATE_AGGREGATOR_KEYS)?;
    let mut stmt = conn.prepare(
        "SELECT key_id, public_key, added_height, removed_height, adding_act, removing_act FROM aggregator_keys",
    )?;
    let entries = stmt
        .query_map([], |row| {
            Ok(AggregatorKeyEntry {
                key_id: row.get(0)?,
                public_key: row.get(1)?,
                added_height: row.get::<_, i64>(2)?.max(0) as u64,
                removed_height: row
                    .get::<_, Option<i64>>(3)?
                    .map(|height| height.max(0) as u64),
                adding_act: row.get::<_, Option<String>>(4)?.map(act_value),
                removing_act: row.get::<_, Option<String>>(5)?.map(act_value),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if entries.is_empty() {
        return Ok(Registry::from_genesis(&anchor.log_id, &anchor.genesis_key)?);
    }
    Registry::from_state_tuples(anchor, at, &entries).map_err(|error| {
        Error::Verify(format!(
            "the store's Aggregator key registry does not authenticate from the Anchor's genesis key ({error}); remove the log's directory and follow the Log again"
        ))
    })
}

/// A row that is not JSON yields a value §7's rules refuse, never an absent act.
fn act_value(text: String) -> serde_json::Value {
    serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
}

pub(super) fn save_aggregator_keys(conn: &Connection, keys: &Registry) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_AGGREGATOR_KEYS)?;
    for entry in keys.entries() {
        let act_text = |act: &Option<serde_json::Value>| -> Result<Option<String>> {
            act.as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(Error::from)
        };
        conn.execute(
            "INSERT INTO aggregator_keys(key_id, public_key, added_height, removed_height, adding_act, removing_act) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(key_id) DO UPDATE SET public_key = excluded.public_key, added_height = excluded.added_height, removed_height = excluded.removed_height, adding_act = excluded.adding_act, removing_act = excluded.removing_act",
            (
                &entry.key_id,
                &entry.public_key,
                entry.added_height as i64,
                entry.removed_height.map(|height| height as i64),
                act_text(&entry.adding_act)?,
                act_text(&entry.removing_act)?,
            ),
        )?;
    }
    Ok(())
}

pub(super) fn save_parameters(conn: &Connection, chain: &ChainState) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_PARAMETERS)?;
    conn.execute("DELETE FROM parameters", [])?;
    for a in chain.accepted() {
        conn.execute(
            "INSERT INTO parameters(parameter, value, epoch_number, entry_index, sealed_at_s, effective_at_s) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                &a.parameter,
                a.value,
                a.epoch_number as i64,
                a.entry_index as i64,
                a.sealed_at_s,
                a.effective_at_s,
            ),
        )?;
    }
    Ok(())
}

pub(super) fn load_parameters(conn: &Connection) -> Result<Vec<Amendment>> {
    conn.execute_batch(crate::store::CREATE_PARAMETERS)?;
    let mut stmt = conn.prepare(
        "SELECT parameter, value, epoch_number, entry_index, sealed_at_s, effective_at_s FROM parameters ORDER BY epoch_number, entry_index",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Amendment {
            parameter: r.get(0)?,
            value: r.get(1)?,
            epoch_number: r.get::<_, i64>(2)? as u64,
            entry_index: r.get::<_, i64>(3)? as u64,
            sealed_at_s: r.get(4)?,
            effective_at_s: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn load_history(conn: &Connection) -> Result<KeyHistory> {
    conn.execute_batch(CREATE_DECLARATION_STATE)?;
    let state: Option<String> = conn
        .query_row(
            "SELECT state FROM declaration_state WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match state {
        Some(state) => KeyHistory::from_state(&state),
        None => Err(Error::Verify(
            "the store carries no Declaration state; run a cold start".into(),
        )),
    }
}

pub(super) fn record_withdrawal(
    conn: &Connection,
    item_id: &str,
    publisher: &str,
    height: u64,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_WITHDRAWALS)?;
    conn.execute(
        "INSERT OR IGNORE INTO withdrawals(item_id, publisher, height) VALUES (?1, ?2, ?3)",
        (item_id, publisher, height as i64),
    )?;
    Ok(())
}

pub(super) fn save_state_tuples(conn: &Connection, tuples: &[StateEntry]) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_STATE_TUPLES)?;
    conn.execute("DELETE FROM state_tuples", [])?;
    for (seq, tuple) in tuples.iter().enumerate() {
        conn.execute(
            "INSERT INTO state_tuples(seq, tuple) VALUES (?1, ?2)",
            (seq as i64, serde_json::to_string(tuple)?),
        )?;
    }
    Ok(())
}

pub(super) fn load_state_tuples(conn: &Connection) -> Result<Vec<StateEntry>> {
    conn.execute_batch(crate::store::CREATE_STATE_TUPLES)?;
    let mut stmt = conn.prepare("SELECT tuple FROM state_tuples ORDER BY seq")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.iter()
        .map(|text| {
            wist_core::json::validate(text.as_bytes())?;
            Ok(serde_json::from_str(text)?)
        })
        .collect()
}

fn held_labels(conn: &Connection) -> Result<Vec<(String, Option<String>)>> {
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    conn.execute_batch(crate::store::CREATE_SEALED_LABEL_IDS)?;
    let mut stmt = conn.prepare(
        "SELECT label_id, subject FROM sealed_label_ids
         UNION SELECT label_id, subject FROM labels
         UNION SELECT label_id, subject FROM label_current WHERE label_id IS NOT NULL",
    )?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Page => "page",
        Kind::Removed => "removed",
    }
}

fn held_items(conn: &Connection) -> Result<Vec<(String, String, Kind, u64)>> {
    conn.execute_batch(crate::store::CREATE_SEALED_ITEMS)?;
    let mut stmt = conn.prepare("SELECT item_id, publisher, kind, height FROM sealed_items")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(item_id, publisher, kind, height)| {
            let kind = match kind.as_str() {
                "page" => Kind::Page,
                "removed" => Kind::Removed,
                other => {
                    return Err(Error::Verify(format!(
                        "the store records a sealed Item of kind {other:?}"
                    )))
                }
            };
            Ok((item_id, publisher, kind, height.max(0) as u64))
        })
        .collect()
}

pub(super) fn record_sealed(
    conn: &Connection,
    label_ids: &[(String, Option<String>)],
    items: &[(String, String, Kind, u64)],
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_SEALED_LABEL_IDS)?;
    conn.execute_batch(crate::store::CREATE_SEALED_ITEMS)?;
    for (label_id, subject) in label_ids {
        conn.execute(
            "INSERT OR IGNORE INTO sealed_label_ids(label_id, subject) VALUES (?1, ?2)",
            (label_id, subject),
        )?;
    }
    for (item_id, publisher, kind, height) in items {
        conn.execute(
            "INSERT INTO sealed_items(item_id, publisher, kind, height) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(item_id, publisher, kind) DO UPDATE SET height = MIN(height, excluded.height)",
            (item_id, publisher, kind_name(*kind), *height as i64),
        )?;
    }
    Ok(())
}

/// WIST-4 §5.1: the `record`, `removal` and `withdrawal` tuples of the installed Snapshot show their
/// Items sealed at or below its Epoch.
pub(super) fn record_snapshot_sightings(
    conn: &Connection,
    epoch_number: u64,
    tuples: &[StateEntry],
) -> Result<()> {
    let sealed = wist_core::withdrawal::SealedItems::from_state(epoch_number, tuples)?;
    let items: Vec<(String, String, Kind, u64)> = sealed
        .sealed()
        .map(|item| {
            (
                item.item_id.to_owned(),
                item.publisher.to_owned(),
                item.kind,
                item.height,
            )
        })
        .collect();
    record_sealed(conn, &[], &items)
}

pub(super) fn earliest_sighting(
    conn: &Connection,
    item_id: &str,
    publisher: &str,
) -> Result<Option<u64>> {
    conn.execute_batch(crate::store::CREATE_SEALED_ITEMS)?;
    let height: Option<i64> = conn.query_row(
        "SELECT MIN(height) FROM sealed_items WHERE item_id = ?1 AND publisher = ?2 AND kind = 'page'",
        (item_id, publisher),
        |row| row.get(0),
    )?;
    Ok(height.map(|height| height.max(0) as u64))
}

/// WIST-3 §7: the index's Label and Item rows stand in for what no state tuple carries.
pub(super) fn load_replay(
    conn: &Connection,
    head: &Checkpoint,
    walk_floor: Option<u64>,
) -> Result<Replay> {
    let history = load_history(conn)?;
    let tuples = load_state_tuples(conn)?;
    let mut replay = Replay::resumed(
        head.epoch_number(),
        head.sealed_at(),
        history.declarations().clone(),
        &tuples,
    )
    .map_err(|error| {
        Error::Verify(format!(
            "the store's publication state does not resume at epoch {}: {error}",
            head.epoch_number()
        ))
    })?;
    replay.hold_walk_floor(walk_floor);
    for (label_id, subject) in held_labels(conn)? {
        replay.hold_sealed_label(&label_id, subject.as_deref());
    }
    for (item_id, publisher, kind, height) in held_items(conn)? {
        replay.hold_sealed_item(&item_id, &publisher, kind, height);
    }
    Ok(replay)
}

pub const CREATE_DECLARATION_STATE: &str = "CREATE TABLE IF NOT EXISTS declaration_state(id INTEGER PRIMARY KEY CHECK(id = 1), state TEXT NOT NULL)";

pub(super) fn save_history(conn: &Connection, history: &KeyHistory) -> Result<()> {
    conn.execute_batch(CREATE_DECLARATION_STATE)?;
    conn.execute(
        "INSERT INTO declaration_state(id, state) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET state = excluded.state",
        [history.state()?],
    )?;
    Ok(())
}

/// Committed in the same transaction as the index rows it describes.
pub const CREATE_SYNC_STATE: &str = "CREATE TABLE IF NOT EXISTS sync_state(id INTEGER PRIMARY KEY CHECK(id = 1), state TEXT NOT NULL)";

/// Reinterpreting an older format would place the verified head at a tree never verified, or keep a
/// registry never chained to the Anchor.
pub fn read_sync_state(bytes: &[u8]) -> Result<SyncState> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let format = value.get("format").and_then(serde_json::Value::as_u64);
    if format != Some(u64::from(super::SYNC_STATE_FORMAT)) {
        return Err(Error::Verify(
            "the stored sync state is in a superseded format, from before the Log became one growing tree, from before its fields were renamed to epoch_number/tree_size, from before the Aggregator key registry carried each key's accepted acts, from before records were keyed by Item ID, or from before link rows and Item sightings were kept per Item; remove the log's directory and follow the Log again".into(),
        ));
    }
    Ok(serde_json::from_value(value)?)
}

pub fn load_sync_state(conn: &Connection) -> Result<Option<SyncState>> {
    if !crate::store::table_exists(conn, "sync_state")? {
        return Ok(None);
    }
    let state: Option<String> = conn
        .query_row("SELECT state FROM sync_state WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?;
    state
        .map(|state| {
            wist_core::json::validate(state.as_bytes())?;
            read_sync_state(state.as_bytes())
        })
        .transpose()
}

pub fn save_sync_state(conn: &Connection, state: &SyncState) -> Result<()> {
    conn.execute_batch(CREATE_SYNC_STATE)?;
    conn.execute(
        "INSERT INTO sync_state(id, state) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET state = excluded.state",
        [serde_json::to_string(state)?],
    )?;
    Ok(())
}

/// WIST-2 §3.3.
pub(super) fn record_label(
    conn: &Connection,
    label: &wist_core::objects::Label,
    label_id: &str,
    height: u64,
    entry_index: u64,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    let retracted = label.retracted == Some(true);
    conn.execute(
        "INSERT OR IGNORE INTO labels(label_id, labeler, subject, name, value, asserted_at, retracted, expires_at, delta, height, entry_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            label_id,
            label.labeler,
            label.subject,
            label.name,
            label.value,
            label.asserted_at,
            retracted,
            label.expires_at,
            label.delta,
            height as i64,
            entry_index as i64
        ],
    )?;
    let current: Option<(String, i64, i64)> = conn
        .query_row(
            "SELECT asserted_at, height, entry_index FROM label_current WHERE labeler = ?1 AND subject = ?2 AND name = ?3",
            (&label.labeler, &label.subject, &label.name),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if supersedes(current, &label.asserted_at, height, entry_index) {
        conn.execute(
            "INSERT INTO label_current(labeler, subject, name, label_id, value, asserted_at, retracted, expires_at, delta, height, entry_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(labeler, subject, name) DO UPDATE SET label_id = excluded.label_id, value = excluded.value, asserted_at = excluded.asserted_at, retracted = excluded.retracted, expires_at = excluded.expires_at, delta = excluded.delta, height = excluded.height, entry_index = excluded.entry_index",
            rusqlite::params![
                label.labeler,
                label.subject,
                label.name,
                label_id,
                label.value,
                label.asserted_at,
                retracted,
                label.expires_at,
                label.delta,
                height as i64,
                entry_index as i64
            ],
        )?;
    }
    conn.execute(
        "INSERT INTO labelers(labeler, label_count, retraction_count, first_seen_height, last_sealed_height) VALUES (?1, 1, ?2, ?3, ?3)
         ON CONFLICT(labeler) DO UPDATE SET label_count = label_count + 1, retraction_count = retraction_count + ?2, first_seen_height = MIN(first_seen_height, ?3), last_sealed_height = MAX(last_sealed_height, ?3)",
        rusqlite::params![label.labeler, i64::from(retracted), height as i64],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO labeler_subjects(labeler, subject) VALUES (?1, ?2)",
        (&label.labeler, &label.subject),
    )?;
    Ok(())
}

/// WIST-2 §3.3: the greater asserted_at, then the later Log position.
fn supersedes(
    current: Option<(String, i64, i64)>,
    asserted_at: &str,
    height: u64,
    entry_index: u64,
) -> bool {
    match current {
        None => true,
        Some((held_at, held_height, held_index)) => {
            wist_core::publisher_time::compare(asserted_at, &held_at)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then((height as i64).cmp(&held_height))
                .then((entry_index as i64).cmp(&held_index))
                == std::cmp::Ordering::Greater
        }
    }
}

/// WIST-2 §3.3.
pub(super) fn record_dispute(
    conn: &Connection,
    dispute: &wist_core::objects::Dispute,
    dispute_id: &str,
    height: u64,
    entry_index: u64,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    conn.execute(
        "INSERT OR IGNORE INTO disputes(dispute_id, label_id, disputant, reason, asserted_at, height, entry_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            dispute_id,
            dispute.label,
            dispute.disputant,
            dispute.reason,
            dispute.asserted_at,
            height as i64,
            entry_index as i64
        ],
    )?;
    let current: Option<(String, i64, i64)> = conn
        .query_row(
            "SELECT asserted_at, height, entry_index FROM dispute_current WHERE label_id = ?1 AND disputant = ?2",
            (&dispute.label, &dispute.disputant),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if supersedes(current, &dispute.asserted_at, height, entry_index) {
        conn.execute(
            "INSERT INTO dispute_current(label_id, disputant, dispute_id, reason, asserted_at, height, entry_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(label_id, disputant) DO UPDATE SET dispute_id = excluded.dispute_id, reason = excluded.reason, asserted_at = excluded.asserted_at, height = excluded.height, entry_index = excluded.entry_index",
            rusqlite::params![
                dispute.label,
                dispute.disputant,
                dispute_id,
                dispute.reason,
                dispute.asserted_at,
                height as i64,
                entry_index as i64
            ],
        )?;
    }
    touch_labeler(conn, &dispute.disputant, height)
}

/// WIST-4 §6.
pub(super) fn touch_labeler(conn: &Connection, domain: &str, height: u64) -> Result<()> {
    if !crate::store::table_exists(conn, "labelers")? {
        return Ok(());
    }
    conn.execute(
        "UPDATE labelers SET last_sealed_height = MAX(last_sealed_height, ?2) WHERE labeler = ?1",
        rusqlite::params![domain, height as i64],
    )?;
    Ok(())
}

/// WIST-3 §8 step 10 and §7: a resumed index holds only first and last adopted tuple heights, none
/// of them a real count.
pub(super) fn adopt_label_tuple(
    conn: &Connection,
    entry: &wist_core::objects::LabelEntry,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    conn.execute(
        "INSERT INTO label_current(labeler, subject, name, label_id, value, asserted_at, retracted, expires_at, delta, height, entry_index) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, 0)
         ON CONFLICT(labeler, subject, name) DO UPDATE SET label_id = excluded.label_id, value = excluded.value, asserted_at = excluded.asserted_at, retracted = 0, expires_at = excluded.expires_at, delta = excluded.delta, height = excluded.height, entry_index = 0",
        rusqlite::params![
            entry.labeler,
            entry.subject,
            entry.name,
            entry.label_id,
            entry.value.map(|v| v as i64),
            entry.asserted_at,
            entry.expires_at,
            entry.delta,
            entry.sealing_height as i64
        ],
    )?;
    let (first, last): (i64, i64) = conn.query_row(
        "SELECT MIN(height), MAX(height) FROM label_current WHERE labeler = ?1",
        [&entry.labeler],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    conn.execute(
        "INSERT INTO labelers(labeler, label_count, retraction_count, first_seen_height, last_sealed_height, adopted) VALUES (?1, 0, 0, ?2, ?3, 1)
         ON CONFLICT(labeler) DO UPDATE SET first_seen_height = excluded.first_seen_height, last_sealed_height = excluded.last_sealed_height, adopted = 1",
        rusqlite::params![entry.labeler, first, last],
    )?;
    Ok(())
}

/// WIST-3 §8 step 10.
pub(super) fn adopt_dispute_tuple(
    conn: &Connection,
    entry: &wist_core::objects::DisputeEntry,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_LABELS)?;
    conn.execute(
        "INSERT INTO dispute_current(label_id, disputant, dispute_id, reason, asserted_at, height, entry_index) VALUES (?1, ?2, NULL, ?3, ?4, ?5, 0)
         ON CONFLICT(label_id, disputant) DO UPDATE SET dispute_id = NULL, reason = excluded.reason, asserted_at = excluded.asserted_at, height = excluded.height, entry_index = 0",
        rusqlite::params![
            entry.label_id,
            entry.disputant,
            entry.reason,
            entry.asserted_at,
            entry.sealing_height as i64
        ],
    )?;
    Ok(())
}

/// WIST-2 §3.3 and WIST-4 §6: the newest definition that verifies wins; a name with none reads as
/// `inform`.
pub(super) fn fetch_definitions(
    conn: &Connection,
    client: &crate::fetch::Client,
    history: &crate::keyset::KeyHistory,
    subscriptions: &std::collections::BTreeSet<String>,
) -> Result<()> {
    if subscriptions.is_empty() || !crate::store::table_exists(conn, "label_current")? {
        return Ok(());
    }
    let mut stmt = conn.prepare("SELECT DISTINCT labeler, name FROM label_current")?;
    let names = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (labeler, name) in names {
        if !subscriptions.contains(&labeler) {
            continue;
        }
        let Some(declaration) = history.declaration_for(&labeler) else {
            continue;
        };
        let scheme = if client.allow_http() && crate::fetch::is_loopback_host(&labeler) {
            "http"
        } else {
            "https"
        };
        let url = format!(
            "{scheme}://{labeler}/.well-known/wist/{}",
            wist_core::label::definition_path(&name)
        );
        let Ok(parsed) = reqwest::Url::parse(&url) else {
            continue;
        };
        let Ok((_, doc)) = client.get_json(&parsed) else {
            continue;
        };
        let Ok(envelope) = wist_core::label::validate_definition(&doc, &declaration) else {
            continue;
        };
        let definition = envelope.definition;
        let newer = conn
            .query_row(
                "SELECT asserted_at FROM label_definitions WHERE labeler = ?1 AND name = ?2",
                (&labeler, &name),
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_none_or(|held| {
                wist_core::publisher_time::compare(&definition.asserted_at, &held)
                    == Some(std::cmp::Ordering::Greater)
            });
        if newer {
            let treatment = match definition.treatment {
                wist_core::objects::Treatment::Hide => "hide",
                wist_core::objects::Treatment::Warn => "warn",
                wist_core::objects::Treatment::Inform => "inform",
            };
            conn.execute(
                "INSERT INTO label_definitions(labeler, name, description, treatment, asserted_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(labeler, name) DO UPDATE SET description = excluded.description, treatment = excluded.treatment, asserted_at = excluded.asserted_at",
                rusqlite::params![labeler, name, definition.description, treatment, definition.asserted_at],
            )?;
        }
    }
    Ok(())
}

fn host_of(url: &str) -> String {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .map_or(url, |rest| rest.split('/').next().unwrap_or(rest))
        .to_string()
}

fn link_change(
    conn: &Connection,
    source_url: &str,
    target_url: &str,
    item_id: &str,
    height: u64,
    added: bool,
) -> Result<()> {
    conn.execute(
        "INSERT INTO link_changes(target_host, height, added, removed, source_url, target_url, item_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            host_of(target_url),
            height as i64,
            i64::from(added),
            i64::from(!added),
            source_url,
            target_url,
            item_id
        ],
    )?;
    Ok(())
}

pub(super) fn replace_inlinks(
    conn: &Connection,
    source_url: &str,
    source_host: &str,
    item_id: Option<&str>,
    targets: &[String],
    height: u64,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_RANKING)?;
    let mut stmt =
        conn.prepare("SELECT target_url, added_by FROM inlinks WHERE source_url = ?1")?;
    let previous: std::collections::BTreeMap<String, String> = stmt
        .query_map([source_url], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let current: std::collections::BTreeSet<&String> = match item_id {
        Some(_) => targets.iter().collect(),
        None => Default::default(),
    };
    for (target, added_by) in &previous {
        if !current.contains(target) {
            link_change(conn, source_url, target, added_by, height, false)?;
        }
    }
    conn.execute("DELETE FROM inlinks WHERE source_url = ?1", [source_url])?;
    let Some(item_id) = item_id else {
        return Ok(());
    };
    for target in current {
        let added_by = match previous.get(target) {
            Some(added_by) => added_by.as_str(),
            None => {
                link_change(conn, source_url, target, item_id, height, true)?;
                item_id
            }
        };
        conn.execute(
            "INSERT OR REPLACE INTO inlinks(source_url, source_host, target_url, target_host, height, item_id, added_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                source_url,
                source_host,
                target,
                host_of(target),
                height as i64,
                item_id,
                added_by
            ],
        )?;
    }
    Ok(())
}

/// WIST-3 §6.2: a withdrawn Payload's declared links are content; the link rows are left as if its
/// links had never been read.
pub(super) fn retract_links(conn: &Connection, item_id: &str) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_RANKING)?;
    let carried: Vec<(String, String, String, i64)> = conn
        .prepare("SELECT source_url, target_url, added_by, height FROM inlinks WHERE item_id = ?1")?
        .query_map([item_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (source_url, target_url, added_by, height) in &carried {
        if added_by != item_id {
            link_change(
                conn,
                source_url,
                target_url,
                added_by,
                (*height).max(0) as u64,
                false,
            )?;
        }
    }
    conn.execute("DELETE FROM inlinks WHERE item_id = ?1", [item_id])?;
    let continued: Vec<(String, String, String, i64)> = conn
        .prepare("SELECT source_url, target_url, item_id, height FROM inlinks WHERE added_by = ?1")?
        .query_map([item_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (source_url, target_url, carrier, height) in &continued {
        link_change(
            conn,
            source_url,
            target_url,
            carrier,
            (*height).max(0) as u64,
            true,
        )?;
    }
    conn.execute(
        "UPDATE inlinks SET added_by = item_id WHERE added_by = ?1",
        [item_id],
    )?;
    conn.execute("DELETE FROM link_changes WHERE item_id = ?1", [item_id])?;
    Ok(())
}

pub(super) fn seed_ranking_index(conn: &Connection, height: u64) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_RANKING)?;
    conn.execute(
        "INSERT OR IGNORE INTO record_heights(url, publisher, height) SELECT url, publisher, ?1 FROM records",
        [height as i64],
    )?;
    if crate::store::table_exists(conn, "links")? {
        let mut stmt = conn.prepare("SELECT source_url, target_url FROM links")?;
        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (source_url, target_url) in rows {
            let Some((source_host, item_id)) = conn
                .query_row(
                    "SELECT publisher, item_id FROM records WHERE url = ?1 LIMIT 1",
                    [&source_url],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
            else {
                continue;
            };
            conn.execute(
                "INSERT OR IGNORE INTO inlinks(source_url, source_host, target_url, target_host, height, item_id, added_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                rusqlite::params![source_url, source_host, target_url, host_of(&target_url), height as i64, item_id],
            )?;
        }
    }
    Ok(())
}
