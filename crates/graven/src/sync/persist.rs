use super::history::ChainState;
use super::SyncState;
use crate::error::{Error, Result};
use crate::keyset::KeyHistory;
use rusqlite::{Connection, OptionalExtension};
use wist_core::aggregator_keys::Registry;
use wist_core::chain::ChainTips;
use wist_core::objects::{AggregatorKeyEntry, Anchor};
use wist_core::parameters::Amendment;
use wist_core::withdrawal::WithdrawalReplay;

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

/// WIST-3 §6.2: a later act of the same Delta keeps the first height.
pub(super) fn load_withdrawn(conn: &Connection) -> Result<WithdrawalReplay> {
    conn.execute_batch(crate::store::CREATE_WITHDRAWALS)?;
    let mut stmt = conn.prepare("SELECT delta_id, publisher, height FROM withdrawals")?;
    let mut replay = WithdrawalReplay::new();
    for row in stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })? {
        let (delta_id, publisher, height) = row?;
        replay.adopt(&delta_id, &publisher, height.max(0) as u64);
    }
    Ok(replay)
}

pub(super) fn record_withdrawal(
    conn: &Connection,
    delta_id: &str,
    publisher: &str,
    height: u64,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_WITHDRAWALS)?;
    conn.execute(
        "INSERT OR IGNORE INTO withdrawals(delta_id, publisher, height) VALUES (?1, ?2, ?3)",
        (delta_id, publisher, height as i64),
    )?;
    Ok(())
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

pub(super) fn load_chain_tips(conn: &Connection) -> Result<ChainTips> {
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

pub(super) fn save_chain_tips(conn: &Connection, tips: &ChainTips) -> Result<()> {
    for (publisher, url, tip) in tips.tips() {
        conn.execute(
            "INSERT INTO chain_tips(publisher, url, tip) VALUES (?1, ?2, ?3)
             ON CONFLICT(publisher, url) DO UPDATE SET tip = excluded.tip",
            (publisher, url, tip),
        )?;
    }
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
            "the stored sync state is in a superseded format, from before the Log became one growing tree, from before its fields were renamed to epoch_number/tree_size, or from before the Aggregator key registry carried each key's accepted acts; remove the log's directory and follow the Log again".into(),
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

/// WIST-2 §3.3.
pub(super) fn sealed_label_subject(conn: &Connection, label_id: &str) -> Result<Option<String>> {
    if !crate::store::table_exists(conn, "labels")? {
        return Ok(None);
    }
    conn.query_row(
        "SELECT subject FROM labels WHERE label_id = ?1
         UNION ALL SELECT subject FROM label_current WHERE label_id = ?1 LIMIT 1",
        [label_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
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

pub(super) fn record_height(
    conn: &Connection,
    url: &str,
    publisher: &str,
    height: u64,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_RANKING)?;
    conn.execute(
        "INSERT INTO record_heights(url, publisher, height) VALUES (?1, ?2, ?3)
         ON CONFLICT(url, publisher) DO UPDATE SET height = excluded.height",
        (url, publisher, height as i64),
    )?;
    Ok(())
}

pub(super) fn replace_inlinks(
    conn: &Connection,
    source_url: &str,
    source_host: &str,
    targets: &[String],
    height: u64,
) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_RANKING)?;
    let mut stmt = conn.prepare("SELECT target_url FROM inlinks WHERE source_url = ?1")?;
    let previous: std::collections::BTreeSet<String> = stmt
        .query_map([source_url], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    let current: std::collections::BTreeSet<String> = targets.iter().cloned().collect();
    let mut changes: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
    for target in previous.difference(&current) {
        changes.entry(host_of(target)).or_default().1 += 1;
    }
    for target in current.difference(&previous) {
        changes.entry(host_of(target)).or_default().0 += 1;
    }
    conn.execute("DELETE FROM inlinks WHERE source_url = ?1", [source_url])?;
    for target in &current {
        conn.execute(
            "INSERT OR REPLACE INTO inlinks(source_url, source_host, target_url, target_host, height) VALUES (?1, ?2, ?3, ?4, ?5)",
            (source_url, source_host, target, host_of(target), height as i64),
        )?;
    }
    for (target_host, (added, removed)) in changes {
        conn.execute(
            "INSERT INTO link_changes(target_host, height, added, removed) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(target_host, height) DO UPDATE SET added = added + excluded.added, removed = removed + excluded.removed",
            (target_host, height as i64, added, removed),
        )?;
    }
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
            let source_host = conn
                .query_row(
                    "SELECT publisher FROM records WHERE url = ?1 LIMIT 1",
                    [&source_url],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .unwrap_or_else(|| host_of(&source_url));
            conn.execute(
                "INSERT OR IGNORE INTO inlinks(source_url, source_host, target_url, target_host, height) VALUES (?1, ?2, ?3, ?4, ?5)",
                (&source_url, source_host, &target_url, host_of(&target_url), height as i64),
            )?;
        }
    }
    Ok(())
}
