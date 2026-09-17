use super::history::{AggregatorKeys, ChainState};
use super::SyncState;
use crate::error::{Error, Result};
use crate::keyset::KeyHistory;
use rusqlite::{Connection, OptionalExtension};
use wist_core::chain::ChainTips;
use wist_core::crypto::PublicKey;
use wist_core::parameters::Amendment;
use wist_core::withdrawal::WithdrawalReplay;

pub(super) fn load_aggregator_keys(
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

pub(super) fn save_aggregator_keys(conn: &Connection, keys: &AggregatorKeys) -> Result<()> {
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

pub(super) fn save_parameters(conn: &Connection, chain: &ChainState) -> Result<()> {
    conn.execute_batch(crate::store::CREATE_PARAMETERS)?;
    conn.execute("DELETE FROM parameters", [])?;
    for a in chain.accepted() {
        conn.execute(
            "INSERT INTO parameters(parameter, value, block_number, entry_index, sealed_at_s, effective_at_s) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                &a.parameter,
                a.value,
                a.block_number as i64,
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
        "SELECT parameter, value, block_number, entry_index, sealed_at_s, effective_at_s FROM parameters ORDER BY block_number, entry_index",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Amendment {
            parameter: r.get(0)?,
            value: r.get(1)?,
            block_number: r.get::<_, i64>(2)? as u64,
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

/// WIST-3 §6.2: the withdrawals the store holds, from adopted tuples and
/// walked acts alike, as core's replay so a later act of the same Delta
/// keeps the first height.
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

/// The sync cursor and verification state, committed in the same
/// transaction as the index rows it describes.
pub const CREATE_SYNC_STATE: &str = "CREATE TABLE IF NOT EXISTS sync_state(id INTEGER PRIMARY KEY CHECK(id = 1), state TEXT NOT NULL)";

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
            Ok(serde_json::from_str(&state)?)
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
