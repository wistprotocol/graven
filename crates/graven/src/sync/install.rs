use super::history::{
    default_recovery_window_days, persist_declaration, AggregatorKeys, ChainState,
};
use super::persist::{load_aggregator_keys, load_sanctions, save_chain_tips, save_sanctions};
use crate::error::{Error, Result};
use crate::fetch::resolve;
use crate::fetch::Client;
use crate::keyset::KeyHistory;
use crate::registry::{self};
use crate::replay::{save_state, ActProfile, ActReplay};
use crate::store::{CREATE_DECLARATIONS, CREATE_TIER1, CREATE_UNIQUE_INDEX};
use crate::tier1;
use reqwest::Url;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::path::PathBuf;
use wist_core::chain::ChainTips;
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::envelope::verify_envelope;
use wist_core::objects::LogAnchorEnvelope;
use wist_core::objects::{
    SnapshotIndexEnvelope, SnapshotManifestEnvelope, SnapshotStateEnvelope, StateEntry,
};
use wist_core::snapshot::content_digest;
use wist_core::snapshot::state_digest;

pub(super) struct TempFileGuard {
    path: PathBuf,
    armed: bool,
}

impl TempFileGuard {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(super) fn verify_file_integrity(
    bytes: &[u8],
    expected_sha256_hex: &str,
    expected_bytes: u64,
) -> Result<()> {
    if bytes.len() as u64 != expected_bytes {
        return Err(Error::Verify(format!(
            "byte length mismatch: expected {expected_bytes}, got {}",
            bytes.len()
        )));
    }
    if hex_encode(&Sha256::digest(bytes)) != expected_sha256_hex {
        return Err(Error::Verify("sha256 mismatch".into()));
    }
    Ok(())
}

pub(super) fn load_anchor_bytes(spec: &str, client: &Client) -> Result<Vec<u8>> {
    if let Ok(url) = Url::parse(spec) {
        if url.scheme() == "http" || url.scheme() == "https" {
            return client.get_bytes(&url);
        }
    }
    Ok(std::fs::read(spec)?)
}

pub(super) fn recompute_content_digest(sqlite_path: &Path) -> Result<String> {
    let conn = Connection::open(sqlite_path)?;
    let mut stmt =
        conn.prepare("SELECT url, publisher, delta_id, observed_at, weight FROM records")?;
    let records = stmt
        .query_map([], |row| {
            Ok(serde_json::json!({
                "url": row.get::<_, String>(0)?,
                "publisher": row.get::<_, String>(1)?,
                "delta_id": row.get::<_, String>(2)?,
                "observed_at": row.get::<_, String>(3)?,
                "weight": row.get::<_, String>(4)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<Value>>>()?;
    Ok(content_digest(&records)?)
}

pub(super) fn load_anchor(anchor: &str, client: &Client) -> Result<(PublicKey, String, String)> {
    let anchor_bytes = load_anchor_bytes(anchor, client)?;
    let anchor_value = wist_core::json::parse(&anchor_bytes)?;
    let anchor_env: LogAnchorEnvelope = serde_json::from_value(anchor_value.clone())?;
    let trust_key = PublicKey::from_b64u(&anchor_env.anchor.genesis_key.public_key)?;
    verify_envelope(&anchor_value, "anchor", &trust_key)?;
    Ok((
        trust_key,
        anchor_env.anchor.log_id,
        anchor_env.anchor.genesis_key.key_id,
    ))
}

/// A verified Snapshot installed into a temporary index with the state
/// its tuples carry adopted (WIST-3 §8 steps 1–10), before any Block
/// above `log_position` has been walked.
pub(super) struct Installation {
    guard: TempFileGuard,
    tmp_sqlite_path: PathBuf,
    pub(super) conn: Connection,
    pub(super) log_position: u64,
    pub(super) anchor_block_hash: String,
    pub(super) content_digest: String,
    pub(super) history: KeyHistory,
    pub(super) replay: ActReplay,
    pub(super) aggregator_keys: AggregatorKeys,
    pub(super) chain: ChainState,
}

/// What the sync record needs from an installation after its index is in
/// place.
pub(super) struct Committed {
    pub(super) log_position: u64,
    pub(super) content_digest: String,
    pub(super) chain: ChainState,
}

impl Installation {
    /// Moves the verified index into place once the walk above the
    /// anchor has been applied to it.
    pub(super) fn commit(self, dir: &Path) -> Result<Committed> {
        let Installation {
            mut guard,
            tmp_sqlite_path,
            conn,
            log_position,
            content_digest,
            chain,
            ..
        } = self;
        drop(conn);
        guard.disarm();
        std::fs::rename(&tmp_sqlite_path, dir.join("index.sqlite"))?;
        Ok(Committed {
            log_position,
            content_digest,
            chain,
        })
    }
}

/// Fetches the newest Snapshot, verifies its index, manifest, state and
/// files against the trust key and each other, writes the tier-0 index to
/// a temporary file and adopts every state tuple into it.
pub(super) fn snapshot(
    client: &Client,
    base: &Url,
    trust_key: &PublicKey,
    genesis_key_id: &str,
    log_id: &str,
    dir: &Path,
    tier1: bool,
) -> Result<Installation> {
    let index_url = resolve(base, "/snapshots/index.json")?;
    let (_, index_value) = client.get_json(&index_url)?;
    verify_envelope(&index_value, "index", trust_key)?;
    let index_env: SnapshotIndexEnvelope = serde_json::from_value(index_value)?;
    let newest = index_env
        .index
        .snapshots
        .into_iter()
        .next()
        .ok_or_else(|| Error::Verify("snapshot index is empty".into()))?;

    let manifest_url = resolve(base, &newest.manifest_url)?;
    let (_, manifest_value) = client.get_json(&manifest_url)?;
    verify_envelope(&manifest_value, "manifest", trust_key)?;
    let manifest_env: SnapshotManifestEnvelope = serde_json::from_value(manifest_value)?;
    let manifest = manifest_env.manifest;
    // WIST-3 §8 step 2: the index entry and the manifest are two
    // independently signed statements about the same Snapshot, so they
    // must agree before either is trusted.
    for (field, from_index, from_manifest) in [
        (
            "snapshot_date",
            &newest.snapshot_date,
            &manifest.snapshot_date,
        ),
        (
            "content_digest",
            &newest.content_digest,
            &manifest.content_digest,
        ),
    ] {
        if from_index != from_manifest {
            return Err(Error::Verify(format!(
                "WIST3-E04: snapshot index names {field} {from_index}, its manifest {from_manifest}"
            )));
        }
    }
    if newest.log_position != manifest.log_position {
        return Err(Error::Verify(format!(
            "WIST3-E04: snapshot index names log_position {}, its manifest {}",
            newest.log_position, manifest.log_position
        )));
    }
    let snapshot_base = format!("/snapshots/{}/", manifest.snapshot_date);

    let state_url = resolve(base, &format!("{snapshot_base}{}", manifest.state.path))?;
    let state_bytes = client.get_bytes(&state_url)?;
    verify_file_integrity(&state_bytes, &manifest.state.sha256, manifest.state.bytes)?;
    let state_value = wist_core::json::parse(&state_bytes)?;
    verify_envelope(&state_value, "state", trust_key)?;
    let state_env: SnapshotStateEnvelope = serde_json::from_value(state_value)?;
    let state_entry_values: Vec<Value> = state_env
        .state
        .entries
        .iter()
        .map(serde_json::to_value)
        .collect::<serde_json::Result<_>>()?;
    let recomputed_state_digest = state_digest(&state_entry_values)?;
    if recomputed_state_digest != manifest.state.state_digest {
        return Err(Error::Verify(
            "state_digest mismatch: recomputed state digest does not match manifest".into(),
        ));
    }

    let mut tier0_bytes: Option<Vec<u8>> = None;
    let mut tier1_extracts: Vec<Vec<u8>> = Vec::new();
    let mut tier1_links: Vec<Vec<u8>> = Vec::new();
    for f in &manifest.files {
        let file_url = resolve(base, &format!("{snapshot_base}{}", f.path))?;
        let bytes = client.get_bytes(&file_url)?;
        verify_file_integrity(&bytes, &f.sha256, f.bytes)?;
        if f.tier == 0 && f.path == "tier0/index.sqlite" {
            tier0_bytes = Some(bytes);
        } else if tier1 && f.path.ends_with("tier1/extracts.parquet") {
            tier1_extracts.push(bytes);
        } else if tier1 && f.path.ends_with("tier1/links.parquet") {
            tier1_links.push(bytes);
        }
    }
    let tier0_bytes = tier0_bytes
        .ok_or_else(|| Error::Verify("manifest has no tier0/index.sqlite file".into()))?;

    let tmp_sqlite_path = dir.join("index.sqlite.verifying");
    std::fs::write(&tmp_sqlite_path, &tier0_bytes)?;
    let guard = TempFileGuard::new(tmp_sqlite_path.clone());

    let recomputed_content_digest = recompute_content_digest(&tmp_sqlite_path)?;
    if recomputed_content_digest != manifest.content_digest {
        return Err(Error::Verify(
            "content_digest mismatch: recomputed tier0 digest does not match manifest".into(),
        ));
    }

    let conn = Connection::open(&tmp_sqlite_path)?;
    conn.execute(CREATE_UNIQUE_INDEX, [])?;
    conn.execute(CREATE_DECLARATIONS, [])?;

    if tier1 {
        conn.execute_batch(CREATE_TIER1)?;
        for bytes in &tier1_extracts {
            tier1::import_extracts(&conn, bytes)?;
        }
        for bytes in &tier1_links {
            tier1::import_links(&conn, bytes)?;
        }
    }

    // WIST-3 §8 step 10: adopt the state the Snapshot carries. Without
    // the chain tips, the first Delta continuing a chain the Snapshot
    // already holds reads as a fork; without the recovery windows, an
    // in-window rotation by a thief is invisible.
    let mut history = KeyHistory::new();
    let mut replay = ActReplay::new(log_id);
    conn.execute_batch(crate::store::CREATE_CHAIN_TIPS)?;
    let mut tips = ChainTips::new();
    let mut adopted_keys: Vec<(String, String, Option<u64>)> = Vec::new();
    let mut adopted_sanctions: Vec<(String, u64)> = Vec::new();
    let mut adopted_exclusions: Vec<(String, String, u64)> = Vec::new();
    let mut adopted_windows: Vec<(String, String, Value, u64)> = Vec::new();
    let mut adopted_parameters: Vec<(String, String, i64)> = Vec::new();
    conn.execute_batch(crate::store::CREATE_ADOPTED_STATE)?;
    for entry in &state_env.state.entries {
        match entry {
            StateEntry::Parameter(p) => {
                adopted_parameters.push((p.name.clone(), p.effective_at.clone(), p.value));
            }
            StateEntry::Declaration(d) => {
                history.adopt_domain(
                    &d.domain,
                    &d.declaration,
                    d.sealing_height,
                    d.highest_accepted_seq,
                )?;
                persist_declaration(
                    &conn,
                    d.sealing_height,
                    "",
                    true,
                    default_recovery_window_days(),
                    &d.declaration,
                )?;
            }
            StateEntry::RecoveryWindow(w) => {
                adopted_windows.push((
                    w.domain.clone(),
                    w.window_end.clone(),
                    w.head.clone(),
                    w.head_height,
                ));
            }
            StateEntry::Auditor(a) => {
                replay.adopt_auditor(
                    &a.auditor_id,
                    &a.key_id,
                    &a.public_key,
                    a.removed_height.is_none(),
                );
                conn.execute(
                    "INSERT OR REPLACE INTO auditors(auditor_id, key_id, public_key, admitted_height, removed_height) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (
                        &a.auditor_id,
                        &a.key_id,
                        &a.public_key,
                        a.admitted_height as i64,
                        a.removed_height.map(|h| h as i64),
                    ),
                )?;
            }
            StateEntry::Observer(o) => {
                replay.adopt_observer(
                    &o.observer_id,
                    &o.key_id,
                    &o.public_key,
                    o.registered_height,
                    o.ended_height.is_none(),
                );
                conn.execute(
                    "INSERT OR REPLACE INTO observers(observer_id, key_id, public_key, registered_height, ended_height) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (
                        &o.observer_id,
                        &o.key_id,
                        &o.public_key,
                        o.registered_height as i64,
                        o.ended_height.map(|h| h as i64),
                    ),
                )?;
            }
            StateEntry::CanaryCommitment(c) => {
                replay.adopt_commitment(
                    &c.update_id,
                    &c.planter,
                    &c.root,
                    c.leaves,
                    c.sealing_height,
                );
                conn.execute(
                    "INSERT OR REPLACE INTO canary_commitments(update_id, planter, root, leaves, sealing_height) VALUES (?1, ?2, ?3, ?4, ?5)",
                    (
                        &c.update_id,
                        &c.planter,
                        &c.root,
                        c.leaves as i64,
                        c.sealing_height as i64,
                    ),
                )?;
            }
            StateEntry::Escalation(e) => {
                conn.execute(
                    "INSERT OR REPLACE INTO escalations(domain, establishing_sealed_at) VALUES (?1, ?2)",
                    (&e.domain, &e.establishing_sealed_at),
                )?;
            }
            StateEntry::CoverageFailure(f) => {
                conn.execute(
                    "INSERT OR REPLACE INTO coverage_failures(auditor_id, block_number) VALUES (?1, ?2)",
                    (&f.auditor_id, f.block_number as i64),
                )?;
            }
            StateEntry::ReputationInputs(r) => {
                conn.execute(
                    "INSERT OR REPLACE INTO reputation_inputs(domain, first_accepted_sealed_at, reset_height, counted_total, counted_json, penalties_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    (
                        &r.domain,
                        &r.first_accepted_sealed_at,
                        r.reset_height.map(|h| h as i64),
                        r.counted_total as i64,
                        serde_json::to_string(&r.counted_url_digests)?,
                        serde_json::to_string(&r.penalties)?,
                    ),
                )?;
            }
            StateEntry::Record(r) => tips.adopt(&r.publisher, &r.url, &r.delta_id),
            StateEntry::AggregatorKey(k) => {
                adopted_keys.push((k.key_id.clone(), k.public_key.clone(), k.removed_height));
            }
            StateEntry::SanctionState(state) => {
                adopted_sanctions.push((state.domain.clone(), state.level));
            }
            StateEntry::Exclusion(e) => {
                adopted_exclusions.push((
                    e.publisher.clone(),
                    e.url.clone(),
                    e.excluded_since_height,
                ));
            }
        }
    }
    for (domain, window_end, head, head_height) in &adopted_windows {
        history.adopt_window(domain, window_end, head, *head_height)?;
    }
    history.seed_head(manifest.log_position, &manifest.anchor_block_hash);
    replay.seed_head(
        manifest.log_position,
        &manifest.anchor_block_hash,
        ActProfile::default(),
    )?;
    save_state(&conn, &replay)?;
    for (_, _, head, head_height) in &adopted_windows {
        persist_declaration(
            &conn,
            *head_height,
            "",
            true,
            default_recovery_window_days(),
            head,
        )?;
    }
    save_chain_tips(&conn, &tips)?;
    let mut ledger = load_sanctions(&conn)?;
    for (domain, level) in &adopted_sanctions {
        let entry = ledger.domains.entry(domain.clone()).or_default();
        entry.level = (*level).clamp(0, 4) as u8;
    }
    for (publisher, url, since) in &adopted_exclusions {
        ledger
            .exclusions
            .insert((publisher.clone(), url.clone()), *since);
    }
    save_sanctions(&conn, &ledger)?;

    let mut aggregator_keys = load_aggregator_keys(&conn, genesis_key_id, trust_key)?;
    for (key_id, public_key, removed_height) in &adopted_keys {
        aggregator_keys.admit(key_id, public_key, removed_height.is_some())?;
    }
    let chain = ChainState::from_tuples(&adopted_parameters)?;
    Ok(Installation {
        guard,
        tmp_sqlite_path,
        conn,
        log_position: manifest.log_position,
        anchor_block_hash: manifest.anchor_block_hash.clone(),
        content_digest: manifest.content_digest.clone(),
        history,
        replay,
        aggregator_keys,
        chain,
    })
}

pub(super) fn migrate_legacy_layout(dir: &Path, log_id: &str) -> Result<bool> {
    if !registry::is_unmigrated_legacy_layout(dir) {
        return Ok(false);
    }
    let target_dir = registry::log_dir(dir, log_id);
    std::fs::create_dir_all(&target_dir)?;

    let index_src = dir.join("index.sqlite");
    let index_dst = target_dir.join("index.sqlite");
    std::fs::rename(&index_src, &index_dst)?;

    let sync_src = dir.join("sync.json");
    let sync_dst = target_dir.join("sync.json");
    if let Err(err) = std::fs::rename(&sync_src, &sync_dst) {
        if let Err(undo_err) = std::fs::rename(&index_dst, &index_src) {
            return Err(Error::Verify(format!(
                "legacy migration failed moving {} into {} ({err}); additionally, could not move {} back to {} ({undo_err}); index.sqlite is stranded at {}",
                sync_src.display(),
                sync_dst.display(),
                index_dst.display(),
                index_src.display(),
                index_dst.display()
            )));
        }
        return Err(Error::Verify(format!(
            "legacy migration failed moving {} into {}: {err}",
            sync_src.display(),
            sync_dst.display()
        )));
    }
    Ok(true)
}

pub(super) fn rollback_migration(dir: &Path, log_id: &str) -> Result<()> {
    let target_dir = registry::log_dir(dir, log_id);
    let index_src = target_dir.join("index.sqlite");
    let index_dst = dir.join("index.sqlite");
    let sync_src = target_dir.join("sync.json");
    let sync_dst = dir.join("sync.json");

    if let Err(err) = std::fs::rename(&index_src, &index_dst) {
        return Err(Error::Verify(format!(
            "rollback of legacy migration failed: could not move {} back to {}: {err}; both files remain in {}",
            index_src.display(),
            index_dst.display(),
            target_dir.display()
        )));
    }
    if let Err(err) = std::fs::rename(&sync_src, &sync_dst) {
        return Err(Error::Verify(format!(
            "rollback of legacy migration failed: index.sqlite was restored to {} but could not move {} back to {}: {err}; sync.json remains in {}",
            dir.display(),
            sync_src.display(),
            sync_dst.display(),
            target_dir.display()
        )));
    }

    std::fs::remove_dir_all(&target_dir).map_err(|err| {
        Error::Verify(format!(
            "rollback of legacy migration restored both files to {} but could not remove {}: {err}",
            dir.display(),
            target_dir.display()
        ))
    })?;
    std::fs::remove_file(dir.join("logs.json")).map_err(|err| {
        Error::Verify(format!(
            "rollback of legacy migration restored both files to {} but could not remove {}: {err}",
            dir.display(),
            dir.join("logs.json").display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn migrate_legacy_layout_is_noop_when_not_legacy() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!migrate_legacy_layout(dir.path(), "log-a").unwrap());
    }

    #[test]
    fn migrate_legacy_layout_moves_both_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.sqlite"), b"idx").unwrap();
        std::fs::write(dir.path().join("sync.json"), b"sync").unwrap();

        assert!(migrate_legacy_layout(dir.path(), "log-a").unwrap());

        let target = registry::log_dir(dir.path(), "log-a");
        assert_eq!(std::fs::read(target.join("index.sqlite")).unwrap(), b"idx");
        assert_eq!(std::fs::read(target.join("sync.json")).unwrap(), b"sync");
        assert!(!dir.path().join("index.sqlite").exists());
        assert!(!dir.path().join("sync.json").exists());
    }

    #[test]
    fn migrate_legacy_layout_restores_first_file_when_second_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.sqlite"), b"idx").unwrap();
        std::fs::write(dir.path().join("sync.json"), b"sync").unwrap();

        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(target.join("sync.json")).unwrap();

        let err = migrate_legacy_layout(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("sync.json"), "error was: {err}");

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite must be restored to the top level, not stranded in target_dir"
        );
        assert!(!target.join("index.sqlite").exists());
        assert_eq!(
            std::fs::read(dir.path().join("sync.json")).unwrap(),
            b"sync"
        );
    }

    #[test]
    fn rollback_migration_moves_files_back_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        rollback_migration(dir.path(), "log-a").unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx"
        );
        assert_eq!(
            std::fs::read(dir.path().join("sync.json")).unwrap(),
            b"sync"
        );
        assert!(!target.exists());
        assert!(!dir.path().join("logs.json").exists());
    }

    #[test]
    fn rollback_migration_leaves_target_dir_intact_when_first_rename_back_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        std::fs::create_dir_all(dir.path().join("index.sqlite")).unwrap();

        let err = rollback_migration(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("index.sqlite"), "error was: {err}");

        assert_eq!(
            std::fs::read(target.join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite must still be in target_dir, not deleted by a premature remove_dir_all"
        );
        assert_eq!(std::fs::read(target.join("sync.json")).unwrap(), b"sync");
        assert!(
            target.exists(),
            "target_dir must not be removed while rollback is incomplete"
        );
        assert!(dir.path().join("logs.json").exists());
    }

    #[test]
    fn rollback_migration_preserves_sync_json_when_second_rename_back_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        std::fs::create_dir_all(dir.path().join("sync.json")).unwrap();

        let err = rollback_migration(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("sync.json"), "error was: {err}");

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite rename-back had already succeeded and must not be undone"
        );
        assert_eq!(
            std::fs::read(target.join("sync.json")).unwrap(),
            b"sync",
            "sync.json must still be in target_dir, not deleted by a premature remove_dir_all"
        );
        assert!(
            target.exists(),
            "target_dir must not be removed while rollback is incomplete"
        );
        assert!(dir.path().join("logs.json").exists());
    }
}
