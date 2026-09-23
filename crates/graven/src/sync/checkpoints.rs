//! WIST-3 §5.
use super::source::Sources;
use super::tree::Tree;
use crate::error::{Error, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rusqlite::{Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use wist_core::aggregator_keys::Registry;
use wist_core::checkpoint::{
    self, archive_path, check_archive_path, witness_key_id, AggregatorKey, Checkpoint, Progression,
    Verification, WitnessKey, WITNESS_KEY_TYPE,
};
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::objects::SnapshotManifest;

/// A Checkpoint is five short lines and its signature lines; the bound is
/// the Consumer's own, since WIST-3 §6 gives the file no octet bound.
pub const CHECKPOINT_MAX_BYTES: u64 = 65_536;

/// WIST-3 §5: `unwitnessed` is NULL for a Checkpoint verified but never adopted.
pub const CREATE_CHECKPOINTS: &str =
    "CREATE TABLE IF NOT EXISTS checkpoints(epoch_number INTEGER PRIMARY KEY, note TEXT NOT NULL, unwitnessed INTEGER)";

fn invalid(message: &str) -> Error {
    Error::Verify(format!("WIST3-E03 {message}"))
}

/// WIST-3 §5: the `<name>+<hex key ID>+base64(0x04 || key)` verifier-key form [signed-note] defines
/// for cosignature/v1.
pub fn parse_witness_key(encoded: &str) -> Result<WitnessKey> {
    let bad = |detail: &str| Error::Verify(format!("witness verifier key {encoded:?}: {detail}"));
    let parts: Vec<&str> = encoded.splitn(3, '+').collect();
    if parts.len() != 3 {
        return Err(bad("expected <name>+<key ID>+<key>"));
    }
    let name = parts[0];
    if name.is_empty() {
        return Err(bad("the name is empty"));
    }
    let raw = STANDARD
        .decode(parts[2])
        .map_err(|_| bad("the key is not base64"))?;
    if raw.len() != 33 || raw[0] != WITNESS_KEY_TYPE {
        return Err(bad("the key is not an Ed25519 cosignature/v1 key"));
    }
    let public_key = PublicKey::from_bytes(raw[1..].try_into().expect("32 octets"))
        .map_err(|_| bad("the key is not an Ed25519 public key"))?;
    if hex_encode(&witness_key_id(name, &public_key)) != parts[1].to_ascii_lowercase() {
        return Err(bad("the key ID is not the one the name and key derive"));
    }
    Ok(WitnessKey {
        name: name.to_owned(),
        public_key,
    })
}

pub fn parse_roster(encoded: &[String]) -> Result<Vec<WitnessKey>> {
    encoded.iter().map(|key| parse_witness_key(key)).collect()
}

fn parse_note(bytes: &[u8], path: &str) -> Result<Checkpoint> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid(&format!("the Checkpoint at {path} is not text")))?;
    Checkpoint::parse(text).map_err(Into::into)
}

pub fn head(sources: &Sources) -> Result<Checkpoint> {
    let bytes = sources.verified("/checkpoint", CHECKPOINT_MAX_BYTES, |bytes| {
        parse_note(bytes, "/checkpoint").map(|_| ())
    })?;
    parse_note(&bytes, "/checkpoint")
}

/// WIST-3 §6: rejected where `epoch_number` is not the path's number.
pub fn archived(sources: &Sources, epoch_number: u64) -> Result<Checkpoint> {
    let path = archive_path(epoch_number);
    let bytes = sources.cached(&path, CHECKPOINT_MAX_BYTES, |bytes| {
        let checkpoint = parse_note(bytes, &path)?;
        check_archive_path(&checkpoint, &path)?;
        Ok(())
    })?;
    parse_note(&bytes, &path)
}

/// WIST-3 §9 `WIST3-E03`: a bad note is its source's fault; the error stands only where no source
/// serves one that verifies.
fn archived_verified(
    sources: &Sources,
    epoch_number: u64,
    log_id: &str,
    aggregator_keys: &[AggregatorKey],
    witnesses: &[WitnessKey],
) -> Result<(Checkpoint, Verification)> {
    let path = archive_path(epoch_number);
    let verify = |bytes: &[u8]| -> Result<(Checkpoint, Verification)> {
        let checkpoint = parse_note(bytes, &path)?;
        check_archive_path(&checkpoint, &path)?;
        let verification = checkpoint::verify(&checkpoint, log_id, aggregator_keys, witnesses)?;
        Ok((checkpoint, verification))
    };
    let bytes = sources.cached(&path, CHECKPOINT_MAX_BYTES, |bytes| {
        verify(bytes).map(|_| ())
    })?;
    verify(&bytes)
}

/// WIST-3 §8 steps 4 and 5: `epoch_number` only selects the file; a manifest mismatch on the
/// verified note is divergence and is never re-fetched.
pub fn manifest_anchor(
    sources: &Sources,
    manifest: &SnapshotManifest,
    state_tree_size: u64,
    log_id: &str,
    aggregator_keys: &[AggregatorKey],
    witnesses: &[WitnessKey],
) -> Result<(Checkpoint, Verification)> {
    wist_core::snapshot::check_state_tree_size(manifest, state_tree_size)?;
    let (anchor, verification) = archived_verified(
        sources,
        manifest.epoch_number,
        log_id,
        aggregator_keys,
        witnesses,
    )?;
    wist_core::snapshot::check_manifest_anchor(manifest, &anchor)?;
    Ok((anchor, verification))
}

/// WIST-3 §3.1 at the verified head: a smaller tree's contradicting root is §5's third Equivocation
/// form (`WIST3-E02`), a missing Epoch `WIST3-E01`, any other failure `WIST3-E03`.
#[allow(clippy::too_many_arguments)]
pub fn sequence_at_head(
    log_dir: &Path,
    log_id: &str,
    registry: &Registry,
    reached: u64,
    previous: &Checkpoint,
    offered: &Checkpoint,
    cadence_seconds: i64,
    larger_tree: Option<&Tree>,
) -> Result<()> {
    let at_previous = registry.valid_at(previous.epoch_number());
    let signature_verifies = checkpoint::verify(offered, log_id, &at_previous, &[]).is_ok();
    let reader = larger_tree.map(|tree| tree.reader() as &dyn wist_core::merkle::HashReader);
    match checkpoint::check_sequence_at_head(
        previous,
        offered,
        cadence_seconds,
        signature_verifies,
        reader,
    ) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == Some("WIST3-E02") => Err(divergence(
            log_dir,
            log_id,
            registry,
            reached,
            Some(previous),
            offered,
            larger_tree,
            "a Checkpoint states a tree below the Epoch before it whose root is not that tree's root at the smaller size",
        )),
        Err(error) => Err(error.into()),
    }
}

/// WIST-3 §3.1: a gap no source serves is `WIST3-E01` and leaves the head in place.
pub fn archived_between(sources: &Sources, epoch_number: u64) -> Result<Checkpoint> {
    archived(sources, epoch_number).map_err(|error| match error.code().as_deref() {
        Some("WIST3-E01") => checkpoint::absent_checkpoint(epoch_number).into(),
        _ => error,
    })
}

pub fn save_checkpoint(
    conn: &Connection,
    checkpoint: &Checkpoint,
    unwitnessed: Option<bool>,
) -> Result<()> {
    conn.execute_batch(CREATE_CHECKPOINTS)?;
    conn.execute(
        "INSERT INTO checkpoints(epoch_number, note, unwitnessed) VALUES (?1, ?2, ?3)
         ON CONFLICT(epoch_number) DO UPDATE SET note = excluded.note, unwitnessed = COALESCE(excluded.unwitnessed, checkpoints.unwitnessed)",
        (
            checkpoint.epoch_number() as i64,
            checkpoint.encode(),
            unwitnessed,
        ),
    )?;
    Ok(())
}

/// `None` where the Checkpoint was retained without being adopted.
pub fn retained_unwitnessed(conn: &Connection, epoch_number: u64) -> Result<Option<bool>> {
    if !crate::store::table_exists(conn, "checkpoints")? {
        return Ok(None);
    }
    Ok(conn
        .query_row(
            "SELECT unwitnessed FROM checkpoints WHERE epoch_number = ?1",
            [epoch_number as i64],
            |row| row.get::<_, Option<bool>>(0),
        )
        .optional()?
        .flatten())
}

pub fn retained(conn: &Connection, epoch_number: u64) -> Result<Option<Checkpoint>> {
    if !crate::store::table_exists(conn, "checkpoints")? {
        return Ok(None);
    }
    let note: Option<String> = conn
        .query_row(
            "SELECT note FROM checkpoints WHERE epoch_number = ?1",
            [epoch_number as i64],
            |row| row.get(0),
        )
        .optional()?;
    note.map(|note| Checkpoint::parse(&note).map_err(Into::into))
        .transpose()
}

fn evidence_dir(log_dir: &Path, kind: &str, epoch_number: u64) -> PathBuf {
    log_dir
        .join("evidence")
        .join(format!("{kind}-epoch-{epoch_number:09}"))
}

/// WIST-3 §5 and §9.
pub fn record_equivocation(
    log_dir: &Path,
    retained: &Checkpoint,
    offered: &Checkpoint,
) -> Result<PathBuf> {
    let dir = evidence_dir(log_dir, "equivocation", offered.epoch_number());
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("retained.checkpoint"), retained.encode())?;
    std::fs::write(dir.join("offered.checkpoint"), offered.encode())?;
    Ok(dir)
}

/// WIST-3 §9: `previous` is absent for a size-0 Checkpoint with another root than §4's, its own
/// whole evidence.
pub fn record_divergence(
    log_dir: &Path,
    previous: Option<&Checkpoint>,
    offered: &Checkpoint,
    tree: Option<&Tree>,
) -> Result<PathBuf> {
    let dir = evidence_dir(log_dir, "divergence", offered.epoch_number());
    std::fs::create_dir_all(&dir)?;
    if let Some(previous) = previous {
        std::fs::write(dir.join("previous.checkpoint"), previous.encode())?;
    }
    std::fs::write(dir.join("offered.checkpoint"), offered.encode())?;
    if let Some(tree) = tree {
        std::fs::create_dir_all(dir.join("tiles"))?;
        for ((level, index), bytes) in tree.tiles() {
            std::fs::write(dir.join("tiles").join(format!("{level}-{index}")), bytes)?;
        }
    }
    Ok(dir)
}

/// WIST-3 §5: "MUST stop applying new data from that Aggregator".
pub const HALT_FILE: &str = "halt.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Halt {
    pub code: String,
    pub epoch_number: u64,
    pub reason: String,
    pub evidence: String,
}

pub fn halt(log_dir: &Path) -> Option<Halt> {
    let bytes = std::fs::read(log_dir.join(HALT_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn record_halt(log_dir: &Path, epoch_number: u64, reason: &str, evidence: &Path) -> Result<()> {
    let halt = Halt {
        code: "WIST3-E02".into(),
        epoch_number,
        reason: reason.to_owned(),
        evidence: evidence.display().to_string(),
    };
    std::fs::create_dir_all(log_dir)?;
    std::fs::write(log_dir.join(HALT_FILE), serde_json::to_vec(&halt)?)?;
    Ok(())
}

pub fn halted(log_dir: &Path) -> Result<()> {
    match halt(log_dir) {
        None => Ok(()),
        Some(halt) => Err(Error::Verify(format!(
            "WIST3-E02 this Log diverged at epoch {}: {}; the evidence is in {}, and nothing more is applied from this Aggregator until {} is removed",
            halt.epoch_number,
            halt.reason,
            halt.evidence,
            log_dir.display()
        ))),
    }
}

/// WIST-3 §5: authenticated before it is evidence, under the keys valid at its own height once
/// verified history reaches it, else at the verified head, since a fork's key acts are not trusted.
#[allow(clippy::too_many_arguments)]
pub fn divergence(
    log_dir: &Path,
    log_id: &str,
    registry: &Registry,
    reached: u64,
    previous: Option<&Checkpoint>,
    offered: &Checkpoint,
    tiles: Option<&Tree>,
    detail: &str,
) -> Error {
    let height = offered.epoch_number().min(reached);
    if let Err(error) = checkpoint::verify(offered, log_id, &registry.valid_at(height), &[]) {
        return Error::Verify(format!(
            "{error}; {detail} is no evidence while no key valid at epoch {height} signs the Checkpoint offered"
        ));
    }
    let dir = match record_divergence(log_dir, previous, offered, tiles) {
        Ok(dir) => dir,
        Err(error) => return error,
    };
    if let Err(error) = record_halt(log_dir, offered.epoch_number(), detail, &dir) {
        return error;
    }
    Error::Verify(format!(
        "WIST3-E02 {detail}; the evidence is preserved in {}, and nothing more is applied from this Aggregator",
        dir.display()
    ))
}

/// WIST-3 §5 rollback rule: a differing note at a retained height is evidence only if the keys
/// valid at that height verify it; otherwise `WIST3-E03`.
pub fn progression(
    log_dir: &Path,
    conn: &Connection,
    offered: &Checkpoint,
    head_epoch_number: u64,
    log_id: &str,
    registry: &Registry,
) -> Result<Progression> {
    let held = retained(conn, offered.epoch_number())?;
    match checkpoint::progression(offered, head_epoch_number, held.as_ref()) {
        Ok(progression) => Ok(progression),
        Err(error) => {
            if let (Some("WIST3-E02"), Some(held)) = (error.code(), held.as_ref()) {
                checkpoint::verify(
                    offered,
                    log_id,
                    &registry.valid_at(offered.epoch_number()),
                    &[],
                )?;
                let dir = record_equivocation(log_dir, held, offered)?;
                record_halt(
                    log_dir,
                    offered.epoch_number(),
                    "two Checkpoints of one Epoch state different note text",
                    &dir,
                )?;
                return Err(Error::Verify(format!(
                    "{error}; the two Checkpoints are preserved in {}, and nothing more is applied from this Aggregator",
                    dir.display()
                )));
            }
            Err(error.into())
        }
    }
}

/// WIST-3 §8 continuous operation step 1: weighed before any tile or bundle is fetched against it.
pub fn offered_head(
    sources: &Sources,
    log_dir: &Path,
    conn: &Connection,
    log_id: &str,
    head_epoch_number: u64,
    registry: &Registry,
) -> Result<Option<Checkpoint>> {
    let mut last: Option<Error> = None;
    let mut answered = false;
    for at in 0..sources.count() {
        let offered = match sources
            .at("/checkpoint", CHECKPOINT_MAX_BYTES, at, |bytes| {
                parse_note(bytes, "/checkpoint").map(|_| ())
            })
            .and_then(|bytes| parse_note(&bytes, "/checkpoint"))
        {
            Ok(offered) => offered,
            Err(error) => {
                last = Some(error);
                continue;
            }
        };
        match progression(log_dir, conn, &offered, head_epoch_number, log_id, registry) {
            Ok(Progression::Above) => return Ok(Some(offered)),
            Ok(Progression::NotAdopted) => answered = true,
            Err(error) if error.code().as_deref() == Some("WIST3-E02") => return Err(error),
            Err(error) => last = Some(error),
        }
    }
    match last {
        Some(error) if !answered => Err(error),
        _ => Ok(None),
    }
}

/// WIST-3 §5 and §8 step 8: short of the quorum is neither evidence nor an error.
pub fn decide(
    checkpoint: &Checkpoint,
    log_id: &str,
    aggregator_keys: &[wist_core::checkpoint::AggregatorKey],
    witnesses: &[WitnessKey],
    quorum: u64,
) -> Result<wist_core::checkpoint::Adoption> {
    let verification = checkpoint::verify(checkpoint, log_id, aggregator_keys, witnesses)?;
    Ok(checkpoint::adoption(&verification, quorum))
}

/// WIST-3 §5.
pub fn stale(sealed_at_s: i64, cadence_seconds: i64, now_s: i64) -> bool {
    cadence_seconds > 0 && now_s.saturating_sub(sealed_at_s) > 3 * cadence_seconds
}

pub fn warn_if_stale(log_id: &str, checkpoint: &Checkpoint, cadence_seconds: i64) -> bool {
    let Ok(sealed_at_s) = checkpoint.sealed_at_s() else {
        return false;
    };
    let now_s = jiff::Timestamp::now().as_second();
    if !stale(sealed_at_s, cadence_seconds, now_s) {
        return false;
    }
    eprintln!(
        "log {log_id} is stale: the newest Checkpoint it can accept was sealed at {} and more than three sealing cadences have passed",
        checkpoint.sealed_at()
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verifier_key_string_round_trips_and_rejects_a_mismatched_key_id() {
        let key = wist_core::crypto::SigningKey::from_seed(&[4u8; 32]);
        let mut encoded = vec![WITNESS_KEY_TYPE];
        encoded.extend_from_slice(&key.public().to_bytes());
        let name = "witness-a.example";
        let good = format!(
            "{name}+{}+{}",
            hex_encode(&witness_key_id(name, &key.public())),
            STANDARD.encode(&encoded)
        );
        let parsed = parse_witness_key(&good).unwrap();
        assert_eq!(parsed.name, name);
        let wrong = format!("{name}+00000000+{}", STANDARD.encode(&encoded));
        assert!(parse_witness_key(&wrong).is_err());
        assert!(parse_witness_key("no-plus-signs").is_err());
    }

    #[test]
    fn staleness_begins_past_three_sealing_cadences() {
        assert!(!stale(1000, 3600, 1000 + 3 * 3600));
        assert!(stale(1000, 3600, 1000 + 3 * 3600 + 1));
    }
}
