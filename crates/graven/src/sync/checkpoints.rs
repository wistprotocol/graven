//! WIST-3 §5 at the Consumer: the head and archived Checkpoints, the
//! rollback rule, the Witness roster and quorum, and the evidence bundles
//! a divergence leaves on disk.
use super::source::Sources;
use super::tree::Tree;
use crate::error::{Error, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rusqlite::{Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use wist_core::aggregator_keys::Registry;
use wist_core::checkpoint::{
    self, archive_path, check_archive_path, witness_key_id, Checkpoint, Progression, WitnessKey,
    WITNESS_KEY_TYPE,
};
use wist_core::crypto::{hex_encode, PublicKey};

/// A Checkpoint is five short lines and its signature lines; the bound is
/// the Consumer's own, since WIST-3 §6 gives the file no octet bound.
pub const CHECKPOINT_MAX_BYTES: u64 = 65_536;

/// Every Checkpoint the Consumer acted on. `unwitnessed` is WIST-3 §5's
/// record of an acceptance carrying no Cosignature from a trusted
/// Witness, kept with the Checkpoint it belongs to; it is NULL for a
/// Checkpoint the Consumer verified on the way to its head but never
/// adopted, which is no acceptance to record.
pub const CREATE_CHECKPOINTS: &str =
    "CREATE TABLE IF NOT EXISTS checkpoints(block_number INTEGER PRIMARY KEY, note TEXT NOT NULL, unwitnessed INTEGER)";

fn invalid(message: &str) -> Error {
    Error::Verify(format!("WIST3-E03 {message}"))
}

/// WIST-3 §5: the Witness roster is the Consumer's configuration, in the
/// `<name>+<hex key ID>+base64(0x04 || key)` verifier-key form
/// [signed-note] defines for the cosignature/v1 type.
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

/// WIST-3 §8: the head Checkpoint, from the first source that serves one
/// that parses.
pub fn head(sources: &Sources) -> Result<Checkpoint> {
    let bytes = sources.verified("/checkpoint", CHECKPOINT_MAX_BYTES, |bytes| {
        parse_note(bytes, "/checkpoint").map(|_| ())
    })?;
    parse_note(&bytes, "/checkpoint")
}

/// WIST-3 §6: the archived Checkpoint of one Block, rejected where the
/// file's `block_number` line is not the path's number.
pub fn archived(sources: &Sources, block_number: u64) -> Result<Checkpoint> {
    let path = archive_path(block_number);
    let bytes = sources.cached(&path, CHECKPOINT_MAX_BYTES, |bytes| {
        let checkpoint = parse_note(bytes, &path)?;
        check_archive_path(&checkpoint, &path)?;
        Ok(())
    })?;
    parse_note(&bytes, &path)
}

pub fn save_checkpoint(
    conn: &Connection,
    checkpoint: &Checkpoint,
    unwitnessed: Option<bool>,
) -> Result<()> {
    conn.execute_batch(CREATE_CHECKPOINTS)?;
    conn.execute(
        "INSERT INTO checkpoints(block_number, note, unwitnessed) VALUES (?1, ?2, ?3)
         ON CONFLICT(block_number) DO UPDATE SET note = excluded.note, unwitnessed = COALESCE(excluded.unwitnessed, checkpoints.unwitnessed)",
        (
            checkpoint.block_number() as i64,
            checkpoint.encode(),
            unwitnessed,
        ),
    )?;
    Ok(())
}

/// Whether the acceptance of the Checkpoint at one Block was recorded as
/// unwitnessed; absent where the Consumer retained it without adopting it.
pub fn retained_unwitnessed(conn: &Connection, block_number: u64) -> Result<Option<bool>> {
    if !crate::store::table_exists(conn, "checkpoints")? {
        return Ok(None);
    }
    Ok(conn
        .query_row(
            "SELECT unwitnessed FROM checkpoints WHERE block_number = ?1",
            [block_number as i64],
            |row| row.get::<_, Option<bool>>(0),
        )
        .optional()?
        .flatten())
}

/// The Checkpoint the Consumer retains at one Block, against whose note
/// text a later offer of that Block is compared (WIST-3 §5).
pub fn retained(conn: &Connection, block_number: u64) -> Result<Option<Checkpoint>> {
    if !crate::store::table_exists(conn, "checkpoints")? {
        return Ok(None);
    }
    let note: Option<String> = conn
        .query_row(
            "SELECT note FROM checkpoints WHERE block_number = ?1",
            [block_number as i64],
            |row| row.get(0),
        )
        .optional()?;
    note.map(|note| Checkpoint::parse(&note).map_err(Into::into))
        .transpose()
}

fn evidence_dir(log_dir: &Path, kind: &str, block_number: u64) -> PathBuf {
    log_dir
        .join("evidence")
        .join(format!("{kind}-block-{block_number:09}"))
}

/// WIST-3 §5 and §9: two Checkpoints that equivocate are kept as the
/// self-contained bundle anyone can verify from the Anchor.
pub fn record_equivocation(
    log_dir: &Path,
    retained: &Checkpoint,
    offered: &Checkpoint,
) -> Result<PathBuf> {
    let dir = evidence_dir(log_dir, "equivocation", offered.block_number());
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("retained.checkpoint"), retained.encode())?;
    std::fs::write(dir.join("offered.checkpoint"), offered.encode())?;
    Ok(dir)
}

/// WIST-3 §9: the two Checkpoints, and — where the divergence is the
/// third Equivocation form or a failed Consistency Proof — the tree
/// hashes that reproduce the larger root, from which anyone recomputes
/// the prefix root the smaller Checkpoint contradicts. A Checkpoint
/// stating tree size 0 with another root than §4's is its own whole
/// evidence, so `previous` may be absent.
pub fn record_divergence(
    log_dir: &Path,
    previous: Option<&Checkpoint>,
    offered: &Checkpoint,
    tree: Option<&Tree>,
) -> Result<PathBuf> {
    let dir = evidence_dir(log_dir, "divergence", offered.block_number());
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

/// WIST-3 §5: "consumers verifying it MUST stop applying new data from
/// that Aggregator". The halt is recorded beside the evidence and read
/// before every later sync of the Log.
pub const HALT_FILE: &str = "halt.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Halt {
    pub code: String,
    pub block_number: u64,
    pub reason: String,
    pub evidence: String,
}

pub fn halt(log_dir: &Path) -> Option<Halt> {
    let bytes = std::fs::read(log_dir.join(HALT_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn record_halt(log_dir: &Path, block_number: u64, reason: &str, evidence: &Path) -> Result<()> {
    let halt = Halt {
        code: "WIST3-E02".into(),
        block_number,
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
            "WIST3-E02 this Log diverged at block {}: {}; the evidence is in {}, and nothing more is applied from this Aggregator until {} is removed",
            halt.block_number,
            halt.reason,
            halt.evidence,
            log_dir.display()
        ))),
    }
}

/// WIST-3 §5: Equivocation and chain divergence are established between
/// Checkpoints "each validly signed under an Aggregator key valid at the
/// height its `block_number` line states", so an offered Checkpoint is
/// authenticated before it is treated as evidence — under the keys valid
/// at its own height where the Consumer's verified history has reached
/// it, and otherwise under those valid at the verified head, since a
/// fork's own key acts are not trusted. One that does not authenticate
/// is `WIST3-E03` against the source that served it.
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
    let height = offered.block_number().min(reached);
    if let Err(error) = checkpoint::verify(offered, log_id, &registry.valid_at(height), &[]) {
        return Error::Verify(format!(
            "{error}; {detail} is no evidence while no key valid at block {height} signs the Checkpoint offered"
        ));
    }
    let dir = match record_divergence(log_dir, previous, offered, tiles) {
        Ok(dir) => dir,
        Err(error) => return error,
    };
    if let Err(error) = record_halt(log_dir, offered.block_number(), detail, &dir) {
        return error;
    }
    Error::Verify(format!(
        "WIST3-E02 {detail}; the evidence is preserved in {}, and nothing more is applied from this Aggregator",
        dir.display()
    ))
}

/// WIST-3 §5's rollback rule, with the evidence an equivocating offer
/// leaves behind: a Checkpoint at or below the verified head adopts
/// nothing and carries no error code, unless its note text differs from
/// the one retained at its `block_number`. Equivocation is two
/// Checkpoints each validly signed under a key valid at the height its
/// `block_number` line states, so a differing note is verified under the
/// keys valid at that height before it is treated as evidence: one that
/// does not verify is `WIST3-E03` against the source that served it and
/// is preserved as nothing.
pub fn progression(
    log_dir: &Path,
    conn: &Connection,
    offered: &Checkpoint,
    head_block_number: u64,
    log_id: &str,
    registry: &Registry,
) -> Result<Progression> {
    let held = retained(conn, offered.block_number())?;
    match checkpoint::progression(offered, head_block_number, held.as_ref()) {
        Ok(progression) => Ok(progression),
        Err(error) => {
            if let (Some("WIST3-E02"), Some(held)) = (error.code(), held.as_ref()) {
                // The Consumer has verified this Block, so the keys valid
                // at its own height are the ones that can speak for it.
                checkpoint::verify(
                    offered,
                    log_id,
                    &registry.valid_at(offered.block_number()),
                    &[],
                )?;
                let dir = record_equivocation(log_dir, held, offered)?;
                record_halt(
                    log_dir,
                    offered.block_number(),
                    "two Checkpoints of one Block state different note text",
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

/// WIST-3 §8's continuous operation, step 1: the head Checkpoint each
/// source offers, weighed against the verified head before any tile or
/// bundle is fetched against it. A source serving a Checkpoint at or
/// below the head, or one whose note the keys valid at its height do not
/// authenticate, is asked nothing further and the next source is tried;
/// equivocation stops the Log.
pub fn offered_head(
    sources: &Sources,
    log_dir: &Path,
    conn: &Connection,
    log_id: &str,
    head_block_number: u64,
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
        match progression(log_dir, conn, &offered, head_block_number, log_id, registry) {
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

/// WIST-3 §5 and §8 step 8: a Checkpoint the Log's signature
/// authenticates under the keys valid at its height, weighed against the
/// Witness quorum in force at its `sealed_at`. A Checkpoint short of the
/// quorum is neither evidence nor an error; one whose known-key signature
/// fails is `WIST3-E03`.
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

/// WIST-3 §5: the Log is stale when the newest acceptable Checkpoint's
/// `sealed_at` lags the current time by more than three sealing cadences.
pub fn stale(sealed_at_s: i64, cadence_seconds: i64, now_s: i64) -> bool {
    cadence_seconds > 0 && now_s.saturating_sub(sealed_at_s) > 3 * cadence_seconds
}

/// Reports whether the newest Checkpoint the Consumer can accept — the
/// one it adopted, or the verified head it kept — lags the current time
/// by more than three sealing cadences, warning where it does.
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
