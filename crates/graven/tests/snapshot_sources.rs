//! WIST-3 §6 and §9 at cold start: a Snapshot's documents and files are
//! verified "by hash, signature, or commitment, never by source", so a
//! source that does not hold one or serves it corrupt sends the same path
//! to the next source, and `WIST3-E04` stands only where no source yields
//! a Snapshot whose documents agree.
mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

fn sync_from(
    fx: &common::Fixture,
    dir: &Path,
    mirrors: &[String],
) -> Result<graven::sync::SyncReport, graven::Error> {
    graven::sync::follow(
        &graven::sync::Follow {
            anchor: fx.anchor_path().to_str().unwrap(),
            log_base: &fx.base_url,
            mirrors,
            witnesses: &[],
            tier1: false,
            allow_http: true,
        },
        dir,
    )
}

/// A second source holding what the first held before it was tampered
/// with, recording every path it is asked for.
fn mirror_of(fx: &common::Fixture) -> (tempfile::TempDir, String, Arc<Mutex<Vec<String>>>) {
    let dir = tempfile::tempdir().unwrap();
    common::copy_dir(fx.dir.path(), dir.path());
    let (addr, requests) = common::serve_recording(dir.path().to_path_buf());
    (dir, format!("http://{addr}"), requests)
}

fn asked_for(requests: &Arc<Mutex<Vec<String>>>, path: &str) -> bool {
    requests
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|seen| seen == path)
}

fn flip_last_byte(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(path, bytes).unwrap();
}

fn snapshot_path(fx: &common::Fixture, file: &str) -> String {
    format!("/snapshots/{}/{file}", fx.snapshot_date)
}

/// WIST-3 §9's `WIST3-E04`: "A file hash or byte size that disagrees with
/// the manifest … reject the entire Snapshot and re-fetch, from another
/// Mirror if needed."
#[test]
fn a_cold_start_asks_another_source_for_a_snapshot_file_whose_hash_fails() {
    let fx = common::build_fixture(true, false);
    let (_mirror_dir, mirror, mirror_requests) = mirror_of(&fx);
    flip_last_byte(
        &fx.dir
            .path()
            .join("snapshots/2026-08-09/tier0/index.sqlite"),
    );

    let only_source = tempfile::tempdir().unwrap();
    assert!(
        sync_from(&fx, only_source.path(), &[]).is_err(),
        "the flipped octet fails the manifest's sha256 and no other source holds the file"
    );

    let target = tempfile::tempdir().unwrap();
    let report = sync_from(&fx, target.path(), std::slice::from_ref(&mirror))
        .expect("the second source serves the file the manifest's sha256 names");
    assert_eq!(report.head, 1);
    assert!(
        asked_for(&mirror_requests, &snapshot_path(&fx, "tier0/index.sqlite")),
        "the same path is asked of the next source"
    );
}

/// WIST-3 §6: "integrity is verified by hash, signature, or commitment,
/// never by source", so a state file one source does not hold is fetched
/// from another.
#[test]
fn a_cold_start_asks_another_source_for_a_state_file_the_first_source_lacks() {
    let fx = common::build_fixture(true, false);
    let (_mirror_dir, mirror, mirror_requests) = mirror_of(&fx);
    std::fs::remove_file(fx.dir.path().join("snapshots/2026-08-09/state.json")).unwrap();

    let only_source = tempfile::tempdir().unwrap();
    assert!(
        sync_from(&fx, only_source.path(), &[]).is_err(),
        "no source holds the state file the manifest names"
    );

    let target = tempfile::tempdir().unwrap();
    let report = sync_from(&fx, target.path(), std::slice::from_ref(&mirror))
        .expect("the second source holds the state file");
    assert_eq!(report.head, 1);
    assert!(
        asked_for(&mirror_requests, &snapshot_path(&fx, "state.json")),
        "the same path is asked of the next source"
    );
}

/// WIST-3 §8 step 2: the index entry and the manifest are independently
/// signed statements about one Snapshot, so a manifest disagreeing with
/// the chosen entry is `WIST3-E04` — and §9 re-fetches it "from another
/// Mirror if needed" before the Snapshot is given up.
#[test]
fn a_cold_start_takes_the_manifest_of_the_source_that_agrees_with_the_chosen_index() {
    let fx = common::build_fixture(true, false);
    let (_mirror_dir, mirror, mirror_requests) = mirror_of(&fx);
    common::corrupt_manifest_content_digest(fx.dir.path(), &fx.log, &fx.snapshot_date);

    let target = tempfile::tempdir().unwrap();
    let report = sync_from(&fx, target.path(), std::slice::from_ref(&mirror))
        .expect("the second source's manifest names the content_digest the index entry names");
    assert_eq!(report.head, 1);
    assert!(
        asked_for(&mirror_requests, &snapshot_path(&fx, "manifest.json")),
        "the manifest of the disagreeing source is asked of the next one"
    );
}

/// WIST-3 §9's `WIST3-E04`: the disagreement is reported only once no
/// source yields a Snapshot whose manifest and index entry agree.
#[test]
fn a_snapshot_no_source_serves_consistently_is_rejected_with_e04() {
    let fx = common::build_fixture(true, false);
    let (mirror_dir, mirror, _mirror_requests) = mirror_of(&fx);
    for served in [fx.dir.path(), mirror_dir.path()] {
        common::corrupt_manifest_content_digest(served, &fx.log, &fx.snapshot_date);
    }

    let target = tempfile::tempdir().unwrap();
    let error = sync_from(&fx, target.path(), std::slice::from_ref(&mirror))
        .unwrap_err()
        .to_string();
    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(!common::synced_log_dir(target.path())
        .join("sync.json")
        .exists());
}

/// WIST-3 §8 step 8 and §9: a Snapshot whose documents do not verify
/// "under the keys valid at the height of the Checkpoint it adopts" is
/// rejected entirely and re-fetched "from another Mirror if needed", so
/// the Consumer cold-starts from the source that re-signed them after the
/// removal.
#[test]
fn a_cold_start_takes_the_snapshot_of_the_source_whose_documents_verify_at_the_adopted_head() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([41u8; 32]);
    common::seal_the_genesis_keys_removal(&fx, &second);
    let (mirror_dir, mirror, mirror_requests) = mirror_of(&fx);
    common::resign_snapshot_documents(mirror_dir.path(), &fx.snapshot_date, "log2", &second);

    let only_source = tempfile::tempdir().unwrap();
    assert!(
        sync_from(&fx, only_source.path(), &[]).is_err(),
        "the first source still serves the documents the removed key signed"
    );

    let target = tempfile::tempdir().unwrap();
    let report = sync_from(&fx, target.path(), std::slice::from_ref(&mirror))
        .expect("the second source serves documents a key valid at the head signed");
    assert_eq!(report.head, 3);
    assert!(
        asked_for(&mirror_requests, "/snapshots/index.json"),
        "the whole Snapshot is re-fetched from the next source, its index first"
    );
}

/// WIST-3 §9's `WIST3-E04`: the rejection stands once no source serves a
/// Snapshot whose documents verify at the adopted head, and nothing the
/// Snapshot carried is persisted.
#[test]
fn a_snapshot_no_source_signs_for_the_adopted_head_is_rejected_by_every_source() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([42u8; 32]);
    common::seal_the_genesis_keys_removal(&fx, &second);
    let (_mirror_dir, mirror, mirror_requests) = mirror_of(&fx);

    let target = tempfile::tempdir().unwrap();
    let error = sync_from(&fx, target.path(), std::slice::from_ref(&mirror))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("WIST3-E04") && error.contains("the Snapshot index"),
        "error was: {error}"
    );
    assert!(
        asked_for(&mirror_requests, "/snapshots/index.json"),
        "every source is asked before the rejection stands"
    );
    assert!(!target.path().join("logs.json").exists());
    assert!(!common::synced_log_dir(target.path())
        .join("index.sqlite")
        .exists());
}

/// WIST-3 §9's `WIST3-E04`: a manifest whose `state_digest` is not the one
/// the state file served beside it recomputes is a disagreement among one
/// source's documents, judged before any signature is, so the whole
/// Snapshot is re-fetched "from another Mirror if needed". §9's no-refetch
/// case is the narrower one: a digest "that disagrees with the Consumer's
/// own rebuild at `tree_size`" from the Log.
#[test]
fn a_cold_start_takes_the_snapshot_of_the_source_whose_manifest_agrees_with_its_state_file() {
    let fx = common::build_fixture(true, false);
    let (_mirror_dir, mirror, mirror_requests) = mirror_of(&fx);
    common::corrupt_state_digest(fx.dir.path(), &fx.other, &fx.snapshot_date);

    let only_source = tempfile::tempdir().unwrap();
    assert!(
        sync_from(&fx, only_source.path(), &[]).is_err(),
        "the first source's manifest names a state_digest its state file does not recompute"
    );

    let target = tempfile::tempdir().unwrap();
    let report = sync_from(&fx, target.path(), std::slice::from_ref(&mirror))
        .expect("the second source's manifest names the digest its state file recomputes");
    assert_eq!(report.head, 1);
    assert!(
        asked_for(&mirror_requests, "/snapshots/index.json"),
        "the whole Snapshot is re-fetched from the next source, its index first"
    );
}

/// The same `WIST3-E04` stands once no source serves a manifest its own
/// state file agrees with, and the Consumer persists nothing derived from
/// the Snapshot — the registration this run made included (§8 step 8).
#[test]
fn a_manifest_no_source_agrees_with_its_state_file_is_rejected_and_registers_nothing() {
    let fx = common::build_fixture(true, false);
    let (mirror_dir, mirror, _mirror_requests) = mirror_of(&fx);
    for served in [fx.dir.path(), mirror_dir.path()] {
        common::corrupt_state_digest(served, &fx.other, &fx.snapshot_date);
    }

    let target = tempfile::tempdir().unwrap();
    let error = sync_from(&fx, target.path(), std::slice::from_ref(&mirror))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("WIST3-E04") && error.contains("state_digest"),
        "error was: {error}"
    );
    assert!(!target.path().join("logs.json").exists());
    assert!(!common::synced_log_dir(target.path())
        .join("index.sqlite")
        .exists());
}
