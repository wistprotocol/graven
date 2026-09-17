mod common;

use common::{write_anchor, write_block, write_checkpoint, write_index, write_manifest, Signer};
use graven::ranking::{DomainState, Profile};
use graven::store::Store;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use wist_core::envelope::sign_envelope;
use wist_core::objects::{LabelEntry, StateEntry};

fn label_entry(signer: &Signer, inner: Value) -> (String, Value) {
    let id = wist_core::label::label_id(&inner).unwrap();
    let body = sign_envelope(&inner, "label", &signer.kid(), &signer.sk).unwrap();
    (id, json!({"type": "label", "body": body}))
}

/// Builds a Log whose only Snapshot is at `snapshot_height`, so a
/// Consumer syncing this fixture resumes from it and never walks the
/// Blocks the Snapshot's tuples stand in for.
struct Resumed {
    dir: tempfile::TempDir,
    target: tempfile::TempDir,
    log: Signer,
    log_id: String,
    anchor_hash: String,
    base_url: String,
}

fn setup_resumed(
    log_id: &str,
    seed: u8,
    snapshot_height: u64,
    declarations: &[(String, Value)],
    state_entries: Vec<StateEntry>,
) -> Resumed {
    let dir = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let log = Signer::new([seed; 32]);
    write_anchor(&dir.path().join("anchor.json"), &log, log_id);

    let mut prev_hash = "sha256:genesis".to_string();
    for h in 0..=snapshot_height {
        let sealed_at = format!("2026-08-09T{h:02}:00:00Z");
        let (_, hash) = common::build_block(&log, h, &prev_hash, &sealed_at, &[]);
        prev_hash = hash;
    }
    let anchor_hash = prev_hash;

    let snapshot_date = "2026-08-09";
    let snapdir = dir.path().join("snapshots").join(snapshot_date);
    let sqlite_bytes = common::write_tier0(&snapdir.join("tier0/index.sqlite"), &[]);
    let content_digest_value = wist_core::snapshot::content_digest(&[]).unwrap();
    let (state_bytes, state_digest_value) = common::write_state_with(
        &snapdir.join("state.json"),
        &log,
        3600,
        declarations,
        &[],
        snapshot_height,
        state_entries,
        0,
    );
    write_manifest(
        &snapdir.join("manifest.json"),
        &log,
        snapshot_date,
        snapshot_height,
        &anchor_hash,
        &content_digest_value,
        &state_bytes,
        &state_digest_value,
        &sqlite_bytes,
    );
    write_index(
        &dir.path().join("snapshots/index.json"),
        &log,
        snapshot_date,
        snapshot_height,
        &format!("/snapshots/{snapshot_date}/manifest.json"),
        &content_digest_value,
    );
    write_checkpoint(
        dir.path(),
        &log,
        snapshot_height,
        &anchor_hash,
        &format!("2026-08-09T{snapshot_height:02}:00:00Z"),
    );

    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
    Resumed {
        dir,
        target,
        log,
        log_id: log_id.to_string(),
        anchor_hash,
        base_url,
    }
}

fn seal_after_snapshot(r: &Resumed, block_number: u64, sealed_at: &str, entries: &[Value]) {
    let (block, hash) =
        common::build_block(&r.log, block_number, &r.anchor_hash, sealed_at, entries);
    write_block(r.dir.path(), block_number, &block);
    write_checkpoint(r.dir.path(), &r.log, block_number, &hash, sealed_at);
}

fn sync(r: &Resumed) -> graven::sync::SyncReport {
    graven::sync::run(
        r.dir.path().join("anchor.json").to_str().unwrap(),
        &r.base_url,
        r.target.path(),
        true,
        false,
    )
    .unwrap()
}

fn opened(r: &Resumed) -> Store {
    Store::open(&graven::registry::log_dir(r.target.path(), &r.log_id)).unwrap()
}

/// WIST-3 §7: a Snapshot carries only the current Label per (labeler,
/// subject, name), not the history behind it. A dispute naming a Label
/// sealed at or below the walk floor cannot be told apart from one the
/// Snapshot's tuples simply don't hold, so it is recorded rather than
/// rejected as absent.
#[test]
fn dispute_at_or_below_the_walk_floor_is_recorded_despite_missing_tuples() {
    let disputant = Signer::new([40u8; 32]);
    let declaration = common::build_declaration(&disputant, "disputant.example");
    let r = setup_resumed(
        "resumed-dispute-below-floor",
        80,
        3,
        &[("disputant.example".into(), declaration)],
        Vec::new(),
    );

    let named_label = format!("sha256:{}", "c".repeat(64));
    let dispute_inner = json!({
        "wist_version": "1.0.0",
        "disputant": "disputant.example",
        "label": named_label,
        "log": "log.example",
        "height": 1u64,
        "asserted_at": "2026-08-09T04:00:00Z",
    });
    let dispute = json!({"type": "dispute", "body": sign_envelope(&dispute_inner, "dispute", &disputant.kid(), &disputant.sk).unwrap()});

    seal_after_snapshot(&r, 4, "2026-08-09T04:00:00Z", &[dispute]);
    sync(&r);

    let store = opened(&r);
    let disputes = store.disputes_for(&named_label).unwrap();
    assert_eq!(
        disputes.len(),
        1,
        "a dispute naming a Label sealed at or below the walk floor must be recorded, not rejected as absent"
    );
    assert_eq!(disputes[0].disputant, "disputant.example");
}

/// The same reading does not excuse a dispute naming a Label sealed
/// above the walk floor: nothing this index holds could have sealed it,
/// so it is genuinely absent and rejected.
#[test]
fn dispute_above_the_walk_floor_naming_an_unknown_label_is_rejected() {
    let disputant = Signer::new([41u8; 32]);
    let declaration = common::build_declaration(&disputant, "auditor2.example");
    let r = setup_resumed(
        "resumed-dispute-above-floor",
        81,
        3,
        &[("auditor2.example".into(), declaration)],
        Vec::new(),
    );

    let unknown_label = format!("sha256:{}", "d".repeat(64));
    let dispute_inner = json!({
        "wist_version": "1.0.0",
        "disputant": "auditor2.example",
        "label": unknown_label,
        "log": "log.example",
        "height": 10u64,
        "asserted_at": "2026-08-09T04:00:00Z",
    });
    let dispute = json!({"type": "dispute", "body": sign_envelope(&dispute_inner, "dispute", &disputant.kid(), &disputant.sk).unwrap()});

    seal_after_snapshot(&r, 4, "2026-08-09T04:00:00Z", &[dispute]);
    sync(&r);

    let store = opened(&r);
    assert!(
        store.disputes_for(&unknown_label).unwrap().is_empty(),
        "a dispute naming a Label sealed above the walk floor is genuinely absent and must be rejected"
    );
}

/// A dispute naming a Label the adopted tuples do carry resolves as
/// Known, and the authority check core's validate_dispute makes for a
/// Known Label still applies: an unauthorized disputant is rejected
/// while an authorized one still succeeds, over the very same tuple.
#[test]
fn dispute_naming_an_adopted_label_still_checks_authority() {
    let subject = "https://records.example/page";
    let known_id = format!("sha256:{}", "e".repeat(64));
    let outsider = Signer::new([42u8; 32]);
    let owner = Signer::new([43u8; 32]);
    let outsider_declaration = common::build_declaration(&outsider, "auditor3.example");
    let owner_declaration = common::build_declaration(&owner, "records.example");

    let label_tuple = StateEntry::Label(LabelEntry {
        labeler: "labels.sample.net".into(),
        subject: subject.into(),
        name: "wist:mismatch".into(),
        value: None,
        asserted_at: "2026-08-01T00:00:00Z".into(),
        expires_at: None,
        delta: None,
        label_id: known_id.clone(),
        sealing_height: 1,
    });

    let r = setup_resumed(
        "resumed-dispute-authority",
        82,
        3,
        &[
            ("auditor3.example".into(), outsider_declaration),
            ("records.example".into(), owner_declaration),
        ],
        vec![label_tuple],
    );

    let unauthorized_inner = json!({
        "wist_version": "1.0.0",
        "disputant": "auditor3.example",
        "label": known_id,
        "log": "log.example",
        "height": 1u64,
        "asserted_at": "2026-08-09T04:00:00Z",
    });
    let unauthorized = json!({"type": "dispute", "body": sign_envelope(&unauthorized_inner, "dispute", &outsider.kid(), &outsider.sk).unwrap()});

    let authorized_inner = json!({
        "wist_version": "1.0.0",
        "disputant": "records.example",
        "label": known_id,
        "log": "log.example",
        "height": 1u64,
        "asserted_at": "2026-08-09T04:01:00Z",
    });
    let authorized = json!({"type": "dispute", "body": sign_envelope(&authorized_inner, "dispute", &owner.kid(), &owner.sk).unwrap()});

    seal_after_snapshot(&r, 4, "2026-08-09T04:00:00Z", &[unauthorized, authorized]);
    sync(&r);

    let store = opened(&r);
    let disputes = store.disputes_for(&known_id).unwrap();
    assert_eq!(
        disputes.len(),
        1,
        "only the authorized disputant's dispute over the adopted Label must be recorded: {disputes:?}"
    );
    assert_eq!(disputes[0].disputant, "records.example");
}

fn default_profile_naming(labeler: &str) -> Profile {
    let json = format!(
        r#"{{
            "name": "test",
            "description": "",
            "author": "",
            "license": "",
            "issues_url": "",
            "superseded_by": null,
            "labelers": ["{labeler}"],
            "agreement_k": 1,
            "seeds": [],
            "distrust_seeds": [],
            "weights": {{"trust_floor": 0.05, "trust": 1.0, "inlinks": 0.25, "freshness": 0.2, "distrust": 1.0, "mismatch": 0.5}},
            "filters": {{"distrust_above": 0.5, "spam": true, "min_age_blocks": 0, "trusted_graph_only": false}},
            "propagation": {{"alpha": 0.15, "iterations": 20, "decay_per_block": 0.999, "growth_window_blocks": 720, "growth_damping": 1.0}},
            "readings": {{"persistence_blocks": 2, "labeler_inactive_blocks": 720}},
            "personalization": false
        }}"#
    );
    serde_json::from_str(&json).unwrap()
}

/// WIST-4 §6's inactivity reading measures against a Labeler's last
/// sealed Entry. A resumed index only holds that height because
/// adopting the Label tuple recorded it (WIST-3 §7); it must read the
/// same verdict a Consumer that walked the Entry itself would, and mark
/// the row as counting from the resume.
#[test]
fn resumed_labeler_activity_matches_a_full_replay() {
    let domain = "spammer.example";
    let subject = "https://victim.example/page";

    // The full replay: the Labeler's only Entry is walked at height 1.
    let genesis_dir = tempfile::tempdir().unwrap();
    let genesis_target = tempfile::tempdir().unwrap();
    let genesis_log = Signer::new([50u8; 32]);
    write_anchor(
        &genesis_dir.path().join("anchor.json"),
        &genesis_log,
        "resumed-labeler-genesis",
    );
    let labeler = Signer::new([51u8; 32]);
    let declaration = common::build_declaration(&labeler, domain);
    let (block0, block0_hash) = common::build_block(
        &genesis_log,
        0,
        "sha256:genesis",
        "2026-08-09T00:00:00Z",
        &[],
    );
    write_block(genesis_dir.path(), 0, &block0);
    let snapshot_date = "2026-08-09";
    let snapdir = genesis_dir.path().join("snapshots").join(snapshot_date);
    let sqlite_bytes = common::write_tier0(&snapdir.join("tier0/index.sqlite"), &[]);
    let content_digest_value = wist_core::snapshot::content_digest(&[]).unwrap();
    let (state_bytes, state_digest_value) = common::write_state_with(
        &snapdir.join("state.json"),
        &genesis_log,
        3600,
        &[(domain.to_string(), declaration.clone())],
        &[],
        0,
        Vec::new(),
        0,
    );
    write_manifest(
        &snapdir.join("manifest.json"),
        &genesis_log,
        snapshot_date,
        0,
        &block0_hash,
        &content_digest_value,
        &state_bytes,
        &state_digest_value,
        &sqlite_bytes,
    );
    write_index(
        &genesis_dir.path().join("snapshots/index.json"),
        &genesis_log,
        snapshot_date,
        0,
        &format!("/snapshots/{snapshot_date}/manifest.json"),
        &content_digest_value,
    );
    let (_, label_wrapped) = label_entry(
        &labeler,
        json!({"wist_version": "1.0.0", "labeler": domain, "subject": subject, "name": "wist:spam", "asserted_at": "2026-08-09T01:00:00Z"}),
    );
    let (block1, block1_hash) = common::build_block(
        &genesis_log,
        1,
        &block0_hash,
        "2026-08-09T01:00:00Z",
        &[label_wrapped],
    );
    write_block(genesis_dir.path(), 1, &block1);
    write_checkpoint(
        genesis_dir.path(),
        &genesis_log,
        1,
        &block1_hash,
        "2026-08-09T01:00:00Z",
    );
    let genesis_base = format!(
        "http://{}",
        common::serve_static(genesis_dir.path().to_path_buf())
    );
    graven::sync::run(
        genesis_dir.path().join("anchor.json").to_str().unwrap(),
        &genesis_base,
        genesis_target.path(),
        true,
        false,
    )
    .unwrap();
    let genesis_store = Store::open(&graven::registry::log_dir(
        genesis_target.path(),
        "resumed-labeler-genesis",
    ))
    .unwrap();

    // The resumed index: the very same Label reaches it only as an
    // adopted Snapshot tuple at height 1, under a Snapshot taken later.
    let label_tuple = StateEntry::Label(LabelEntry {
        labeler: domain.into(),
        subject: subject.into(),
        name: "wist:spam".into(),
        value: None,
        asserted_at: "2026-08-09T01:00:00Z".into(),
        expires_at: None,
        delta: None,
        label_id: format!("sha256:{}", "9".repeat(64)),
        sealing_height: 1,
    });
    let r = setup_resumed(
        "resumed-labeler-resumed",
        52,
        5,
        &[(domain.to_string(), declaration)],
        vec![label_tuple],
    );
    sync(&r);
    let resumed_store = opened(&r);

    let resumed_row = resumed_store
        .labelers()
        .unwrap()
        .into_iter()
        .find(|l| l.labeler == domain)
        .expect("adopting the Label tuple must record a labelers row");
    assert_eq!(resumed_row.last_sealed_height, 1);
    assert!(
        resumed_row.counts_from_resume,
        "a Labeler this index only knows through an adopted tuple must be marked"
    );

    let genesis_row = genesis_store
        .labelers()
        .unwrap()
        .into_iter()
        .find(|l| l.labeler == domain)
        .expect("the walked Label must record a labelers row");
    assert_eq!(genesis_row.last_sealed_height, 1);
    assert!(!genesis_row.counts_from_resume);

    let profile = default_profile_naming(domain);
    let empty: BTreeSet<String> = BTreeSet::new();

    // Below the inactivity window from height 1: both read the Labeler
    // as active, so its wist:spam Label counts.
    let genesis_conn = rusqlite::Connection::open(
        graven::registry::log_dir(genesis_target.path(), "resumed-labeler-genesis")
            .join("index.sqlite"),
    )
    .unwrap();
    let resumed_conn = rusqlite::Connection::open(
        graven::registry::log_dir(r.target.path(), &r.log_id).join("index.sqlite"),
    )
    .unwrap();
    let near_genesis = DomainState::derive(&genesis_conn, &profile, &empty, 100, None).unwrap();
    let near_resumed = DomainState::derive(&resumed_conn, &profile, &empty, 100, None).unwrap();
    assert!(near_genesis.spam_urls.contains(subject));
    assert!(near_resumed.spam_urls.contains(subject));

    // Past the window from height 1 (720 blocks): both must read the
    // Labeler as inactive and stop counting its Label, in agreement.
    let far_height = 1 + 720 + 5;
    let far_genesis =
        DomainState::derive(&genesis_conn, &profile, &empty, far_height, None).unwrap();
    let far_resumed =
        DomainState::derive(&resumed_conn, &profile, &empty, far_height, None).unwrap();
    assert!(!far_genesis.spam_urls.contains(subject));
    assert!(
        !far_resumed.spam_urls.contains(subject),
        "the resumed index must read the same inactivity verdict as a full replay"
    );
}
