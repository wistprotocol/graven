mod common;

use common::{write_index, write_manifest, Log, Signer};
use graven::ranking::{DomainState, Profile};
use graven::store::Store;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::BTreeSet;
use wist_core::envelope::sign_envelope;
use wist_core::objects::{LabelEntry, StateEntry};

fn label_entry(signer: &Signer, inner: Value) -> (String, Value) {
    let id = wist_core::label::label_id(&inner).unwrap();
    let body = sign_envelope(&inner, "label", &signer.kid(), &signer.sk).unwrap();
    (id, json!({"type": "label", "body": body}))
}

struct Resumed {
    dir: tempfile::TempDir,
    target: tempfile::TempDir,
    log_id: String,
    state: RefCell<Log>,
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
    let mut state = Log::new(dir.path(), Signer::new([seed; 32]), log_id);
    for h in 0..=snapshot_height {
        state.seal(&format!("2026-08-09T{h:02}:00:00Z"), &[]);
    }
    let anchor_root = state.root_token();
    let anchor_size = state.tree_size();

    let snapshot_date = "2026-08-09";
    let snapdir = common::snapshot_dir(dir.path(), snapshot_date, snapshot_height);
    let sqlite_bytes = common::write_tier0(&snapdir.join("tier0/index.sqlite"), &[]);
    let content_digest_value = common::content_digest(&[]);
    let (state_bytes, state_digest_value) = common::write_state_with(
        &snapdir.join("state.json"),
        &log,
        3600,
        declarations,
        anchor_size,
        state_entries,
        0,
    );
    write_manifest(
        &snapdir.join("manifest.json"),
        &log,
        snapshot_date,
        snapshot_height,
        anchor_size,
        &anchor_root,
        &content_digest_value,
        &state_bytes,
        &state_digest_value,
        &sqlite_bytes,
    );
    write_index(
        &dir.path().join("snapshots/index.json"),
        &log,
        snapshot_date,
        anchor_size,
        &common::manifest_url(snapshot_date, snapshot_height),
        &content_digest_value,
    );

    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
    Resumed {
        dir,
        target,
        log_id: log_id.to_string(),
        state: RefCell::new(state),
        base_url,
    }
}

fn seal_after_snapshot(r: &Resumed, _epoch_number: u64, sealed_at: &str, entries: &[Value]) {
    r.state.borrow_mut().seal(sealed_at, entries);
}

fn sync(r: &Resumed) -> graven::sync::SyncReport {
    let report = graven::sync::run(
        r.dir.path().join("log/anchor.json").to_str().unwrap(),
        &r.base_url,
        r.target.path(),
        true,
        false,
    )
    .unwrap();
    common::assert_records_materialized(&graven::registry::log_dir(r.target.path(), &r.log_id));
    report
}

fn opened(r: &Resumed) -> Store {
    Store::open(&graven::registry::log_dir(r.target.path(), &r.log_id)).unwrap()
}

/// WIST-3 §7.
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
        retracted: false,
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
            "filters": {{"distrust_above": 0.5, "spam": true, "min_age_epochs": 0, "trusted_graph_only": false}},
            "propagation": {{"alpha": 0.15, "iterations": 20, "decay_per_epoch": 0.999, "growth_window_epochs": 720, "growth_damping": 1.0}},
            "readings": {{"persistence_epochs": 2, "labeler_inactive_epochs": 720}},
            "personalization": false
        }}"#
    );
    serde_json::from_str(&json).unwrap()
}

/// WIST-4 §6 and WIST-3 §7.
#[test]
fn resumed_labeler_activity_matches_a_full_replay() {
    let domain = "spammer.example";
    let subject = "https://victim.example/page";

    let genesis_dir = tempfile::tempdir().unwrap();
    let genesis_target = tempfile::tempdir().unwrap();
    let genesis_log = Signer::new([50u8; 32]);
    let mut genesis_state = Log::new(
        genesis_dir.path(),
        Signer::new([50u8; 32]),
        "resumed-labeler-genesis",
    );
    let labeler = Signer::new([51u8; 32]);
    let declaration = common::build_declaration(&labeler, domain);
    let epoch0 = genesis_state.seal("2026-08-09T00:00:00Z", &[]);
    let epoch0_root = epoch0.root_token();
    let epoch0_size = epoch0.tree_size();
    let snapshot_date = "2026-08-09";
    let snapdir = common::snapshot_dir(genesis_dir.path(), snapshot_date, 0);
    let sqlite_bytes = common::write_tier0(&snapdir.join("tier0/index.sqlite"), &[]);
    let content_digest_value = common::content_digest(&[]);
    let (state_bytes, state_digest_value) = common::write_state_with(
        &snapdir.join("state.json"),
        &genesis_log,
        3600,
        &[(domain.to_string(), declaration.clone())],
        epoch0_size,
        Vec::new(),
        0,
    );
    write_manifest(
        &snapdir.join("manifest.json"),
        &genesis_log,
        snapshot_date,
        0,
        epoch0_size,
        &epoch0_root,
        &content_digest_value,
        &state_bytes,
        &state_digest_value,
        &sqlite_bytes,
    );
    write_index(
        &genesis_dir.path().join("snapshots/index.json"),
        &genesis_log,
        snapshot_date,
        epoch0_size,
        &common::manifest_url(snapshot_date, 0),
        &content_digest_value,
    );
    let (_, label_wrapped) = label_entry(
        &labeler,
        json!({"wist_version": "1.0.0", "labeler": domain, "subject": subject, "name": "wist:spam", "asserted_at": "2026-08-09T01:00:00Z"}),
    );
    genesis_state.seal("2026-08-09T01:00:00Z", &[label_wrapped]);
    let genesis_base = format!(
        "http://{}",
        common::serve_static(genesis_dir.path().to_path_buf())
    );
    graven::sync::run(
        genesis_dir.path().join("log/anchor.json").to_str().unwrap(),
        &genesis_base,
        genesis_target.path(),
        true,
        false,
    )
    .unwrap();
    common::assert_records_materialized(&graven::registry::log_dir(
        genesis_target.path(),
        "resumed-labeler-genesis",
    ));
    let genesis_store = Store::open(&graven::registry::log_dir(
        genesis_target.path(),
        "resumed-labeler-genesis",
    ))
    .unwrap();

    let label_tuple = StateEntry::Label(LabelEntry {
        labeler: domain.into(),
        subject: subject.into(),
        name: "wist:spam".into(),
        value: None,
        asserted_at: "2026-08-09T01:00:00Z".into(),
        retracted: false,
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

    // 720 Epochs: the default inactivity window.
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

struct Epoch {
    sealed_at: &'static str,
    labels: Vec<Value>,
}

fn serve_log(
    log_id: &str,
    seed: u8,
    labeler: &Signer,
    domain: &str,
    epochs: &[Epoch],
    snapshot_height: u64,
) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let log = Signer::new([seed; 32]);
    let declaration = common::build_declaration(labeler, domain);
    let mut state = Log::new(dir.path(), Signer::new([seed; 32]), log_id);
    let mut current: std::collections::BTreeMap<
        (String, String, String),
        wist_core::label::SealedLabel,
    > = std::collections::BTreeMap::new();
    for (height, epoch) in epochs.iter().enumerate() {
        let height = height as u64;
        let wrapped: Vec<Value> = epoch
            .labels
            .iter()
            .map(|inner| label_entry(labeler, inner.clone()).1)
            .collect();
        state.seal(epoch.sealed_at, &wrapped);
        for inner in &epoch.labels {
            let label: wist_core::objects::Label = serde_json::from_value(inner.clone()).unwrap();
            let triple = (
                label.labeler.clone(),
                label.subject.clone(),
                label.name.clone(),
            );
            let newer = current.get(&triple).is_none_or(|held| {
                wist_core::publisher_time::compare(&label.asserted_at, &held.label.asserted_at)
                    != Some(std::cmp::Ordering::Less)
            });
            if newer {
                current.insert(
                    triple,
                    wist_core::label::SealedLabel {
                        label_id: wist_core::label::label_id(inner).unwrap(),
                        label,
                        height,
                        entry_index: 0,
                    },
                );
            }
        }
        if height != snapshot_height {
            continue;
        }
        let tuples = current
            .values()
            .map(|sealed| StateEntry::Label(wist_core::label::label_tuple(sealed)))
            .collect();
        let snapshot_date = "2026-08-09";
        let snapdir = common::snapshot_dir(dir.path(), snapshot_date, height);
        let sqlite_bytes = common::write_tier0(&snapdir.join("tier0/index.sqlite"), &[]);
        let content_digest_value = common::content_digest(&[]);
        let (state_bytes, state_digest_value) = common::write_state_with(
            &snapdir.join("state.json"),
            &log,
            3600,
            &[(domain.to_string(), declaration.clone())],
            state.tree_size(),
            tuples,
            0,
        );
        write_manifest(
            &snapdir.join("manifest.json"),
            &log,
            snapshot_date,
            height,
            state.tree_size(),
            &state.root_token(),
            &content_digest_value,
            &state_bytes,
            &state_digest_value,
            &sqlite_bytes,
        );
        write_index(
            &dir.path().join("snapshots/index.json"),
            &log,
            snapshot_date,
            state.tree_size(),
            &common::manifest_url(snapshot_date, height),
            &content_digest_value,
        );
    }
    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
    (dir, base_url)
}

type CurrentRow = (
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    String,
    i64,
    Option<String>,
    Option<String>,
    i64,
);

fn synced_label_current(
    log_id: &str,
    seed: u8,
    labeler: &Signer,
    domain: &str,
    epochs: &[Epoch],
    snapshot_height: u64,
    subject: &str,
) -> (Vec<CurrentRow>, usize) {
    let (dir, base_url) = serve_log(log_id, seed, labeler, domain, epochs, snapshot_height);
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        dir.path().join("log/anchor.json").to_str().unwrap(),
        &base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    let log_dir = graven::registry::log_dir(target.path(), log_id);
    common::assert_records_materialized(&log_dir);
    let conn = rusqlite::Connection::open(log_dir.join("index.sqlite")).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT labeler, subject, name, label_id, value, asserted_at, retracted, expires_at, delta, height FROM label_current ORDER BY labeler, subject, name",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<CurrentRow>>>()
        .unwrap();
    let head_sealed_at = epochs.last().unwrap().sealed_at;
    let applying = Store::open(&log_dir)
        .unwrap()
        .current_labels(subject, Some(head_sealed_at))
        .unwrap()
        .len();
    (rows, applying)
}

fn spam_label(domain: &str, subject: &str, asserted_at: &str) -> Value {
    json!({"wist_version": "1.0.0", "labeler": domain, "subject": subject, "name": "wist:spam", "asserted_at": asserted_at})
}

/// WIST-3 §7 and §8 step 4, WIST-2 §3.3.
#[test]
fn a_resumed_retraction_stays_current_against_an_earlier_label_sealed_above_the_snapshot() {
    let domain = "retracting.example";
    let subject = "https://victim.example/retracted";
    let labeler = Signer::new([60u8; 32]);
    let retraction = json!({"wist_version": "1.0.0", "labeler": domain, "subject": subject, "name": "wist:spam", "asserted_at": "2026-08-09T02:00:00Z", "retracted": true});
    let epochs = [
        Epoch {
            sealed_at: "2026-08-09T00:00:00Z",
            labels: Vec::new(),
        },
        Epoch {
            sealed_at: "2026-08-09T01:00:00Z",
            labels: vec![spam_label(domain, subject, "2026-08-09T01:00:00Z")],
        },
        Epoch {
            sealed_at: "2026-08-09T02:00:00Z",
            labels: vec![retraction.clone()],
        },
        Epoch {
            sealed_at: "2026-08-09T03:00:00Z",
            labels: vec![spam_label(domain, subject, "2026-08-09T01:30:00Z")],
        },
    ];
    let log_id = "resumed-retraction";
    let (replayed, replayed_applying) =
        synced_label_current(log_id, 61, &labeler, domain, &epochs, 0, subject);
    let (resumed, resumed_applying) =
        synced_label_current(log_id, 61, &labeler, domain, &epochs, 2, subject);

    let retraction_id = wist_core::label::label_id(&retraction).unwrap();
    assert_eq!(resumed.len(), 1, "{resumed:?}");
    assert_eq!(resumed[0].3.as_deref(), Some(retraction_id.as_str()));
    assert_eq!(resumed[0].5, "2026-08-09T02:00:00Z");
    assert_eq!(
        resumed[0].6, 1,
        "the adopted retraction must stay retracted"
    );
    assert_eq!(resumed[0].9, 2);
    assert_eq!(resumed, replayed, "resume and full replay must agree");
    assert_eq!(resumed_applying, 0);
    assert_eq!(replayed_applying, 0);
}

/// WIST-3 §7 and §8 step 4, WIST-2 §3.3.
#[test]
fn a_resumed_expired_label_stays_current_against_an_earlier_label_sealed_above_the_snapshot() {
    let domain = "expiring.example";
    let subject = "https://victim.example/expired";
    let labeler = Signer::new([62u8; 32]);
    let expiring = json!({"wist_version": "1.0.0", "labeler": domain, "subject": subject, "name": "wist:spam", "asserted_at": "2026-08-09T01:00:00Z", "expires_at": "2026-08-09T01:30:00Z"});
    let epochs = [
        Epoch {
            sealed_at: "2026-08-09T00:00:00Z",
            labels: Vec::new(),
        },
        Epoch {
            sealed_at: "2026-08-09T01:00:00Z",
            labels: vec![expiring.clone()],
        },
        Epoch {
            sealed_at: "2026-08-09T02:00:00Z",
            labels: Vec::new(),
        },
        Epoch {
            sealed_at: "2026-08-09T03:00:00Z",
            labels: vec![spam_label(domain, subject, "2026-08-09T00:30:00Z")],
        },
    ];
    let log_id = "resumed-expiry";
    let (replayed, replayed_applying) =
        synced_label_current(log_id, 63, &labeler, domain, &epochs, 0, subject);
    let (resumed, resumed_applying) =
        synced_label_current(log_id, 63, &labeler, domain, &epochs, 2, subject);

    let expiring_id = wist_core::label::label_id(&expiring).unwrap();
    assert_eq!(resumed.len(), 1, "{resumed:?}");
    assert_eq!(resumed[0].3.as_deref(), Some(expiring_id.as_str()));
    assert_eq!(resumed[0].6, 0);
    assert_eq!(resumed[0].7.as_deref(), Some("2026-08-09T01:30:00Z"));
    assert_eq!(resumed[0].9, 1);
    assert_eq!(resumed, replayed, "resume and full replay must agree");
    assert_eq!(resumed_applying, 0, "the expired Label applies nothing");
    assert_eq!(replayed_applying, 0);
}
