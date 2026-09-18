//! WIST-4 §6's recommended readings, applied by a profile over an index:
//! a `wist:mismatch` or `wist:unavailable` Label counts only once it has
//! persisted, and an unattended Labeler is ignored.
use graven::ranking::{load_profile, rank, DomainState, Profile};
use graven::store::RecordHit;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::BTreeSet;

fn spec_dir() -> std::path::PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
}

const LABELER: &str = "labels.example";
const SUBJECT: &str = "https://sub.example/a";

fn vector(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(spec_dir().join(format!("vectors/{name}.json"))).unwrap())
        .unwrap()
}

fn index(events: &[Value], expires_at: Option<&str>, last_sealed_height: u64) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(graven::store::CREATE_LABELS).unwrap();
    conn.execute_batch(graven::store::CREATE_RANKING).unwrap();
    let mut current: Option<&Value> = None;
    for (index, event) in events.iter().enumerate() {
        let retracted = i64::from(event["retracted"].as_bool().unwrap());
        conn.execute(
            "INSERT INTO labels(label_id, labeler, subject, name, value, asserted_at, retracted, expires_at, delta, height, entry_index) \
             VALUES (?1, ?2, ?3, 'wist:mismatch', NULL, ?4, ?5, ?6, NULL, ?7, 0)",
            (
                format!("sha256:{index:064x}"),
                LABELER,
                SUBJECT,
                event["asserted_at"].as_str().unwrap(),
                retracted,
                expires_at,
                event["height"].as_i64().unwrap(),
            ),
        )
        .unwrap();
        current = Some(event);
    }
    if let Some(event) = current {
        conn.execute(
            "INSERT INTO label_current(labeler, subject, name, label_id, value, asserted_at, retracted, expires_at, delta, height, entry_index) \
             VALUES (?1, ?2, 'wist:mismatch', NULL, NULL, ?3, ?4, ?5, NULL, ?6, 0)",
            (
                LABELER,
                SUBJECT,
                event["asserted_at"].as_str().unwrap(),
                i64::from(event["retracted"].as_bool().unwrap()),
                expires_at,
                event["height"].as_i64().unwrap(),
            ),
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO labelers(labeler, label_count, retraction_count, first_seen_height, last_sealed_height) VALUES (?1, 1, 0, 0, ?2)",
        (LABELER, last_sealed_height as i64),
    )
    .unwrap();
    conn
}

fn subscribed() -> BTreeSet<String> {
    BTreeSet::from([LABELER.to_string()])
}

fn hit() -> RecordHit {
    RecordHit {
        url: SUBJECT.to_string(),
        publisher: "sub.example".to_string(),
        delta_id: format!("sha256:{:064x}", 1),
        observed_at: "2026-08-02T12:00:00Z".to_string(),
        title: "A".to_string(),
        r#abstract: None,
    }
}

fn mismatch_at(
    conn: &Connection,
    profile: &Profile,
    height: u64,
    head_sealed_at: Option<&str>,
) -> bool {
    let state = DomainState::derive(conn, profile, &subscribed(), height, head_sealed_at).unwrap();
    let ranked = rank(conn, profile, &state, vec![(hit(), 1.0)]).unwrap();
    assert_eq!(ranked.len(), 1);
    ranked[0].signals.mismatch
}

#[test]
fn the_default_profile_counts_a_mismatch_label_only_once_it_has_persisted() {
    let profile = load_profile(std::path::Path::new("/nonexistent"), "default").unwrap();
    assert_eq!(profile.readings.persistence_epochs, 2);
    let vector = vector("wist3/label-tables");
    let mut cases = 0;
    for case in vector["persistence_cases"].as_array().unwrap() {
        let events = case["events"].as_array().unwrap();
        // The vector's expiry height is the first height at which the Epoch
        // instant reaches the expiry; the index reads it from the head's
        // instant, so an expiring case is probed against that boundary.
        let expiry = case["expires_at_height"].as_u64();
        for probe in case["probes"].as_array().unwrap() {
            let height = probe["height"].as_u64().unwrap();
            let expired = expiry.is_some_and(|expiry| height >= expiry);
            let conn = index(events, expired.then_some("2026-08-02T12:00:00Z"), height);
            let head_sealed_at = expired.then_some("2027-01-01T00:00:00Z");
            assert_eq!(
                mismatch_at(&conn, &profile, height, head_sealed_at),
                probe["counted"].as_bool().unwrap(),
                "{} at height {height}",
                case["label"]
            );
            cases += 1;
        }
    }
    let expected: usize = vector["persistence_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["probes"].as_array().unwrap().len())
        .sum();
    assert_eq!(cases, expected, "every probe in the vector is exercised");
}

#[test]
fn a_profile_ignores_a_labeler_that_has_sealed_nothing_within_its_window() {
    let vector = vector("wist3/label-tables");
    let persisted = serde_json::json!([
        {"height": 0, "asserted_at": "2026-08-02T12:00:00Z", "retracted": false}
    ]);
    let events = persisted.as_array().unwrap();
    let mut cases = 0;
    for case in vector["inactivity_cases"].as_array().unwrap() {
        let mut profile = load_profile(std::path::Path::new("/nonexistent"), "default").unwrap();
        profile.readings.labeler_inactive_epochs = case["inactivity_epochs"].as_u64().unwrap();
        let conn = index(events, None, case["last_sealed_height"].as_u64().unwrap());
        assert_eq!(
            mismatch_at(&conn, &profile, case["height"].as_u64().unwrap(), None),
            case["applies"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn a_label_an_index_holds_only_as_a_snapshot_tuple_still_counts() {
    let profile = load_profile(std::path::Path::new("/nonexistent"), "default").unwrap();
    let events = serde_json::json!([
        {"height": 4000, "asserted_at": "2026-08-02T12:00:00Z", "retracted": false}
    ]);
    // The Labeler has sealed something recently, so the inactivity rule
    // leaves it in the profile's set.
    let conn = index(events.as_array().unwrap(), None, 4900);
    // A Consumer that resumed from a Snapshot holds the tuple and none of
    // the history behind it (WIST-3 §7).
    conn.execute("DELETE FROM labels", []).unwrap();
    assert!(
        mismatch_at(&conn, &profile, 5000, None),
        "a Label sealed below the Snapshot was live at the head and the Epoch before it"
    );
    assert!(
        !mismatch_at(&conn, &profile, 4000, None),
        "the Epoch that sealed it is still its first"
    );
}

#[test]
fn a_counted_mismatch_lowers_the_score_and_says_so() {
    let profile = load_profile(std::path::Path::new("/nonexistent"), "default").unwrap();
    let events = serde_json::json!([
        {"height": 1, "asserted_at": "2026-08-02T12:00:00Z", "retracted": false}
    ]);
    let conn = index(events.as_array().unwrap(), None, 5);
    let state = DomainState::derive(&conn, &profile, &subscribed(), 5, None).unwrap();
    let ranked = rank(&conn, &profile, &state, vec![(hit(), 1.0)]).unwrap();
    assert!(ranked[0].signals.mismatch);
    assert!(
        ranked[0].score < 1.0 * (profile.weights.trust_floor + 1.0) + f64::EPSILON,
        "{:?}",
        ranked[0]
    );
    assert!(
        ranked[0]
            .explanation
            .iter()
            .any(|line| line.contains("mismatch or unavailable Label counted")),
        "{:?}",
        ranked[0].explanation
    );
    let text_only = load_profile(std::path::Path::new("/nonexistent"), "text-only").unwrap();
    assert_eq!(text_only.weights.mismatch, 0.0);
}
