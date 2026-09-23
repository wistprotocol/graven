//! WIST-3 §3.4, §5 and §7. The vector publishes no private key, so no Snapshot can be signed and
//! each history is installed at its Epoch 0.
mod common;

use graven::fetch::Client;
use graven::sync::source::Sources;
use graven::sync::{checkpoints, tree, SyncState, Tree};
use rusqlite::Connection;
use serde_json::Value;
use std::path::{Path, PathBuf};
use wist_core::objects::{AggregatorKeyEntry, StateEntry};

const CREATE_DECLARATION_STATE: &str =
    "CREATE TABLE IF NOT EXISTS declaration_state(id INTEGER PRIMARY KEY CHECK(id = 1), state TEXT NOT NULL)";

fn spec_dir() -> PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
}

fn read_json(rel: &str) -> Value {
    let path = spec_dir().join(rel);
    serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn histories() -> Vec<Value> {
    read_json("vectors/wist3/aggregator-keys.json")["histories"]
        .as_array()
        .unwrap()
        .clone()
}

fn key_entries(state: &Value) -> Vec<AggregatorKeyEntry> {
    state
        .as_array()
        .unwrap()
        .iter()
        .filter(|tuple| tuple[0] == "aggregator_key")
        .map(
            |tuple| match serde_json::from_value(tuple.clone()).unwrap() {
                StateEntry::AggregatorKey(entry) => entry,
                other => panic!("{other:?} is not an aggregator_key tuple"),
            },
        )
        .collect()
}

type Row = (
    String,
    String,
    u64,
    Option<u64>,
    Option<String>,
    Option<String>,
);

fn canonical(act: &Option<Value>) -> Option<String> {
    act.as_ref()
        .map(|act| String::from_utf8(wist_core::jcs::canonicalize(act).unwrap()).unwrap())
}

fn rows(entries: &[AggregatorKeyEntry]) -> Vec<Row> {
    let mut rows: Vec<Row> = entries
        .iter()
        .map(|entry| {
            (
                entry.key_id.clone(),
                entry.public_key.clone(),
                entry.added_height,
                entry.removed_height,
                canonical(&entry.adding_act),
                canonical(&entry.removing_act),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn stored_rows(target: &Path, log_id: &str) -> Vec<Row> {
    let index = graven::registry::log_dir(target, log_id).join("index.sqlite");
    let conn = Connection::open(index).expect("the store carries an index");
    let mut stmt = conn
        .prepare("SELECT key_id, public_key, added_height, removed_height, adding_act, removing_act FROM aggregator_keys")
        .unwrap();
    let stored_act = |text: Option<String>| {
        canonical(&text.map(|text| serde_json::from_str::<Value>(&text).unwrap()))
    };
    let mut rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?.max(0) as u64,
                row.get::<_, Option<i64>>(3)?
                    .map(|height| height.max(0) as u64),
                stored_act(row.get::<_, Option<String>>(4)?),
                stored_act(row.get::<_, Option<String>>(5)?),
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    rows.sort();
    rows
}

struct ServedHistory {
    dir: tempfile::TempDir,
    log: common::Log,
    log_id: String,
    base_url: String,
    anchor_path: PathBuf,
}

fn serve(history: &Value, through: usize, note: Option<&str>) -> ServedHistory {
    let dir = tempfile::tempdir().unwrap();
    let log_id = history["log_id"].as_str().unwrap().to_string();
    let anchor_path = dir.path().join("log/anchor.json");
    std::fs::create_dir_all(anchor_path.parent().unwrap()).unwrap();
    std::fs::write(
        &anchor_path,
        serde_json::to_vec(&history["anchor"]).unwrap(),
    )
    .unwrap();

    let mut log = common::Log::empty(dir.path(), common::Signer::new([0u8; 32]), &log_id);
    let epochs = history["epochs"].as_array().unwrap();
    for (index, epoch) in epochs[..through].iter().enumerate() {
        let published = match (index + 1 == through, note) {
            (true, Some(note)) => note,
            _ => epoch["checkpoint"]
                .as_str()
                .expect("the Epoch carries a Checkpoint"),
        };
        log.adopt(published, epoch["entries"].as_array().unwrap());
    }
    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
    ServedHistory {
        dir,
        log,
        log_id,
        base_url,
        anchor_path,
    }
}

fn install_at_epoch_0(served: &ServedHistory, target: &Path, history: &Value) {
    let checkpoint = served.log.checkpoints[0].clone();
    let log_dir = graven::registry::log_dir(target, &served.log_id);
    std::fs::create_dir_all(&log_dir).unwrap();
    let index = log_dir.join("index.sqlite");
    common::write_tier0(&index, &[]);
    let conn = Connection::open(&index).unwrap();
    conn.execute_batch(graven::sync::CREATE_SYNC_STATE).unwrap();
    conn.execute_batch(graven::sync::CREATE_CHECKPOINTS)
        .unwrap();
    conn.execute_batch(graven::store::CREATE_AGGREGATOR_KEYS)
        .unwrap();
    conn.execute_batch(CREATE_DECLARATION_STATE).unwrap();
    for entry in key_entries(&history["epochs"][0]["expected_state"]) {
        let act = |act: &Option<Value>| act.as_ref().map(|act| serde_json::to_string(act).unwrap());
        conn.execute(
            "INSERT INTO aggregator_keys(key_id, public_key, added_height, removed_height, adding_act, removing_act) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                &entry.key_id,
                &entry.public_key,
                entry.added_height as i64,
                entry.removed_height.map(|height| height as i64),
                act(&entry.adding_act),
                act(&entry.removing_act),
            ),
        )
        .unwrap();
    }
    let mut keys = graven::keyset::KeyHistory::new();
    keys.seed_head(
        checkpoint.epoch_number(),
        &checkpoint.root_token(),
        Some(checkpoint.sealed_at_s().unwrap()),
    );
    conn.execute(
        "INSERT INTO declaration_state(id, state) VALUES (1, ?1)",
        [keys.state().unwrap()],
    )
    .unwrap();
    checkpoints::save_checkpoint(&conn, &checkpoint, Some(true)).unwrap();
    graven::sync::save_sync_state(
        &conn,
        &SyncState {
            format: graven::sync::SYNC_STATE_FORMAT,
            tree_size: checkpoint.tree_size(),
            epoch_number: checkpoint.epoch_number(),
            root: checkpoint.root_token(),
            unwitnessed: true,
            content_digest: None,
            schedule_first_s: None,
            prior_sealed_at_s: Some(checkpoint.sealed_at_s().unwrap()),
            largest_epoch_bytes: 0,
        },
    )
    .unwrap();

    let client = Client::new(true);
    let sources = Sources::new(
        &client,
        vec![graven::fetch::parse_base(&served.base_url).unwrap()],
    );
    let mut tree = Tree::new();
    tree::seed(
        &sources,
        &mut tree,
        checkpoint.tree_size(),
        checkpoint.root(),
    )
    .unwrap();
    tree.save(&conn).unwrap();
}

fn stored_amendments(target: &Path, log_id: &str) -> Vec<(String, i64, u64)> {
    let index = graven::registry::log_dir(target, log_id).join("index.sqlite");
    let conn = Connection::open(index).unwrap();
    let mut stmt = conn
        .prepare("SELECT parameter, value, epoch_number FROM parameters")
        .unwrap();
    let mut rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?.max(0) as u64,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    rows.sort();
    rows
}

/// WIST-4 §5.1: `WIST4-E11` changes nothing.
fn accepted_amendments(history: &Value, through: usize) -> Vec<(String, i64, u64)> {
    let mut accepted = Vec::new();
    for epoch in history["epochs"].as_array().unwrap()[1..through].iter() {
        for act in epoch["acts"].as_array().unwrap() {
            let index = act["entry_index"].as_u64().unwrap() as usize;
            let update = &epoch["entries"][index]["body"]["update"];
            if act["action"] == "parameter_change" && act["code"].is_null() {
                accepted.push((
                    act["subject"].as_str().unwrap().to_string(),
                    update["details"]["value"].as_i64().unwrap(),
                    epoch["epoch_number"].as_u64().unwrap(),
                ));
            }
        }
    }
    accepted.sort();
    accepted
}

fn sync(served: &ServedHistory, target: &Path) -> Result<graven::sync::SyncReport, graven::Error> {
    graven::sync::run(
        served.anchor_path.to_str().unwrap(),
        &served.base_url,
        target,
        true,
        false,
    )
}

fn applied_epochs(history: &Value) -> usize {
    history["epochs"]
        .as_array()
        .unwrap()
        .iter()
        .take_while(|epoch| epoch["applied"].as_bool().unwrap())
        .count()
}

fn head_state(history: &Value) -> Value {
    history["epochs"].as_array().unwrap()[applied_epochs(history) - 1]["expected_state"].clone()
}

#[test]
fn each_history_walks_to_its_verified_head_and_persists_the_tuples_the_vector_records() {
    for history in histories() {
        let name = history["name"].as_str().unwrap();
        let served = serve(&history, applied_epochs(&history), None);
        let target = tempfile::tempdir().unwrap();
        install_at_epoch_0(&served, target.path(), &history);
        let report = sync(&served, target.path()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            Some(report.head),
            history["verified_head"].as_u64(),
            "{name}: the head the walk adopts"
        );
        assert_eq!(
            stored_rows(target.path(), &served.log_id),
            rows(&key_entries(&head_state(&history))),
            "{name}: the aggregator_key records the store keeps"
        );
        assert_eq!(
            stored_amendments(target.path(), &served.log_id),
            accepted_amendments(&history, applied_epochs(&history)),
            "{name}: the amendments the walked Epochs leave accepted"
        );
        drop(served.dir);
    }
}

#[test]
fn a_checkpoint_no_key_valid_at_its_epoch_signs_leaves_the_head_where_it_was() {
    let mut refused = 0;
    let mut adopted = 0;
    for history in histories() {
        let name = history["name"].as_str().unwrap();
        for (index, epoch) in history["epochs"].as_array().unwrap().iter().enumerate() {
            // Core's conformance tests judge Epoch 0 candidates directly.
            if index == 0 {
                continue;
            }
            for case in epoch["checkpoint_cases"].as_array().unwrap() {
                let case_name = case["name"].as_str().unwrap();
                let note = case["checkpoint"].as_str().unwrap();
                let mut served = serve(&history, index, None);
                let target = tempfile::tempdir().unwrap();
                install_at_epoch_0(&served, target.path(), &history);
                let kept = history["epochs"].as_array().unwrap()[index - 1].clone();
                assert_eq!(
                    sync(&served, target.path()).unwrap().head,
                    kept["epoch_number"].as_u64().unwrap(),
                    "{name}: {case_name}: the Epochs below the candidate"
                );
                served.log.adopt(note, epoch["entries"].as_array().unwrap());
                let outcome = sync(&served, target.path());
                match case["expected"].as_str().unwrap() {
                    "valid" => {
                        let report = outcome.unwrap_or_else(|e| panic!("{name}: {case_name}: {e}"));
                        assert_eq!(report.head, index as u64, "{name}: {case_name}");
                        assert_eq!(
                            stored_rows(target.path(), &served.log_id),
                            rows(&key_entries(&epoch["expected_state"])),
                            "{name}: {case_name}"
                        );
                        adopted += 1;
                    }
                    "WIST3-E03" => {
                        let error = outcome.err().map(|e| e.to_string()).unwrap_or_default();
                        assert!(error.contains("WIST3-E03"), "{name}: {case_name}: {error}");
                        assert_eq!(
                            graven::store::synced_state(&graven::registry::log_dir(
                                target.path(),
                                &served.log_id
                            ))
                            .unwrap()
                            .epoch_number,
                            kept["epoch_number"].as_u64().unwrap(),
                            "{name}: {case_name}: the verified head stands"
                        );
                        assert_eq!(
                            stored_rows(target.path(), &served.log_id),
                            rows(&key_entries(&kept["expected_state"])),
                            "{name}: {case_name}: the Epoch changes no key registry state"
                        );
                        refused += 1;
                    }
                    other => panic!("{name}: {case_name}: unknown expectation {other}"),
                }
                drop(served.dir);
            }
        }
    }
    assert!(
        refused >= 3 && adopted >= 2,
        "{refused} refused, {adopted} adopted"
    );
}

#[test]
fn an_epoch_no_checkpoint_verifies_is_never_applied() {
    let history = histories()
        .into_iter()
        .find(|history| {
            history["epochs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|epoch| !epoch["applied"].as_bool().unwrap())
        })
        .expect("the vector carries an Epoch no Checkpoint verifies");
    let epochs = history["epochs"].as_array().unwrap();
    let index = epochs
        .iter()
        .position(|epoch| !epoch["applied"].as_bool().unwrap())
        .unwrap();
    assert!(epochs[index]["checkpoint"].is_null());
    for case in epochs[index]["checkpoint_cases"].as_array().unwrap() {
        assert_eq!(case["expected"], "WIST3-E03");
    }

    let served = serve(&history, index, None);
    let target = tempfile::tempdir().unwrap();
    install_at_epoch_0(&served, target.path(), &history);
    let report = sync(&served, target.path()).unwrap();
    assert_eq!(
        report.head,
        epochs[index - 1]["epoch_number"].as_u64().unwrap()
    );
    assert_eq!(
        stored_rows(target.path(), &served.log_id),
        rows(&key_entries(&epochs[index]["expected_state"])),
        "the refused Epoch leaves the tuples the Epoch below it left"
    );
}

#[test]
fn a_checkpoint_below_the_head_is_evidence_only_under_the_keys_valid_at_its_own_epoch() {
    let mut seen = std::collections::BTreeSet::new();
    for history in histories() {
        let name = history["name"].as_str().unwrap();
        let Some(cases) = history["equivocation_cases"].as_array() else {
            continue;
        };
        for case in cases {
            let case_name = case["name"].as_str().unwrap();
            let served = serve(&history, applied_epochs(&history), None);
            let target = tempfile::tempdir().unwrap();
            install_at_epoch_0(&served, target.path(), &history);
            assert_eq!(
                Some(sync(&served, target.path()).unwrap().head),
                history["verified_head"].as_u64()
            );

            served
                .log
                .write_head_note(case["checkpoint"].as_str().unwrap());
            let error = sync(&served, target.path())
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            let expected = case["expected"].as_str().unwrap();
            assert!(error.contains(expected), "{name}: {case_name}: {error}");
            let log_dir = graven::registry::log_dir(target.path(), &served.log_id);
            assert_eq!(
                graven::store::synced_state(&log_dir).unwrap().epoch_number,
                history["verified_head"].as_u64().unwrap(),
                "{name}: {case_name}: the verified head stands"
            );
            let bundle = log_dir.join(format!(
                "evidence/equivocation-epoch-{:09}",
                case["epoch_number"].as_u64().unwrap()
            ));
            assert_eq!(
                bundle.exists(),
                expected == "WIST3-E02",
                "{name}: {case_name}: {}",
                case["why"]
            );
            assert_eq!(
                checkpoints::halt(&log_dir).is_some(),
                expected == "WIST3-E02",
                "{name}: {case_name}: the halt follows the evidence"
            );
            if expected == "WIST3-E02" {
                assert_eq!(
                    std::fs::read_to_string(bundle.join("offered.checkpoint")).unwrap(),
                    case["checkpoint"].as_str().unwrap()
                );
            }
            seen.insert(expected.to_string());
            drop(served.dir);
        }
    }
    assert_eq!(
        seen,
        ["WIST3-E02".to_string(), "WIST3-E03".to_string()]
            .into_iter()
            .collect()
    );
}
