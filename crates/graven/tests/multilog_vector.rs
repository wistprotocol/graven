mod common;

use common::served_log::{leaf_of, parameter_map, vector, ServedLog, VectorEpoch};
use graven::store::{HeldState, MultiStore};
use serde_json::{json, Value};
use std::path::Path;
use wist_core::crypto::hex_decode;
use wist_core::objects::{
    AggregatorKeyEntry, DeclarationEntry, ParameterEntry, RemovalEntry, StateEntry,
};

fn state_json(state: Option<&HeldState>) -> Value {
    match state {
        None => Value::Null,
        Some(HeldState::Record(record)) => json!({
            "state": "record",
            "item": record.item_id,
            "collection": record.collection,
            "catalog": record.catalog,
            "generated_at": record.generated_at,
        }),
        Some(HeldState::Removed(removal)) => json!({
            "state": "removed",
            "item": removal.item_id,
            "catalog": removal.catalog,
            "generated_at": removal.generated_at,
        }),
    }
}

fn combined_json(store: &MultiStore, publisher: &str, url: &str) -> Value {
    match store.combined_state(publisher, url).unwrap() {
        None => Value::Null,
        Some((state, logs)) => json!({"state": state_json(Some(&state)), "logs": logs}),
    }
}

fn log_states_json(store: &MultiStore, publisher: &str, url: &str) -> Value {
    Value::Object(
        store
            .url_states(publisher, url)
            .unwrap()
            .into_iter()
            .map(|(log_id, state)| (log_id, state_json(state.as_ref())))
            .collect(),
    )
}

fn provenance(hit: &graven::store::MergedHit) -> Vec<&str> {
    hit.provenance.iter().map(|p| p.log_id.as_str()).collect()
}

fn serve_payloads(dir: &Path, payloads: &Value) {
    for (item_id, payload) in payloads.as_object().unwrap() {
        common::write_payload(dir, &item_id["sha256:".len()..], payload);
    }
}

#[test]
fn catalog_order_cases_order_catalogs_by_instant_then_catalog_id() {
    let vector = vector("multilog/catalog-order.json");
    for case in vector["order_cases"].as_array().unwrap() {
        assert_eq!(
            json!(
                wist_core::several_logs::in_catalog_order(case["catalogs"].as_array().unwrap())
                    .unwrap()
            ),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn catalog_order_combined_cases_walked_into_one_index_take_the_latest_state() {
    let vector = vector("multilog/catalog-order.json");
    let mut cases = 0;
    for case in vector["combined_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let publisher = case["publisher"].as_str().unwrap();
        let url = case["url"].as_str().unwrap();
        let target = tempfile::tempdir().unwrap();
        let mut served = Vec::new();
        for log in case["logs"].as_array().unwrap() {
            let log_id = log["name"].as_str().unwrap();
            let mut held = ServedLog::new(&vector["keys"]["log"], log_id);
            serve_payloads(held.dir.path(), &vector["payloads"]);
            for (epoch, result) in log["epochs"]
                .as_array()
                .unwrap()
                .iter()
                .zip(log["results"].as_array().unwrap())
            {
                let height = held.seal(VectorEpoch {
                    sealed_at: epoch["sealed_at"].as_str().unwrap().to_owned(),
                    parameters: parameter_map(&epoch["parameters"]),
                    leaves: epoch["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(leaf_of)
                        .collect(),
                });
                assert_eq!(result["status"], "accepted", "{name}: {log_id} at {height}");
                if height == 0 {
                    held.install(target.path());
                } else {
                    held.amend(target.path());
                    assert_eq!(
                        held.sync(target.path()),
                        Ok(height),
                        "{name}: {log_id} at {height}"
                    );
                }
            }
            served.push(held);
        }

        let store = MultiStore::open_read_only(target.path()).unwrap();
        assert_eq!(store.logs().len(), served.len(), "{name}");
        let expected = &case["expected"];
        assert_eq!(
            log_states_json(&store, publisher, url),
            expected["log_states"],
            "{name}: each Log's state"
        );
        assert_eq!(
            combined_json(&store, publisher, url),
            expected["combined"],
            "{name}: the combined state"
        );

        let record = store.get(url).unwrap();
        match &expected["combined"]["state"]["state"] {
            Value::String(state) if state == "record" => {
                let record = record.unwrap_or_else(|| panic!("{name}: a record"));
                assert_eq!(
                    record.item_id, expected["combined"]["state"]["item"],
                    "{name}"
                );
                assert_eq!(
                    json!(provenance(&record)),
                    expected["combined"]["logs"],
                    "{name}: held by the Logs holding the combined state"
                );
                let title = &vector["payloads"][&record.item_id]["content"]["summary"]["title"];
                assert_eq!(json!(record.title), *title, "{name}: content of its Item");
                let hits = store.search(title.as_str().unwrap(), 10).unwrap();
                assert_eq!(hits.len(), 1, "{name}");
                assert_eq!(hits[0].item_id, record.item_id, "{name}");
            }
            _ => assert!(record.is_none(), "{name}: no record"),
        }

        if let Some(snapshot) = expected.get("snapshot") {
            let log_id = snapshot["log"].as_str().unwrap();
            let held = served.iter().find(|log| log.log_id == log_id).unwrap();
            let removals: Vec<Value> = common::state_tuples(&held.log_dir(target.path()))
                .into_iter()
                .filter_map(|tuple| match serde_json::from_value(tuple).unwrap() {
                    StateEntry::Removal(RemovalEntry {
                        publisher,
                        url,
                        item_id,
                        catalog_id,
                        generated_at,
                    }) => Some(json!({
                        "publisher": publisher,
                        "url": url,
                        "item": item_id,
                        "catalog": catalog_id,
                        "generated_at": generated_at,
                    })),
                    _ => None,
                })
                .collect();
            assert_eq!(
                json!(removals),
                snapshot["removals"],
                "{name}: the removal states a Snapshot of {log_id} carries"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 15);
}

struct DedupLog {
    _dir: tempfile::TempDir,
    anchor_path: std::path::PathBuf,
    base_url: String,
}

fn dedup_log(vector: &Value, log: &Value) -> DedupLog {
    let dir = tempfile::tempdir().unwrap();
    let anchor_path = dir.path().join("log/anchor.json");
    std::fs::create_dir_all(anchor_path.parent().unwrap()).unwrap();
    std::fs::write(&anchor_path, serde_json::to_vec(&log["anchor"]).unwrap()).unwrap();

    let seed: [u8; 32] = hex_decode(log["genesis_seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let log_id = log["log_id"].as_str().unwrap();
    let mut published = common::Log::empty(dir.path(), common::Signer::new(seed), log_id);
    for epoch in log["epochs"].as_array().unwrap() {
        let entries = epoch["entries"].as_array().cloned().unwrap_or_default();
        published.adopt(epoch["checkpoint"].as_str().unwrap(), &entries);
    }
    assert_eq!(published.tree_size(), log["tree_size"].as_u64().unwrap());

    common::write_payload(
        dir.path(),
        &vector["item_id"].as_str().unwrap()["sha256:".len()..],
        &vector["payload"],
    );

    let genesis = &log["anchor"]["anchor"]["genesis_key"];
    let key_id = genesis["key_id"].as_str().unwrap();
    let declaration = &vector["publisher_declaration"];
    let genesis_checkpoint = &published.checkpoints[0];
    common::write_snapshot(
        dir.path(),
        &common::SnapshotParts {
            signer: &common::Signer::new(seed),
            key_id,
            snapshot_date: "2026-08-02",
            checkpoint: genesis_checkpoint,
            entries: vec![
                StateEntry::AggregatorKey(AggregatorKeyEntry {
                    key_id: key_id.into(),
                    public_key: genesis["public_key"].as_str().unwrap().into(),
                    added_height: 0,
                    removed_height: None,
                    adding_act: None,
                    removing_act: None,
                }),
                StateEntry::Parameter(ParameterEntry {
                    name: "epoch_cadence_seconds".into(),
                    effective_at: genesis_checkpoint.sealed_at().into(),
                    value: 3600,
                }),
                StateEntry::Declaration(DeclarationEntry {
                    domain: declaration["publisher"]["domain"].as_str().unwrap().into(),
                    declaration: declaration.clone(),
                    sealing_height: 0,
                    highest_accepted_seq: declaration["publisher"]["seq"].as_u64().unwrap(),
                }),
            ],
            records: &[],
            extracts: Vec::new(),
            links: Vec::new(),
            tier1: false,
            shards: None,
        },
    );

    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
    DedupLog {
        _dir: dir,
        anchor_path,
        base_url,
    }
}

#[test]
fn dedup_vector_logs_sealing_one_item_combine_into_one_record_held_by_both() {
    let vector = vector("multilog/dedup.json");
    let logs = vector["logs"].as_array().unwrap();
    let served: Vec<DedupLog> = logs.iter().map(|log| dedup_log(&vector, log)).collect();

    let target = tempfile::tempdir().unwrap();
    for (log, held) in logs.iter().zip(&served) {
        graven::sync::run(
            held.anchor_path.to_str().unwrap(),
            &held.base_url,
            target.path(),
            true,
            false,
        )
        .unwrap();
        let log_dir = graven::registry::log_dir(target.path(), log["log_id"].as_str().unwrap());
        common::assert_records_materialized(&log_dir);
    }

    let store = MultiStore::open_read_only(target.path()).unwrap();
    assert_eq!(store.logs().len(), logs.len());
    let item = &vector["item"];
    let publisher = item["publisher"].as_str().unwrap();
    let url = item["url"].as_str().unwrap();
    let expected = &vector["expected"];
    assert_eq!(
        log_states_json(&store, publisher, url),
        expected["log_states"]
    );
    assert_eq!(combined_json(&store, publisher, url), expected["combined"]);

    let record = store.get(url).unwrap().expect("the combined record");
    assert_eq!(record.publisher, publisher);
    assert_eq!(record.item_id, vector["item_id"].as_str().unwrap());
    assert_eq!(record.collection.as_deref(), Some("default"));
    assert_eq!(
        json!(record.generated_at),
        expected["combined"]["state"]["generated_at"]
    );
    assert_eq!(
        json!(record.title),
        vector["payload"]["content"]["summary"]["title"]
    );
    assert_eq!(json!(provenance(&record)), expected["combined"]["logs"]);

    let hits = store.search("Shared Post", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(json!(provenance(&hits[0])), expected["combined"]["logs"]);
}
