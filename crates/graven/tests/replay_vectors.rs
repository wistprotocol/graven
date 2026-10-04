mod common;

use common::served_log::{leaf_of, parameter_map, signer_of, vector, ServedLog, VectorEpoch};

use graven::keyset::KeyHistory;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use wist_core::envelope::sign_envelope;
use wist_core::objects::{AggregatorKeyEntry, ParameterEntry, StateEntry};
use wist_core::timestamp::log_seconds;

impl ServedLog {
    fn snapshot(&self, height: u64, date: &str, mut tuples: Vec<StateEntry>, held: &Held) {
        let at = |seconds: i64| wist_core::timestamp::instant(seconds).unwrap();
        tuples.push(StateEntry::AggregatorKey(AggregatorKeyEntry {
            key_id: self.log_key_id.clone(),
            public_key: self.log.log.public_b64u(),
            added_height: 0,
            removed_height: None,
            adding_act: None,
            removing_act: None,
        }));
        for amendment in self.amendments() {
            if amendment.epoch_number <= height {
                tuples.push(StateEntry::Parameter(ParameterEntry {
                    name: amendment.parameter,
                    effective_at: at(amendment.effective_at_s),
                    value: amendment.value,
                }));
            }
        }
        let signer = common::Signer::new(self.log.log.seed);
        common::write_snapshot(
            self.dir.path(),
            &common::SnapshotParts {
                signer: &signer,
                key_id: &self.log_key_id,
                snapshot_date: date,
                checkpoint: &self.log.checkpoints[height as usize],
                entries: tuples,
                records: &held.records,
                extracts: held.extracts.clone(),
                links: held.links.clone(),
                tier1: true,
                shards: None,
            },
        );
    }
}

fn tuples(log_dir: &Path) -> Vec<StateEntry> {
    common::state_tuples(log_dir)
        .into_iter()
        .map(|tuple| serde_json::from_value(tuple).unwrap())
        .collect()
}

fn declarations(log_dir: &Path) -> KeyHistory {
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    let state: String = conn
        .query_row(
            "SELECT state FROM declaration_state WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    KeyHistory::from_state(&state).unwrap()
}

fn rows(log_dir: &Path, query: &str, columns: &[&str]) -> Vec<Value> {
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    conn.execute_batch(graven::store::CREATE_LABELS).unwrap();
    let mut stmt = conn.prepare(query).unwrap();
    stmt.query_map([], |row| {
        let mut object = serde_json::Map::new();
        for (index, column) in columns.iter().enumerate() {
            let value = match row.get_ref(index)? {
                rusqlite::types::ValueRef::Integer(n) => json!(n),
                rusqlite::types::ValueRef::Text(text) => json!(std::str::from_utf8(text).unwrap()),
                _ => Value::Null,
            };
            object.insert((*column).to_owned(), value);
        }
        Ok(Value::Object(object))
    })
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

fn declaration_names(histories: &[Value]) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for history in histories {
        for epoch in history["epochs"].as_array().unwrap() {
            for named in epoch["entries"].as_array().unwrap() {
                if named["entry"]["type"] == "publisher_declaration" {
                    names.insert(
                        wist_core::declaration::inner_hash(&named["entry"]["body"]).unwrap(),
                        named["name"].as_str().unwrap().to_owned(),
                    );
                }
            }
        }
    }
    names
}

fn window_end(window: Option<&wist_core::declarations::RecoveryWindow>) -> Value {
    json!(window.map(|window| {
        wist_core::timestamp::instant(i64::try_from(window.end_s()).unwrap()).unwrap()
    }))
}

fn stored_sealing_state(log_dir: &Path, names: &BTreeMap<String, String>) -> Value {
    let history = declarations(log_dir);
    let declarations: Vec<Value> = history
        .declarations()
        .domains()
        .iter()
        .map(|(domain, state)| {
            json!({
                "publisher": domain,
                "current": names[state.current().hash()],
                "pending_head": state.pending().map(|pending| &names[pending.head().hash()]),
                "window_end": window_end(state.window()),
            })
        })
        .collect();
    let mut catalogs = Vec::new();
    let mut records = Vec::new();
    let mut removals = Vec::new();
    for tuple in tuples(log_dir) {
        match tuple {
            StateEntry::Collection(c) => catalogs.push(json!({
                "publisher": c.publisher,
                "collection": c.collection,
                "catalog": wist_core::catalog::catalog_id(&c.envelope["catalog"]).unwrap(),
                "floor": c.envelope["catalog"]["generated_at"],
                "sealing_height": c.sealing_height,
            })),
            StateEntry::Record(r) => records.push(json!({
                "publisher": r.publisher,
                "url": r.url,
                "item": r.item,
                "collection": r.collection,
                "catalog": r.catalog_id,
                "generated_at": r.generated_at,
            })),
            StateEntry::Removal(r) => removals.push(json!({
                "publisher": r.publisher,
                "url": r.url,
                "item": r.item_id,
                "catalog": r.catalog_id,
                "generated_at": r.generated_at,
            })),
            _ => {}
        }
    }
    json!({
        "declarations": declarations,
        "catalogs": catalogs,
        "records": records,
        "removals": removals,
        "labels": rows(
            log_dir,
            "SELECT label_id, labeler, subject, name, height FROM labels ORDER BY label_id",
            &["label", "labeler", "subject", "name", "height"],
        ),
        "disputes": rows(
            log_dir,
            "SELECT dispute_id, label_id, disputant, height FROM disputes ORDER BY dispute_id",
            &["dispute", "label", "disputant", "height"],
        ),
    })
}

// WIST-3 §7: no state tuple carries a latest Catalog's `base`.
fn without_base(state: &Value) -> Value {
    let mut state = state.clone();
    for catalog in state["catalogs"].as_array_mut().unwrap() {
        catalog.as_object_mut().unwrap().remove("base");
    }
    state
}

#[test]
fn catalog_sealing_histories_walked_by_the_consumer_hold_each_epochs_state() {
    let vector = vector("wist3/catalog-sealing.json");
    let histories = vector["histories"].as_array().unwrap();
    let names = declaration_names(histories);
    let mut walked = 0;
    let mut rejected = 0;
    let mut uninterrupted = 0;
    for history in histories {
        let name = history["name"].as_str().unwrap();
        let mut served = ServedLog::new(&vector["keys"]["log"], "sealing-vector-log");
        let target = tempfile::tempdir().unwrap();
        let log_dir = served.log_dir(target.path());
        let expected = history["expected"].as_array().unwrap();
        for (epoch, want) in history["epochs"].as_array().unwrap().iter().zip(expected) {
            let height = served.seal(VectorEpoch {
                sealed_at: epoch["sealed_at"].as_str().unwrap().to_owned(),
                parameters: parameter_map(&epoch["parameters"]),
                leaves: epoch["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(leaf_of)
                    .collect(),
            });
            if height == 0 {
                served.install(target.path());
                continue;
            }
            let label = format!("{name} at {height}");
            served.amend(target.path());
            let outcome = served.sync(target.path());
            match want["status"].as_str().unwrap() {
                "accepted" => {
                    assert_eq!(outcome, Ok(height), "{label}");
                    walked += 1;
                }
                "rejected" => {
                    assert_eq!(outcome, Ok(height), "{label}");
                    let codes = want["codes"].as_array().unwrap();
                    let reported = served.rejected(target.path());
                    assert!(
                        reported.iter().any(|epoch| epoch.epoch_number == height
                            && codes
                                .iter()
                                .any(|code| epoch.codes.iter().any(|held| held == code))),
                        "{label}: {reported:?} reports none of {codes:?}"
                    );
                    rejected += 1;
                }
                other => panic!("{label}: {other}"),
            }
            assert_eq!(
                stored_sealing_state(&log_dir, &names),
                without_base(&want["state"]),
                "{label}"
            );
        }
        if served.epochs.len() < 2 {
            continue;
        }
        let once = tempfile::tempdir().unwrap();
        served.install(once.path());
        let _ = served.sync(once.path());
        assert_eq!(
            rows(
                &served.log_dir(once.path()),
                "SELECT url, publisher, item_id, attested_at FROM records ORDER BY publisher, url",
                &["url", "publisher", "item", "attested_at"],
            ),
            rows(
                &log_dir,
                "SELECT url, publisher, item_id, attested_at FROM records ORDER BY publisher, url",
                &["url", "publisher", "item", "attested_at"],
            ),
            "{name}: one uninterrupted run materializes what a run per Epoch does"
        );
        assert_eq!(
            served.head(once.path()),
            served.head(target.path()),
            "{name}"
        );
        for read in [
            |dir: &Path| json!(common::state_tuples(dir)),
            |dir: &Path| {
                json!(rows(
                    dir,
                    "SELECT label_id, subject FROM sealed_label_ids ORDER BY label_id",
                    &["label", "subject"]
                ))
            },
            |dir: &Path| {
                json!(rows(
                    dir,
                    "SELECT item_id, publisher, kind, height FROM sealed_items ORDER BY item_id, publisher, kind",
                    &["item", "publisher", "kind", "height"]
                ))
            },
        ] {
            assert_eq!(
                read(&served.log_dir(once.path())),
                read(&log_dir),
                "{name}: one uninterrupted run holds what a run per Epoch holds"
            );
        }
        assert_eq!(
            stored_sealing_state(&served.log_dir(once.path()), &names),
            stored_sealing_state(&log_dir, &names),
            "{name}"
        );
        uninterrupted += 1;
    }
    assert!(
        walked > 100 && rejected >= 15 && uninterrupted > 50,
        "{walked} walked, {rejected} rejected, {uninterrupted} uninterrupted"
    );
}

struct Narrowing<'v> {
    envelopes: &'v serde_json::Map<String, Value>,
    keys: Vec<common::Signer>,
    names: BTreeMap<String, String>,
}

impl Narrowing<'_> {
    fn signer_for(&self, current: &str, envelope: &Value) -> &common::Signer {
        let declaration = wist_core::declaration::publisher_of(&self.envelopes[current]).unwrap();
        self.keys
            .iter()
            .find(|signer| {
                let mut signed = envelope.clone();
                signed["sig"]["key_id"] = json!(signer.kid());
                let resigned =
                    sign_envelope(&envelope["catalog"], "catalog", &signer.kid(), &signer.sk)
                        .unwrap();
                wist_core::catalog::authenticate(&resigned, &declaration).is_ok()
            })
            .unwrap_or(&self.keys[0])
    }

    fn epoch(&self, epoch: &Value, current: &str, publisher: &str) -> Vec<Vec<u8>> {
        let sealed_at = epoch["sealed_at"].as_str().unwrap();
        let mut entries: Vec<Value> = epoch["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|label| json!({"type": "publisher_declaration", "body": self.envelopes[label.as_str().unwrap()]}))
            .collect();
        let mut by_collection: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
        for record in epoch["records"].as_array().unwrap() {
            by_collection
                .entry(record["collection"].as_str().unwrap())
                .or_default()
                .push(common::page_item(
                    publisher,
                    record["url"].as_str().unwrap(),
                    sealed_at,
                ));
        }
        for (collection, items) in by_collection {
            let probe = common::publish(&self.keys[0], publisher, collection, sealed_at, &items);
            let signer = self.signer_for(current, &probe.catalog["body"]);
            let published = common::publish(signer, publisher, collection, sealed_at, &items);
            entries.push(published.catalog);
            entries.extend(published.items);
        }
        common::canonical_order(&entries)
            .iter()
            .map(|entry| wist_core::jcs::canonicalize(entry).unwrap())
            .collect()
    }

    fn stored(&self, log_dir: &Path, publisher: &str) -> Value {
        let history = declarations(log_dir);
        let state = &history.declarations().domains()[publisher];
        let live: Vec<Value> = tuples(log_dir)
            .into_iter()
            .filter_map(|tuple| match tuple {
                StateEntry::Record(r) if r.publisher == publisher => {
                    Some(json!({"url": r.url, "collection": r.collection}))
                }
                _ => None,
            })
            .collect();
        json!({
            "current_declaration": self.names[state.current().hash()],
            "pending_head": state.pending().map(|p| &self.names[p.head().hash()]),
            "activation_height": state.pending().map(|p| p.activation_height()),
            "window_end": window_end(state.window()),
            "live": sorted(live),
        })
    }
}

fn sorted(mut records: Vec<Value>) -> Vec<Value> {
    records.sort_by(|a, b| {
        (a["url"].as_str(), a["collection"].as_str())
            .cmp(&(b["url"].as_str(), b["collection"].as_str()))
    });
    records
}

#[test]
fn collection_narrowing_histories_walked_by_the_consumer_keep_the_records_each_declaration_keeps() {
    let vector = vector("wist1/collection-narrowing.json");
    let keys: Vec<common::Signer> = [
        "owner",
        "owner2",
        "recovery",
        "recovery2",
        "fresh",
        "journal",
        "journal2",
        "store",
        "store2",
        "docs",
    ]
    .iter()
    .map(|name| signer_of(&vector["keys"][name]))
    .collect();
    let log_key = json!({
        "seed_hex": "77".repeat(32),
        "x": common::Signer::new([0x77; 32]).public_b64u(),
        "kid": "narrowing-log-key",
    });
    let mut walked = 0;
    let mut refused = 0;
    for (array, per_epoch) in [("histories", false), ("parameter_histories", true)] {
        for history in vector[array].as_array().unwrap() {
            let name = history["name"].as_str().unwrap();
            let envelopes = history["declarations"].as_object().unwrap();
            let narrowing = Narrowing {
                envelopes,
                keys: keys.iter().map(|k| common::Signer::new(k.seed)).collect(),
                names: envelopes
                    .iter()
                    .map(|(label, envelope)| {
                        (
                            wist_core::declaration::inner_hash(envelope).unwrap(),
                            label.clone(),
                        )
                    })
                    .collect(),
            };
            let publisher = envelopes.values().next().unwrap()["publisher"]["domain"]
                .as_str()
                .unwrap();
            let expected = history["expected"]["epochs"].as_array().unwrap();
            let rejected_at = history["expected"]["rejected"]["height"].as_u64();
            let mut served = ServedLog::new(&log_key, "narrowing-vector-log");
            let target = tempfile::tempdir().unwrap();
            let log_dir = served.log_dir(target.path());
            let mut live: BTreeMap<String, String> = BTreeMap::new();
            for epoch in history["epochs"].as_array().unwrap() {
                let height = epoch["height"].as_u64().unwrap();
                let label = format!("{array}: {name} at {height}");
                let want = expected.get(height as usize);
                let current = want.or(expected.last()).unwrap()["current_declaration"]
                    .as_str()
                    .unwrap();
                let parameters = if per_epoch {
                    &epoch["parameters"]
                } else {
                    &history["parameters"]
                };
                served.seal(VectorEpoch {
                    sealed_at: epoch["sealed_at"].as_str().unwrap().to_owned(),
                    parameters: parameter_map(parameters),
                    leaves: narrowing.epoch(epoch, current, publisher),
                });
                if let Some(want) = want {
                    for transition in want["transitions"].as_array().unwrap() {
                        for removed in transition["removed"].as_array().unwrap() {
                            live.remove(removed["url"].as_str().unwrap());
                        }
                    }
                    for sealed in want["records_sealed"].as_array().unwrap() {
                        live.insert(
                            sealed["url"].as_str().unwrap().to_owned(),
                            sealed["collection"].as_str().unwrap().to_owned(),
                        );
                    }
                }
                if height == 0 {
                    served.install(target.path());
                    continue;
                }
                served.amend(target.path());
                let before = narrowing.stored(&log_dir, publisher);
                let outcome = served.sync(target.path());
                assert_eq!(outcome, Ok(height), "{label}");
                if rejected_at == Some(height) {
                    let code = history["expected"]["rejected"]["code"].as_str().unwrap();
                    let reported: Vec<(u64, Vec<String>)> = served
                        .rejected(target.path())
                        .into_iter()
                        .map(|epoch| (epoch.epoch_number, epoch.codes))
                        .collect();
                    assert_eq!(reported, [(height, vec![code.to_owned()])], "{label}");
                    assert_eq!(narrowing.stored(&log_dir, publisher), before, "{label}");
                    let later = common::Signer::new([0x65; 32]);
                    let sealed_at = wist_core::timestamp::instant(
                        log_seconds(epoch["sealed_at"].as_str().unwrap()).unwrap() + 3600,
                    )
                    .unwrap();
                    served.seal(VectorEpoch {
                        sealed_at,
                        parameters: parameter_map(parameters),
                        leaves: leaves(&[common::declaration_entry(&later, "later.example")]),
                    });
                    served.amend(target.path());
                    assert_eq!(served.sync(target.path()), Ok(height + 1), "{label}");
                    assert!(
                        common::holds_declaration(&log_dir, "later.example"),
                        "{label}"
                    );
                    assert_eq!(narrowing.stored(&log_dir, publisher), before, "{label}");
                    refused += 1;
                    break;
                }
                let want = want.unwrap();
                let live_now: Vec<Value> = live
                    .iter()
                    .map(|(url, collection)| json!({"url": url, "collection": collection}))
                    .collect();
                assert_eq!(
                    narrowing.stored(&log_dir, publisher),
                    json!({
                        "current_declaration": want["current_declaration"],
                        "pending_head": want["pending_head"],
                        "activation_height": want["activation_height"],
                        "window_end": want["window_end"],
                        "live": sorted(live_now),
                    }),
                    "{label}"
                );
                walked += 1;
            }
            if let Some(final_live) = history["expected"].get("live_records") {
                let final_live: Vec<Value> = final_live
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| json!({"url": r["url"], "collection": r["collection"]}))
                    .collect();
                let held: Vec<Value> = live
                    .iter()
                    .map(|(url, collection)| json!({"url": url, "collection": collection}))
                    .collect();
                assert_eq!(sorted(held), sorted(final_live), "{name}");
            }
        }
    }
    assert!(
        walked > 50 && refused == 2,
        "{walked} walked, {refused} refused"
    );
}

fn synthetic_log_key(seed: u8) -> Value {
    json!({
        "seed_hex": format!("{seed:02x}").repeat(32),
        "x": common::Signer::new([seed; 32]).public_b64u(),
        "kid": format!("log-key-{seed}"),
    })
}

fn leaves(entries: &[Value]) -> Vec<Vec<u8>> {
    common::canonical_order(entries)
        .iter()
        .map(|entry| wist_core::jcs::canonicalize(entry).unwrap())
        .collect()
}

fn hourly(height: u64) -> String {
    wist_core::timestamp::instant(
        log_seconds("2026-10-01T00:00:00Z").unwrap() + 3600 * height as i64,
    )
    .unwrap()
}

#[test]
fn the_per_labeler_and_per_domain_caps_reject_an_epoch_the_consumer_walks() {
    let vector = vector("wist3/label-tables.json");
    let mut cases = 0;
    for case in vector["cap_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let parameters: BTreeMap<String, i64> =
            ["labeler_epoch_entries_max", "domain_epoch_entries_max"]
                .into_iter()
                .map(|name| (name.to_owned(), case[name].as_i64().unwrap()))
                .collect();
        let entries: Vec<Value> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(n, entry)| {
                let domain = &entry["domain"];
                let body = match entry["type"].as_str().unwrap() {
                    "label" => json!({"label": {"labeler": domain, "n": n}}),
                    "dispute" => json!({"dispute": {"disputant": domain, "n": n}}),
                    "publisher_catalog" => json!({"catalog": {"publisher": domain, "n": n}}),
                    "publisher_item" => json!({"item": {"publisher": domain, "n": n}}),
                    other => panic!("{label}: {other}"),
                };
                json!({"type": entry["type"], "body": body})
            })
            .collect();
        let mut served = ServedLog::new(&synthetic_log_key(0x61), "label-tables-log");
        for (height, leaves) in [(0, Vec::new()), (1, leaves(&entries))] {
            served.seal(VectorEpoch {
                sealed_at: hourly(height),
                parameters: parameters.clone(),
                leaves,
            });
        }
        let target = tempfile::tempdir().unwrap();
        served.install(target.path());
        let log_dir = served.log_dir(target.path());
        let before = common::state_tuples(&log_dir);
        assert_eq!(served.sync(target.path()), Ok(1), "{label}");
        let rejected: Vec<(u64, Vec<String>)> = served
            .rejected(target.path())
            .into_iter()
            .map(|epoch| (epoch.epoch_number, epoch.codes))
            .collect();
        match case["expected"].as_str() {
            None => assert!(rejected.is_empty(), "{label}: {rejected:?}"),
            Some(code) => {
                assert_eq!(rejected, [(1, vec![code.to_owned()])], "{label}");
                assert_eq!(common::state_tuples(&log_dir), before, "{label}");
                let later = common::Signer::new([0x64; 32]);
                served.seal(VectorEpoch {
                    sealed_at: hourly(2),
                    parameters: parameters.clone(),
                    leaves: leaves(&[common::declaration_entry(&later, "later.example")]),
                });
                served.amend(target.path());
                assert_eq!(served.sync(target.path()), Ok(2), "{label}");
                assert!(
                    common::holds_declaration(&log_dir, "later.example"),
                    "{label}"
                );
                assert_eq!(served.rejected(target.path()).len(), 1, "{label}");
            }
        }
        cases += 1;
    }
    assert_eq!(cases, 8);
}

#[test]
fn walked_labels_fill_the_labeler_statistics_the_vector_records() {
    let vector = vector("wist3/label-tables.json");
    for case in vector["statistics_cases"].as_array().unwrap() {
        let name = case["label"].as_str().unwrap();
        let sealed = case["sealed"].as_array().unwrap();
        let mut labelers: BTreeMap<&str, common::Signer> = BTreeMap::new();
        for (seed, label) in sealed.iter().enumerate() {
            labelers
                .entry(label["labeler"].as_str().unwrap())
                .or_insert_with(|| common::Signer::new([0x40 + seed as u8; 32]));
        }
        let declarations: Vec<Value> = labelers
            .iter()
            .map(|(domain, signer)| common::declaration_entry(signer, domain))
            .collect();
        let mut served = ServedLog::new(&synthetic_log_key(0x62), "label-statistics-log");
        served.seal(VectorEpoch {
            sealed_at: hourly(0),
            parameters: BTreeMap::new(),
            leaves: leaves(&declarations),
        });
        let target = tempfile::tempdir().unwrap();
        served.install(target.path());
        let top = sealed
            .iter()
            .map(|label| label["height"].as_u64().unwrap())
            .max()
            .unwrap();
        for height in 1..=top {
            let entries: Vec<Value> = sealed
                .iter()
                .enumerate()
                .filter(|(_, label)| label["height"] == height)
                .map(|(index, label)| {
                    let labeler = label["labeler"].as_str().unwrap();
                    let mut inner = json!({
                        "wist_version": "1.0.0",
                        "labeler": labeler,
                        "subject": label["subject"],
                        "name": label["name"],
                        "asserted_at": wist_core::timestamp::instant(
                            log_seconds(&hourly(height)).unwrap() - index as i64,
                        )
                        .unwrap(),
                    });
                    if label["retracted"] == true {
                        inner["retracted"] = json!(true);
                    }
                    let signer = &labelers[labeler];
                    let body = sign_envelope(&inner, "label", &signer.kid(), &signer.sk).unwrap();
                    json!({"type": "label", "body": body})
                })
                .collect();
            served.seal(VectorEpoch {
                sealed_at: hourly(height),
                parameters: BTreeMap::new(),
                leaves: leaves(&entries),
            });
            served.amend(target.path());
            assert_eq!(served.sync(target.path()), Ok(height), "{name}");
        }
        let held = rows(
            &served.log_dir(target.path()),
            "SELECT labeler, label_count, retraction_count,
                    (SELECT COUNT(*) FROM labeler_subjects s WHERE s.labeler = l.labeler),
                    first_seen_height
             FROM labelers l ORDER BY labeler",
            &[
                "labeler",
                "label_count",
                "retraction_count",
                "distinct_subjects",
                "first_seen_height",
            ],
        );
        assert_eq!(json!(held), case["rows"], "{name}");
    }
}

const VECTOR_OBSERVED: &str = "2026-09-30T10:00:00Z";
const VECTOR_NBF: &str = "2026-09-01T00:00:00Z";

struct Materialization<'v> {
    vector: &'v Value,
    case: &'v Value,
    signers: BTreeMap<String, common::Signer>,
    declared: BTreeMap<String, Value>,
    catalogs: BTreeMap<String, String>,
}

impl<'v> Materialization<'v> {
    fn new(vector: &'v Value, case: &'v Value) -> Self {
        let signers = vector["keys"]
            .as_object()
            .unwrap()
            .values()
            .map(|key| (key["x"].as_str().unwrap().to_owned(), signer_of(key)))
            .collect();
        Materialization {
            vector,
            case,
            signers,
            declared: BTreeMap::new(),
            catalogs: BTreeMap::new(),
        }
    }

    fn signer(&self, publisher: &str) -> &common::Signer {
        let x = self.declared[publisher]["publisher"]["keys"][0]["x"]
            .as_str()
            .unwrap();
        &self.signers[x]
    }

    fn snapshot_declaration(&self, domain: &str) -> Option<Value> {
        self.case["snapshot"]["tuples"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tuple| tuple[0] == "declaration" && tuple[1] == domain)
            .map(|tuple| tuple[2].clone())
    }

    fn kept_urls(&self, publisher: &str, height: u64) -> Vec<String> {
        let mut urls: Vec<String> = self.case["expected"][height as usize]["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| record["publisher"] == publisher)
            .map(|record| record["url"].as_str().unwrap().to_owned())
            .collect();
        for epoch in &self.case["epochs"].as_array().unwrap()[height as usize..] {
            for event in epoch["events"].as_array().unwrap() {
                if event["event"] == "record" && event["publisher"] == publisher {
                    urls.push(event["item"]["url"].as_str().unwrap().to_owned());
                }
            }
        }
        urls.sort();
        urls.dedup();
        urls
    }

    fn declaration(&mut self, domain: &str, epoch: &Value) -> Value {
        let height = epoch["height"].as_u64().unwrap();
        let envelope = match self.declared.get(domain) {
            None => self.snapshot_declaration(domain).unwrap_or_else(|| {
                let docs = signer_of(&self.vector["keys"]["docs"]);
                let inner = json!({
                    "wist_version": "1.0.0",
                    "seq": 0,
                    "domain": domain,
                    "keys": [common::key_entry(&docs, VECTOR_NBF)],
                });
                sign_envelope(&inner, "publisher", &docs.kid(), &docs.sk).unwrap()
            }),
            Some(current) => {
                let mut inner = current["publisher"].clone();
                inner["seq"] = json!(inner["seq"].as_u64().unwrap() + 1);
                inner["prev_declaration"] = json!(common::declaration_hash(current));
                let scope: Vec<Value> = self
                    .kept_urls(domain, height)
                    .iter()
                    .map(|url| json!({"url": url, "match": "prefix"}))
                    .collect();
                inner["collections"] = json!([{"name": "default", "scope": scope}]);
                let signer = self.signer(domain);
                sign_envelope(&inner, "publisher", &signer.kid(), &signer.sk).unwrap()
            }
        };
        self.declared.insert(domain.to_owned(), envelope.clone());
        json!({"type": "publisher_declaration", "body": envelope})
    }

    fn withdrawal(
        &self,
        event: &Value,
        epoch: &Value,
        log: &common::Signer,
        key_id: &str,
    ) -> Value {
        let item_id = event["item"].as_str().unwrap();
        let publisher = self.case["epochs"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|epoch| epoch["events"].as_array().unwrap())
            .find(|e| {
                e["event"] == "record" && wist_core::item::item_id(&e["item"]).unwrap() == item_id
            })
            .unwrap()["publisher"]
            .clone();
        let update = json!({
            "wist_version": "1.0.0",
            "action": "payload_withdrawal",
            "subject": publisher,
            "effective_at": epoch["sealed_at"],
            "details": {"delta_id": item_id, "legal_basis": "court order 12/2026", "jurisdiction": "BR"},
        });
        let body = sign_envelope(&update, "update", key_id, &log.sk).unwrap();
        assert_eq!(
            wist_core::registry_updates::update_id(&body).unwrap(),
            event["update"].as_str().unwrap()
        );
        json!({"type": "registry_update", "body": body})
    }

    fn entries(&mut self, epoch: &Value, log: &common::Signer, key_id: &str) -> Vec<Value> {
        let mut entries = Vec::new();
        let mut listed: BTreeMap<String, (String, String, String, Vec<Value>)> = BTreeMap::new();
        for event in epoch["events"].as_array().unwrap() {
            match event["event"].as_str().unwrap() {
                "declaration" => {
                    let domain = event["domain"].as_str().unwrap().to_owned();
                    entries.push(self.declaration(&domain, epoch));
                }
                "withdrawal" => entries.push(self.withdrawal(event, epoch, log, key_id)),
                "record" | "removal" => {
                    let item = if event["event"] == "record" {
                        event["item"].clone()
                    } else {
                        let removed = common::removed_item(
                            event["publisher"].as_str().unwrap(),
                            event["url"].as_str().unwrap(),
                            VECTOR_OBSERVED,
                        );
                        assert_eq!(wist_core::item::item_id(&removed).unwrap(), event["item"]);
                        removed
                    };
                    listed
                        .entry(event["catalog"].as_str().unwrap().to_owned())
                        .or_insert_with(|| {
                            (
                                event["publisher"].as_str().unwrap().to_owned(),
                                event["collection"].as_str().unwrap_or("default").to_owned(),
                                event["generated_at"].as_str().unwrap().to_owned(),
                                Vec::new(),
                            )
                        })
                        .3
                        .push(item);
                }
                "narrowing" | "base" => {}
                other => panic!("an event {other}"),
            }
        }
        for (vector_id, (publisher, collection, generated_at, items)) in listed {
            let published = common::publish(
                self.signer(&publisher),
                &publisher,
                &collection,
                &generated_at,
                &items,
            );
            self.catalogs
                .insert(published.catalog_id.clone(), vector_id);
            entries.push(published.catalog);
            entries.extend(published.items);
        }
        entries
    }

    fn state(&self, log_dir: &Path) -> Value {
        let mut records = Vec::new();
        let mut removals = Vec::new();
        for tuple in tuples(log_dir) {
            match tuple {
                StateEntry::Record(r) => records.push(json!({
                    "publisher": r.publisher,
                    "url": r.url,
                    "item": wist_core::item::item_id(&r.item).unwrap(),
                    "collection": r.collection,
                    "catalog": self.catalogs[&r.catalog_id],
                    "generated_at": r.generated_at,
                })),
                StateEntry::Removal(r) => removals.push(json!({
                    "publisher": r.publisher,
                    "url": r.url,
                    "item": r.item_id,
                    "catalog": self.catalogs[&r.catalog_id],
                    "generated_at": r.generated_at,
                })),
                _ => {}
            }
        }
        let materialized = rows(
            log_dir,
            "SELECT url, publisher, item_id, observed_at, attested_at FROM records ORDER BY publisher, url",
            &["url", "publisher", "item_id", "observed_at", "attested_at"],
        );
        let tuples: Vec<wist_core::materialization::ContentTuple> =
            serde_json::from_value(json!(materialized)).unwrap();
        let links = match common::table_exists(log_dir, "links") {
            false => Vec::new(),
            true => rows(
                log_dir,
                "SELECT l.source_url, l.target_url, l.position FROM links l
             JOIN records r ON r.url = l.source_url
             ORDER BY r.publisher, r.url, l.position",
                &["source_url", "target_url", "position"],
            ),
        };
        json!({
            "records": records,
            "removals": removals,
            "materialized": materialized,
            "links": links,
            "content_digest": wist_core::snapshot::content_digest(&tuples).unwrap(),
        })
    }

    fn titles(&self, log_dir: &Path) -> Vec<(Value, Value)> {
        rows(
            log_dir,
            "SELECT item_id, title FROM records ORDER BY item_id",
            &["item", "title"],
        )
        .into_iter()
        .map(|row| {
            let payload = &self.vector["payloads"][row["item"].as_str().unwrap()];
            (
                row["title"].clone(),
                payload["content"]["summary"]["title"].clone(),
            )
        })
        .collect()
    }
}

fn without_height(expected: &Value) -> Value {
    let mut expected = expected.clone();
    expected.as_object_mut().unwrap().remove("height");
    expected
}

#[test]
fn record_materialization_cases_walked_by_the_consumer_hold_each_epochs_records_and_rows() {
    let vector = vector("wist3/record-materialization.json");
    let log_key = &vector["keys"]["log"];
    let log = signer_of(log_key);
    let key_id = log_key["kid"].as_str().unwrap();
    let mut walked = 0;
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut materialization = Materialization::new(&vector, case);
        let mut served = ServedLog::new(log_key, "materialization-vector-log");
        for (item_id, payload) in vector["payloads"].as_object().unwrap() {
            let path = served
                .dir
                .path()
                .join(format!("payloads/{}.json", &item_id["sha256:".len()..]));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, serde_json::to_vec(payload).unwrap()).unwrap();
        }
        let target = tempfile::tempdir().unwrap();
        let log_dir = served.log_dir(target.path());
        let expected = case["expected"].as_array().unwrap();
        for (epoch, want) in case["epochs"].as_array().unwrap().iter().zip(expected) {
            let height = epoch["height"].as_u64().unwrap();
            let entries = materialization.entries(epoch, &log, key_id);
            assert_eq!(
                served.seal(VectorEpoch {
                    sealed_at: epoch["sealed_at"].as_str().unwrap().to_owned(),
                    parameters: BTreeMap::new(),
                    leaves: leaves(&entries),
                }),
                height
            );
            let label = format!("{name} at {height}");
            if height == 0 {
                served.install(target.path());
            } else {
                served.amend(target.path());
                assert_eq!(
                    served.sync_tiers(target.path(), true),
                    Ok(height),
                    "{label}"
                );
            }
            assert_eq!(
                materialization.state(&log_dir),
                without_height(want),
                "{label}"
            );
            for (held, signed) in materialization.titles(&log_dir) {
                assert_eq!(held, signed, "{label}: content from the verified Payload");
            }
            walked += 1;
        }
    }
    assert_eq!(walked, 16);
}

#[test]
fn materialization_preference_cases_walked_by_the_consumer_materialize_the_preferred_record() {
    let vector = vector("wist3/materialization-preference.json");
    let log_key = synthetic_log_key(0x63);
    let log = signer_of(&log_key);
    let key_id = log_key["kid"].as_str().unwrap();
    let mut cases = 0;
    for case in vector["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let host = case["host"].as_str().unwrap();
        let url = format!("https://{host}/page");
        let records = case["records"].as_array().unwrap();
        let mut publishers: Vec<&str> = records
            .iter()
            .map(|record| record["publisher"].as_str().unwrap())
            .collect();
        if case["self_declared"] == true && !publishers.contains(&host) {
            publishers.push(host);
        }
        let signers: BTreeMap<&str, common::Signer> = publishers
            .iter()
            .enumerate()
            .map(|(n, publisher)| (*publisher, common::Signer::new([0x50 + n as u8; 32])))
            .collect();
        let declarations: Vec<Value> = publishers
            .iter()
            .map(|publisher| match *publisher == host {
                true => common::declaration_entry(&signers[publisher], publisher),
                false => common::scoped_declaration_entry(&signers[publisher], publisher, &[host]),
            })
            .collect();
        let mut sealed = Vec::new();
        for record in records {
            let publisher = record["publisher"].as_str().unwrap();
            let item = common::page_item(publisher, &url, "2026-09-30T10:00:00Z");
            sealed.extend(common::catalog_entries(
                &signers[publisher],
                publisher,
                &hourly(1),
                std::slice::from_ref(&item),
            ));
            if record["withdrawn"] == true {
                sealed.push(common::withdrawal_entry(&log, key_id, &item, &hourly(1)));
            }
        }
        let mut served = ServedLog::new(&log_key, "preference-vector-log");
        served.seal(VectorEpoch {
            sealed_at: hourly(0),
            parameters: BTreeMap::new(),
            leaves: leaves(&declarations),
        });
        let target = tempfile::tempdir().unwrap();
        served.install(target.path());
        served.seal(VectorEpoch {
            sealed_at: hourly(1),
            parameters: BTreeMap::new(),
            leaves: leaves(&sealed),
        });
        served.amend(target.path());
        assert_eq!(served.sync(target.path()), Ok(1), "{label}");
        let log_dir = served.log_dir(target.path());
        for record in records {
            let publisher = record["publisher"].as_str().unwrap();
            assert!(
                common::holds_record_tuple(&log_dir, publisher, &url),
                "{label}: {publisher} holds a record"
            );
        }
        let held = common::record_row(&log_dir, &url).map(|(publisher, _, _)| publisher);
        assert_eq!(
            json!(held),
            case["materialized"],
            "{label}: the materialized Publisher"
        );
        cases += 1;
    }
    assert_eq!(cases, 10);
}

#[derive(Default)]
struct Held {
    records: Vec<common::RecordFixture>,
    extracts: Vec<(String, String, String, String)>,
    links: Vec<(String, String, i64)>,
}

fn held_from_payloads(vector: &Value, materialized: &Value) -> Held {
    let mut held = Held::default();
    for tuple in materialized.as_array().unwrap() {
        let text = |member: &str| tuple[member].as_str().unwrap().to_owned();
        let content = &vector["payloads"][text("item_id")]["content"];
        held.records.push(common::RecordFixture {
            url: text("url"),
            publisher: text("publisher"),
            item: Value::Null,
            item_id: text("item_id"),
            observed_at: text("observed_at"),
            attested_at: text("attested_at"),
            title: content["summary"]["title"].as_str().unwrap().to_owned(),
            abstract_text: content["summary"]["abstract"].as_str().map(str::to_owned),
            lang: "en".into(),
        });
        held.extracts.push((
            text("url"),
            text("publisher"),
            text("item_id"),
            content["extract"].as_str().unwrap().to_owned(),
        ));
        for (position, target) in content["links"]["urls"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            held.links.push((
                text("url"),
                target.as_str().unwrap().to_owned(),
                position as i64,
            ));
        }
    }
    held
}

fn held_by_store(log_dir: &Path) -> Held {
    let text = |row: &Value, member: &str| row[member].as_str().unwrap().to_owned();
    let mut held = Held::default();
    for row in rows(
        log_dir,
        "SELECT url, publisher, item_id, observed_at, attested_at, title, abstract, lang FROM records ORDER BY publisher, url",
        &["url", "publisher", "item_id", "observed_at", "attested_at", "title", "abstract", "lang"],
    ) {
        held.records.push(common::RecordFixture {
            url: text(&row, "url"),
            publisher: text(&row, "publisher"),
            item: Value::Null,
            item_id: text(&row, "item_id"),
            observed_at: text(&row, "observed_at"),
            attested_at: text(&row, "attested_at"),
            title: text(&row, "title"),
            abstract_text: row["abstract"].as_str().map(str::to_owned),
            lang: text(&row, "lang"),
        });
    }
    for row in rows(
        log_dir,
        "SELECT url, publisher, item_id, extract FROM extracts",
        &["url", "publisher", "item_id", "extract"],
    ) {
        held.extracts.push((
            text(&row, "url"),
            text(&row, "publisher"),
            text(&row, "item_id"),
            text(&row, "extract"),
        ));
    }
    for row in rows(
        log_dir,
        "SELECT source_url, target_url, position FROM links",
        &["source_url", "target_url", "position"],
    ) {
        held.links.push((
            text(&row, "source_url"),
            text(&row, "target_url"),
            row["position"].as_i64().unwrap(),
        ));
    }
    held
}

fn sorted_tuples(log_dir: &Path) -> Vec<String> {
    let mut tuples: Vec<String> = common::state_tuples(log_dir)
        .iter()
        .map(|tuple| serde_json::to_string(tuple).unwrap())
        .collect();
    tuples.sort();
    tuples
}

fn store_rows(log_dir: &Path) -> Vec<Value> {
    let mut held = rows(
        log_dir,
        "SELECT url, publisher, item_id, observed_at, attested_at, title, abstract, lang, collection, generated_at FROM records ORDER BY publisher, url",
        &["url", "publisher", "item_id", "observed_at", "attested_at", "title", "abstract", "lang", "collection", "generated_at"],
    );
    held.extend(rows(
        log_dir,
        "SELECT url, publisher, item_id, extract, collection FROM extracts ORDER BY publisher, url",
        &["url", "publisher", "item_id", "extract", "collection"],
    ));
    held.extend(rows(
        log_dir,
        "SELECT source_url, target_url, position FROM links ORDER BY source_url, position",
        &["source_url", "target_url", "position"],
    ));
    held
}

fn assert_same_store(resumed: &Path, walked: &Path, label: &str) {
    assert_eq!(store_rows(resumed), store_rows(walked), "{label}: rows");
    assert_eq!(
        sorted_tuples(resumed),
        sorted_tuples(walked),
        "{label}: state tuples"
    );
}

/// WIST-3 §7 and §8 catch-up decision: a Consumer resumed from a Snapshot's tuples reaches every
/// later state, and resumed from the state a full walk holds at that Epoch holds that walk's rows
/// and tuples at every later Epoch.
#[test]
fn record_materialization_snapshots_resume_to_the_records_and_state_of_a_full_walk() {
    let vector = vector("wist3/record-materialization.json");
    let log_key = &vector["keys"]["log"];
    let log = signer_of(log_key);
    let key_id = log_key["kid"].as_str().unwrap();
    let mut resumed = 0;
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let snapshot_height = case["snapshot"]["height"].as_u64().unwrap();
        let vector_tuples: Vec<Value> = case["snapshot"]["tuples"].as_array().unwrap().clone();
        let mut materialization = Materialization::new(&vector, case);
        for tuple in &vector_tuples {
            let catalog = match tuple[0].as_str().unwrap() {
                "record" => &tuple[5],
                "removal" => &tuple[4],
                _ => continue,
            };
            let catalog = catalog.as_str().unwrap().to_owned();
            materialization
                .catalogs
                .entry(catalog.clone())
                .or_insert(catalog);
        }
        let mut served = ServedLog::new(log_key, "materialization-snapshot-log");
        for (item_id, payload) in vector["payloads"].as_object().unwrap() {
            let path = served
                .dir
                .path()
                .join(format!("payloads/{}.json", &item_id["sha256:".len()..]));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, serde_json::to_vec(payload).unwrap()).unwrap();
        }
        let walked = tempfile::tempdir().unwrap();
        let from_vector = tempfile::tempdir().unwrap();
        let from_walk = tempfile::tempdir().unwrap();
        let walked_dir = served.log_dir(walked.path());
        let expected = case["expected"].as_array().unwrap();
        for (epoch, want) in case["epochs"].as_array().unwrap().iter().zip(expected) {
            let height = epoch["height"].as_u64().unwrap();
            let entries = materialization.entries(epoch, &log, key_id);
            served.seal(VectorEpoch {
                sealed_at: epoch["sealed_at"].as_str().unwrap().to_owned(),
                parameters: BTreeMap::new(),
                leaves: leaves(&entries),
            });
            let label = format!("{name} at {height}");
            if height == 0 {
                served.install(walked.path());
            } else {
                served.amend(walked.path());
                assert_eq!(
                    served.sync_tiers(walked.path(), true),
                    Ok(height),
                    "{label}"
                );
            }
            if height < snapshot_height {
                continue;
            }
            if height == snapshot_height {
                let offered: Vec<StateEntry> = vector_tuples
                    .iter()
                    .map(|tuple| serde_json::from_value(tuple.clone()).unwrap())
                    .collect();
                served.snapshot(
                    height,
                    "2026-10-01",
                    offered,
                    &held_from_payloads(&vector, &want["materialized"]),
                );
                let declarations: Vec<StateEntry> = vector_tuples
                    .iter()
                    .filter(|tuple| tuple[0] == "declaration")
                    .map(|tuple| serde_json::from_value(tuple.clone()).unwrap())
                    .collect();
                assert_eq!(
                    served.sync_tiers(from_vector.path(), true),
                    Ok(height),
                    "{label}"
                );
                served.snapshot(
                    height,
                    "2026-10-02",
                    tuples(&walked_dir)
                        .into_iter()
                        .chain(declarations)
                        .collect(),
                    &held_by_store(&walked_dir),
                );
            } else {
                assert_eq!(
                    served.sync_tiers(from_vector.path(), true),
                    Ok(height),
                    "{label}"
                );
            }
            assert_eq!(
                served.sync_tiers(from_walk.path(), true),
                Ok(height),
                "{label}"
            );
            let from_vector_dir = served.log_dir(from_vector.path());
            assert_eq!(
                materialization.state(&from_vector_dir),
                without_height(want),
                "{label}: resumed from the vector's tuples"
            );
            for (held, signed) in materialization.titles(&from_vector_dir) {
                assert_eq!(held, signed, "{label}: content of the resumed store");
            }
            assert_same_store(&served.log_dir(from_walk.path()), &walked_dir, &label);
            resumed += 1;
        }
    }
    assert_eq!(resumed, 9);
}

fn test_agg_k1() -> Value {
    let keypair = vector("wist1/keypair.json");
    json!({
        "seed_hex": keypair["seed_hex"],
        "x": keypair["public_key"],
        "kid": "test-agg-k1",
    })
}

fn tuple_entries(tuples: &Value) -> Vec<StateEntry> {
    tuples
        .as_array()
        .unwrap()
        .iter()
        .map(|tuple| serde_json::from_value(tuple.clone()).unwrap())
        .collect()
}

fn sorted_values(values: &[Value]) -> Vec<String> {
    let mut values: Vec<String> = values
        .iter()
        .map(|value| serde_json::to_string(value).unwrap())
        .collect();
    values.sort();
    values
}

struct Resume<'v> {
    vector: &'v Value,
    served: ServedLog,
    signers: BTreeMap<String, common::Signer>,
}

impl<'v> Resume<'v> {
    fn new(vector: &'v Value) -> Self {
        let resume = &vector["resume"];
        let mut domains: Vec<String> = vector["sealed_items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|sealed| sealed["publisher"].as_str().unwrap().to_owned())
            .chain(
                ["record_tuples", "removal_tuples"]
                    .iter()
                    .flat_map(|name| resume[*name].as_array().unwrap())
                    .map(|tuple| tuple[1].as_str().unwrap().to_owned()),
            )
            .collect();
        domains.sort();
        domains.dedup();
        let signers = domains
            .into_iter()
            .enumerate()
            .map(|(n, domain)| (domain, common::Signer::new([0x70 + n as u8; 32])))
            .collect();
        Resume {
            vector,
            served: ServedLog::new(&test_agg_k1(), "withdrawal-resume-log"),
            signers,
        }
    }

    fn declaration(&self, domain: &str) -> Value {
        let signer = &self.signers[domain];
        common::build_declaration_full(signer, domain, 0, None, &[(signer, "2026-08-01T00:00:00Z")])
    }

    fn entries(&self, height: u64) -> Vec<Value> {
        let resume = &self.vector["resume"];
        let mut entries = Vec::new();
        if height == 0 {
            entries.extend(self.signers.keys().map(
                |domain| json!({"type": "publisher_declaration", "body": self.declaration(domain)}),
            ));
        }
        let mut listed: BTreeMap<&str, (&str, Vec<Value>)> = BTreeMap::new();
        for sealed in self.vector["sealed_items"].as_array().unwrap() {
            if sealed["height"] != height || height <= resume["snapshot_height"].as_u64().unwrap() {
                continue;
            }
            listed
                .entry(sealed["publisher"].as_str().unwrap())
                .or_insert_with(|| (sealed["generated_at"].as_str().unwrap(), Vec::new()))
                .1
                .push(sealed["item"].clone());
        }
        for (publisher, (generated_at, items)) in listed {
            entries.extend(common::catalog_entries(
                &self.signers[publisher],
                publisher,
                generated_at,
                &items,
            ));
        }
        for act in resume["act_cases"].as_array().unwrap() {
            if act["height"] == height {
                let body: Value =
                    serde_json::from_str(act["envelope_json"].as_str().unwrap()).unwrap();
                entries.push(json!({"type": "registry_update", "body": body}));
            }
        }
        entries
    }

    fn seal_through(&mut self, height: u64) {
        while (self.served.epochs.len() as u64) <= height {
            let next = self.served.epochs.len() as u64;
            let entries = self.entries(next);
            self.served.seal(VectorEpoch {
                sealed_at: format!("2026-08-02T{next:02}:30:00Z"),
                parameters: BTreeMap::new(),
                leaves: leaves(&entries),
            });
        }
    }

    fn snapshot(&self) {
        let resume = &self.vector["resume"];
        let height = resume["snapshot_height"].as_u64().unwrap();
        let mut tuples: Vec<StateEntry> = [
            "registry_update_tuples",
            "record_tuples",
            "removal_tuples",
            "adopted",
        ]
        .iter()
        .flat_map(|name| tuple_entries(&resume[*name]))
        .collect();
        let records = wist_core::sealing::Records::from_state(&tuples).unwrap();
        let withdrawn: Vec<&str> = resume["adopted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tuple| tuple[1].as_str().unwrap())
            .collect();
        let materialized = wist_core::materialization::materialized(
            records.records(),
            |host| self.signers.contains_key(host),
            |item_id| withdrawn.contains(&item_id),
        )
        .unwrap();
        let held = Held {
            records: materialized
                .into_iter()
                .map(|tuple| common::RecordFixture {
                    item: records
                        .record(&tuple.publisher, &tuple.url)
                        .unwrap()
                        .item
                        .clone(),
                    title: tuple.url.clone(),
                    url: tuple.url,
                    publisher: tuple.publisher,
                    item_id: tuple.item_id,
                    observed_at: tuple.observed_at,
                    attested_at: tuple.attested_at,
                    abstract_text: None,
                    lang: "en".into(),
                })
                .collect(),
            ..Held::default()
        };
        tuples.extend(self.signers.keys().map(|domain| {
            StateEntry::Declaration(wist_core::objects::DeclarationEntry {
                domain: domain.clone(),
                declaration: self.declaration(domain),
                sealing_height: 0,
                highest_accepted_seq: 0,
            })
        }));
        self.served.snapshot(height, "2026-08-02", tuples, &held);
    }

    fn assert_verdicts(&self, target: &Path, label: &str) {
        let resume = &self.vector["resume"];
        let tuples = common::state_tuples(&self.served.log_dir(target));
        let withdrawals: Vec<Value> = tuples
            .iter()
            .filter(|tuple| tuple[0] == "withdrawal")
            .cloned()
            .collect();
        assert_eq!(
            sorted_values(&withdrawals),
            sorted_values(resume["state_tuples"].as_array().unwrap()),
            "{label}: withdrawal tuples"
        );
        let accepted: Vec<&str> = tuples
            .iter()
            .filter(|tuple| tuple[0] == "registry_update")
            .map(|tuple| tuple[1].as_str().unwrap())
            .collect();
        for act in resume["act_cases"].as_array().unwrap() {
            let case = act["label"].as_str().unwrap();
            let body: Value = serde_json::from_str(act["envelope_json"].as_str().unwrap()).unwrap();
            let update_id = wist_core::registry_updates::update_id(&body).unwrap();
            assert_eq!(
                accepted.contains(&update_id.as_str()),
                act["code"].is_null(),
                "{label}: {case} at {}",
                act["height"]
            );
        }
    }
}

/// WIST-4 §5.1: a resumed Consumer judges an act against every Item it applied through the act's
/// Epoch and the tuples of the Snapshot it resumed from, however its walk is split into runs.
#[test]
fn withdrawal_resume_verdicts_hold_in_every_split_of_the_walk_into_runs() {
    let vector = vector("wist4/withdrawal.json");
    let snapshot_height = vector["resume"]["snapshot_height"].as_u64().unwrap();
    let top = vector["resume"]["act_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|act| act["height"].as_u64().unwrap())
        .max()
        .unwrap();
    let inner: Vec<u64> = (snapshot_height + 1..top).collect();
    for split in 0..1u32 << inner.len() {
        let stops: Vec<u64> = inner
            .iter()
            .enumerate()
            .filter(|(bit, _)| split & (1 << bit) != 0)
            .map(|(_, height)| *height)
            .chain(std::iter::once(top))
            .collect();
        let mut resume = Resume::new(&vector);
        resume.seal_through(snapshot_height);
        resume.snapshot();
        let target = tempfile::tempdir().unwrap();
        assert_eq!(resume.served.sync(target.path()), Ok(snapshot_height));
        for height in &stops {
            resume.seal_through(*height);
            assert_eq!(resume.served.sync(target.path()), Ok(*height), "{stops:?}");
        }
        resume.assert_verdicts(target.path(), &format!("runs ending at {stops:?}"));
        if split == 0 {
            let once = tempfile::tempdir().unwrap();
            assert_eq!(resume.served.sync(once.path()), Ok(top));
            resume.assert_verdicts(once.path(), "one run from the Snapshot");
        }
    }
}

fn amendments_sealed_at(log_dir: &Path, height: u64) -> Vec<Value> {
    rows(
        log_dir,
        &format!(
            "SELECT parameter, value FROM parameters WHERE epoch_number = {height} ORDER BY entry_index"
        ),
        &["parameter", "value"],
    )
}

fn walk_one_act(body: &Value) -> Vec<Value> {
    let entry = json!({"type": "registry_update", "body": body});
    let leaf = wist_core::jcs::canonicalize(&entry)
        .unwrap_or_else(|_| serde_json::to_vec(&entry).unwrap());
    let mut served = ServedLog::new(&test_agg_k1(), "parameter-wire-log");
    served.seal(VectorEpoch {
        sealed_at: "2026-08-01T00:00:00Z".into(),
        parameters: BTreeMap::new(),
        leaves: Vec::new(),
    });
    let target = tempfile::tempdir().unwrap();
    served.install(target.path());
    served.seal(VectorEpoch {
        sealed_at: "2026-08-01T01:00:00Z".into(),
        parameters: BTreeMap::new(),
        leaves: vec![leaf],
    });
    served.amend(target.path());
    assert_eq!(served.sync(target.path()), Ok(1));
    amendments_sealed_at(&served.log_dir(target.path()), 1)
}

/// WIST-4 §5.1: a `parameter_change` changes the schedule only when it passes JSON/JCS eligibility,
/// the envelope checks, its `details` and `subject` contract, authentication and §5's bounds and
/// combinations.
#[test]
fn parameter_change_wire_cases_walked_by_the_consumer_change_the_schedule_as_the_vector_disposes() {
    let vector = vector("wist4/parameter-combinations.json");
    let mut cases = 0;
    for case in vector["wire_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let adopted = case["code"].is_null() && case["combinations_hold_at_defaults"] == true;
        let held = walk_one_act(&case["envelope"]);
        assert_eq!(held.len(), usize::from(adopted), "{label}: {held:?}");
        if adopted {
            assert_eq!(
                held[0]["parameter"], case["envelope"]["update"]["details"]["parameter"],
                "{label}"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 45);
}

#[test]
fn a_parameter_change_breaking_its_contract_or_major_version_changes_no_schedule() {
    let log = signer_of(&test_agg_k1());
    let signed = |update: Value| sign_envelope(&update, "update", "test-agg-k1", &log.sk).unwrap();
    let update = json!({
        "wist_version": "1.0.0",
        "action": "parameter_change",
        "subject": "quota_base",
        "effective_at": "2026-08-12T00:00:00Z",
        "details": {"parameter": "quota_base", "value": 2},
    });
    assert_eq!(walk_one_act(&signed(update.clone())).len(), 1);

    let mut other_subject = update.clone();
    other_subject["subject"] = json!("catalog_refresh_seconds");
    let mut extra_member = update.clone();
    extra_member["details"]["note"] = json!("raised");
    let mut next_major = update.clone();
    next_major["wist_version"] = json!("2.0.0");
    for (label, changed) in [
        ("a subject other than details.parameter", other_subject),
        ("a details member the contract does not name", extra_member),
        ("wist_version 2.0.0", next_major),
    ] {
        assert!(walk_one_act(&signed(changed)).is_empty(), "{label}");
    }
}
