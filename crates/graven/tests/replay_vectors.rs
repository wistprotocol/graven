mod common;

use graven::keyset::KeyHistory;
use graven::sync::{checkpoints, tree, SyncState, Tree};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use wist_core::crypto::{hex_decode, PublicKey};
use wist_core::envelope::sign_envelope;
use wist_core::item::Kind;
use wist_core::objects::{Anchor, GenesisKey, StateEntry};
use wist_core::parameters::{Amendment, Schedule};
use wist_core::sealing::{carried_label_ids, Epoch, Parameters, Replay};
use wist_core::timestamp::log_seconds;

fn spec_dir() -> PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
}

fn vector(rel: &str) -> Value {
    serde_json::from_slice(&std::fs::read(spec_dir().join("vectors").join(rel)).unwrap()).unwrap()
}

fn signer_of(key: &Value) -> common::Signer {
    let seed: [u8; 32] = hex_decode(key["seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signer = common::Signer::new(seed);
    assert_eq!(signer.public_b64u(), key["x"].as_str().unwrap());
    signer
}

struct VectorEpoch {
    sealed_at: String,
    parameters: BTreeMap<String, i64>,
    leaves: Vec<Vec<u8>>,
}

impl VectorEpoch {
    fn entries(&self) -> Vec<Value> {
        self.leaves
            .iter()
            .map(|leaf| serde_json::from_slice(leaf).unwrap())
            .collect()
    }

    fn stored(&self) -> Vec<(usize, &[u8])> {
        self.leaves
            .iter()
            .enumerate()
            .filter(|(_, leaf)| wist_core::json::member_eligible(leaf, &[]) != Some(true))
            .map(|(index, leaf)| (index, leaf.as_slice()))
            .collect()
    }
}

struct ServedLog {
    dir: tempfile::TempDir,
    log: common::Log,
    log_id: String,
    log_key_id: String,
    base_url: String,
    epochs: Vec<VectorEpoch>,
}

impl ServedLog {
    fn new(log_key: &Value, log_id: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let signer = signer_of(log_key);
        let key_id = log_key["kid"].as_str().unwrap().to_owned();
        let anchor = Anchor {
            wist_version: "1.0.0".into(),
            log_id: log_id.into(),
            genesis_key: GenesisKey {
                key_id: key_id.clone(),
                alg: "Ed25519".into(),
                public_key: signer.public_b64u(),
            },
            created_at: "2026-08-01T00:00:00Z".into(),
            predecessor: None,
        };
        let envelope = sign_envelope(
            &serde_json::to_value(&anchor).unwrap(),
            "anchor",
            &key_id,
            &signer.sk,
        )
        .unwrap();
        let anchor_path = dir.path().join("log/anchor.json");
        std::fs::create_dir_all(anchor_path.parent().unwrap()).unwrap();
        std::fs::write(&anchor_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let log = common::Log::empty(dir.path(), signer, log_id);
        let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
        ServedLog {
            dir,
            log,
            log_id: log_id.into(),
            log_key_id: key_id,
            base_url,
            epochs: Vec::new(),
        }
    }

    fn seal(&mut self, epoch: VectorEpoch) -> u64 {
        let height = self
            .log
            .seal_leaf_bytes(&epoch.sealed_at, &epoch.leaves)
            .epoch_number();
        self.epochs.push(epoch);
        height
    }

    fn log_key(&self) -> impl Fn(&str) -> Option<PublicKey> + '_ {
        let public = PublicKey::from_b64u(&self.log.log.public_b64u()).unwrap();
        move |key_id: &str| (key_id == self.log_key_id).then(|| public.clone())
    }

    fn log_dir(&self, target: &Path) -> PathBuf {
        graven::registry::log_dir(target, &self.log_id)
    }

    fn amendments(&self) -> Vec<Amendment> {
        let first = log_seconds(&self.epochs[0].sealed_at).unwrap();
        let mut schedule = Schedule::new(first);
        let mut amendments = Vec::new();
        for (height, epoch) in self.epochs.iter().enumerate() {
            let at = log_seconds(&epoch.sealed_at).unwrap();
            let mut wanted = epoch.parameters.clone();
            wanted.insert("epoch_cadence_seconds".into(), 1);
            for (index, (parameter, value)) in wanted.into_iter().enumerate() {
                if schedule.value_at(&parameter, at) == Some(value) {
                    continue;
                }
                let amendment = Amendment {
                    parameter,
                    value,
                    epoch_number: height as u64,
                    entry_index: index as u64,
                    sealed_at_s: at,
                    effective_at_s: at,
                };
                schedule.adopt(amendment.clone());
                amendments.push(amendment);
            }
        }
        amendments
    }

    fn genesis_replay(&self) -> Replay {
        let epoch = &self.epochs[0];
        let entries = epoch.entries();
        let parameters = Parameters::new(
            epoch
                .parameters
                .iter()
                .map(|(name, value)| (name.as_str(), *value)),
        )
        .unwrap();
        let root = self.log.checkpoints[0].root_token();
        let log_key = self.log_key();
        let mut replay = Replay::new();
        replay
            .epoch_stored(
                &Epoch {
                    height: 0,
                    root: &root,
                    sealed_at: &epoch.sealed_at,
                    parameters: &parameters,
                    suffix_list: None,
                    log_key: &log_key,
                    entries: &entries,
                },
                &epoch.stored(),
            )
            .unwrap();
        replay
    }

    fn install(&self, target: &Path) {
        let replay = self.genesis_replay();
        assert_eq!(replay.labels().count(), 0);
        let checkpoint = self.log.checkpoints[0].clone();
        let log_dir = self.log_dir(target);
        std::fs::create_dir_all(&log_dir).unwrap();
        let index = log_dir.join("index.sqlite");
        common::write_tier0(&index, &[]);
        let conn = Connection::open(&index).unwrap();
        conn.execute_batch(graven::store::CREATE_STATE_TUPLES)
            .unwrap();
        conn.execute_batch(graven::store::CREATE_PARAMETERS)
            .unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS declaration_state(id INTEGER PRIMARY KEY CHECK(id = 1), state TEXT NOT NULL)",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO declaration_state(id, state) VALUES (1, ?1)",
            [KeyHistory::from_declarations(replay.declarations().clone())
                .state()
                .unwrap()],
        )
        .unwrap();
        for (seq, tuple) in replay.state_entries().iter().enumerate() {
            conn.execute(
                "INSERT INTO state_tuples(seq, tuple) VALUES (?1, ?2)",
                (seq as i64, serde_json::to_string(tuple).unwrap()),
            )
            .unwrap();
        }
        conn.execute_batch(graven::store::CREATE_SEALED_LABEL_IDS)
            .unwrap();
        conn.execute_batch(graven::store::CREATE_SEALED_ITEMS)
            .unwrap();
        let genesis = &self.epochs[0];
        for label_id in carried_label_ids(&genesis.entries(), &genesis.stored()).unwrap() {
            conn.execute(
                "INSERT INTO sealed_label_ids(label_id, subject) VALUES (?1, NULL)",
                [label_id],
            )
            .unwrap();
        }
        for item in replay.sealed_items().sealed() {
            let kind = match item.kind {
                Kind::Page => "page",
                Kind::Removed => "removed",
            };
            conn.execute(
                "INSERT INTO sealed_items(item_id, publisher, kind, height) VALUES (?1, ?2, ?3, ?4)",
                (item.item_id, item.publisher, kind, item.height as i64),
            )
            .unwrap();
        }
        checkpoints::save_checkpoint(&conn, &checkpoint, Some(true)).unwrap();
        let at = checkpoint.sealed_at_s().unwrap();
        graven::sync::save_sync_state(
            &conn,
            &SyncState {
                format: graven::sync::SYNC_STATE_FORMAT,
                tree_size: checkpoint.tree_size(),
                epoch_number: 0,
                root: checkpoint.root_token(),
                unwitnessed: true,
                content_digest: None,
                schedule_first_s: Some(at),
                prior_sealed_at_s: Some(at),
                largest_epoch_bytes: 0,
                walk_floor: None,
            },
        )
        .unwrap();
        let client = graven::fetch::Client::new(true);
        let sources = graven::sync::Sources::new(
            &client,
            vec![graven::fetch::parse_base(&self.base_url).unwrap()],
        );
        let mut held = Tree::new();
        tree::seed(
            &sources,
            &mut held,
            checkpoint.tree_size(),
            checkpoint.root(),
        )
        .unwrap();
        held.save(&conn).unwrap();
        self.amend(target);
    }

    fn amend(&self, target: &Path) {
        let conn = Connection::open(self.log_dir(target).join("index.sqlite")).unwrap();
        conn.execute_batch(graven::store::CREATE_PARAMETERS)
            .unwrap();
        for a in self.amendments() {
            conn.execute(
                "INSERT OR IGNORE INTO parameters(parameter, value, epoch_number, entry_index, sealed_at_s, effective_at_s) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (&a.parameter, a.value, a.epoch_number as i64, a.entry_index as i64, a.sealed_at_s, a.effective_at_s),
            )
            .unwrap();
        }
    }

    fn sync(&self, target: &Path) -> Result<u64, String> {
        graven::sync::run(
            self.dir.path().join("log/anchor.json").to_str().unwrap(),
            &self.base_url,
            target,
            true,
            false,
        )
        .map(|report| report.head)
        .map_err(|error| error.to_string())
    }

    fn head(&self, target: &Path) -> u64 {
        graven::store::synced_state(&self.log_dir(target))
            .unwrap()
            .epoch_number
    }
}

fn leaf_of(named: &Value) -> Vec<u8> {
    match named["entry_json"].as_str() {
        Some(text) => text.as_bytes().to_vec(),
        None => wist_core::jcs::canonicalize(&named["entry"]).unwrap(),
    }
}

fn parameter_map(map: &Value) -> BTreeMap<String, i64> {
    map.as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| (name.clone(), value.as_i64().unwrap()))
        .collect()
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
                    let error = outcome.unwrap_err();
                    let codes = want["codes"].as_array().unwrap();
                    assert!(
                        codes
                            .iter()
                            .any(|code| error.contains(code.as_str().unwrap())),
                        "{label}: {error} reports none of {codes:?}"
                    );
                    assert_eq!(served.head(target.path()), height - 1, "{label}");
                    rejected += 1;
                }
                other => panic!("{label}: {other}"),
            }
            assert_eq!(
                stored_sealing_state(&log_dir, &names),
                without_base(&want["state"]),
                "{label}"
            );
            if want["status"] == "rejected" {
                break;
            }
        }
        if served.epochs.len() < 2 {
            continue;
        }
        let once = tempfile::tempdir().unwrap();
        served.install(once.path());
        let _ = served.sync(once.path());
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
                let outcome = served.sync(target.path());
                if rejected_at == Some(height) {
                    let code = history["expected"]["rejected"]["code"].as_str().unwrap();
                    let error = outcome.unwrap_err();
                    assert!(error.contains(code), "{label}: {error}");
                    assert_eq!(served.head(target.path()), height - 1, "{label}");
                    refused += 1;
                    break;
                }
                assert_eq!(outcome, Ok(height), "{label}");
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
        let outcome = served.sync(target.path());
        match case["expected"].as_str() {
            None => assert_eq!(outcome, Ok(1), "{label}"),
            Some(code) => {
                let error = outcome.unwrap_err();
                assert!(
                    error.contains(&format!("the Epoch is rejected ({code})")),
                    "{label}: {error}"
                );
                assert_eq!(served.head(target.path()), 0, "{label}");
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
