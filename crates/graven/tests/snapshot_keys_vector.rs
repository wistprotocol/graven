mod common;

use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use wist_core::crypto::{hex_decode, hex_encode, PublicKey};
use wist_core::envelope::{sign_envelope, verify_envelope};

fn spec_dir() -> PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
}

fn vector() -> Value {
    serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist3/snapshot-keys.json")).unwrap(),
    )
    .unwrap()
}

fn key_of(key_id: &str) -> common::Signer {
    let seed = hex_decode(vector()["keys"][key_id]["seed_hex"].as_str().unwrap()).unwrap();
    common::Signer::new(seed.try_into().unwrap())
}

fn signed_by_its_named_key(envelope: &Value, inner: &str) -> bool {
    let key_id = envelope["sig"]["key_id"].as_str().unwrap();
    let public = PublicKey::from_b64u(&key_of(key_id).public_b64u()).unwrap();
    verify_envelope(envelope, inner, &public).is_ok()
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// WIST-3 §8 steps 1–4: the case's three documents as served; a manifest its named key signs is
/// signed again over a tier-0 index a Consumer can open, the family's own being a placeholder.
fn serve(history: &Value, case: &Value) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path().join("log/anchor.json"),
        &serde_json::to_vec(&history["anchor"]).unwrap(),
    );
    let mut log = common::Log::empty(
        dir.path(),
        common::Signer::new([0u8; 32]),
        history["log_id"].as_str().unwrap(),
    );
    let adopted_head = case["adopted_head"].as_u64().unwrap() as usize;
    for epoch in &history["epochs"].as_array().unwrap()[..=adopted_head] {
        log.adopt(
            epoch["checkpoint"].as_str().unwrap(),
            epoch["entries"].as_array().unwrap(),
        );
    }
    write(
        &dir.path().join("snapshots/index.json"),
        &serde_json::to_vec(&case["index"]).unwrap(),
    );
    let manifest_url = case["index"]["index"]["snapshots"][0]["manifest_url"]
        .as_str()
        .unwrap();
    let snapshot = dir
        .path()
        .join(manifest_url.trim_start_matches('/'))
        .parent()
        .unwrap()
        .to_path_buf();
    write(
        &snapshot.join("state.json"),
        &wist_core::jcs::canonicalize(&case["state"]).unwrap(),
    );
    let mut manifest = case["manifest"].clone();
    let tier0 = snapshot.join("tier0/index.sqlite");
    if signed_by_its_named_key(&manifest, "manifest") {
        let bytes = common::write_tier0(&tier0, &[]);
        let mut inner = manifest["manifest"].clone();
        inner["files"][0]["sha256"] = hex_encode(&Sha256::digest(&bytes)).into();
        inner["files"][0]["bytes"] = (bytes.len() as u64).into();
        let key_id = manifest["sig"]["key_id"].as_str().unwrap().to_owned();
        manifest = sign_envelope(&inner, "manifest", &key_id, &key_of(&key_id).sk).unwrap();
    } else {
        write(&tier0, b"tier0-placeholder");
    }
    write(
        &dir.path().join(manifest_url.trim_start_matches('/')),
        &serde_json::to_vec(&manifest).unwrap(),
    );
    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
    (dir, base_url)
}

fn key_ids_valid_at(log_dir: &Path, height: u64) -> Vec<String> {
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT key_id FROM aggregator_keys WHERE added_height <= ?1 AND (removed_height IS NULL OR removed_height > ?1) ORDER BY key_id",
        )
        .unwrap();
    stmt.query_map([height as i64], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

/// WIST-3 §3.4, §7 and §8: a cold start authenticates the state file's key tuples from the Anchor
/// and verifies the three documents under the keys valid at the adopted head.
#[test]
fn snapshot_keys_cases_cold_started_accept_or_reject_with_wist3_e04() {
    let vector = vector();
    let history = &vector["history"];
    assert_eq!(
        key_of(
            history["anchor"]["anchor"]["genesis_key"]["key_id"]
                .as_str()
                .unwrap()
        )
        .public_b64u(),
        history["anchor"]["anchor"]["genesis_key"]["public_key"]
    );
    let mut replayed = 0;
    for case in vector["cases"].as_array().unwrap() {
        if case.get("consumer_registry").is_some() {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let (dir, base_url) = serve(history, case);
        let target = tempfile::tempdir().unwrap();
        let outcome = graven::sync::run(
            dir.path().join("log/anchor.json").to_str().unwrap(),
            &base_url,
            target.path(),
            true,
            false,
        );
        let log_dir = graven::registry::log_dir(target.path(), history["log_id"].as_str().unwrap());
        match case["expected"].as_str().unwrap() {
            "accept" => {
                let report = outcome.unwrap_or_else(|e| panic!("{name}: {e}"));
                let adopted_head = case["adopted_head"].as_u64().unwrap();
                assert_eq!(report.head, adopted_head, "{name}");
                assert_eq!(
                    serde_json::json!(key_ids_valid_at(&log_dir, adopted_head)),
                    case["key_ids_at_adopted_head"],
                    "{name}"
                );
                common::assert_records_materialized(&log_dir);
            }
            code => {
                let error = outcome
                    .err()
                    .unwrap_or_else(|| panic!("{name} is rejected"))
                    .to_string();
                assert!(error.contains(code), "{name}: {error}");
                assert!(!log_dir.join("index.sqlite").exists(), "{name}");
            }
        }
        replayed += 1;
    }
    assert_eq!(replayed, 31);
}

fn cold_start(history: &Value, case: &Value, target: &Path) -> graven::sync::SyncReport {
    let (dir, base_url) = serve(history, case);
    graven::sync::run(
        dir.path().join("log/anchor.json").to_str().unwrap(),
        &base_url,
        target,
        true,
        false,
    )
    .unwrap_or_else(|e| panic!("{}: {e}", case["name"]))
}

fn holding_case(vector: &Value, verified_head: u64) -> &Value {
    let name = match verified_head {
        1 => "resume after the genesis key's removal",
        2 => "resume across a key addition",
        3 => "the index signed by a key added above the Snapshot's Epoch",
        other => panic!("no accept case adopts epoch {other}"),
    };
    let case = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    assert_eq!(case["adopted_head"], verified_head, "{name}");
    case
}

fn held_registry(log_dir: &Path) -> Vec<Value> {
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT key_id, public_key, added_height, removed_height FROM aggregator_keys ORDER BY key_id",
        )
        .unwrap();
    stmt.query_map([], |row| {
        Ok(serde_json::json!([
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<i64>>(3)?
        ]))
    })
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

fn sync_state(log_dir: &Path) -> graven::sync::SyncState {
    graven::sync::load_sync_state(&Connection::open(log_dir.join("index.sqlite")).unwrap())
        .unwrap()
        .unwrap()
}

fn table_dump(log_dir: &Path) -> std::collections::BTreeMap<String, Vec<String>> {
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
            let columns = stmt.column_count();
            let mut rows: Vec<String> = stmt
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| {
                            row.get::<_, rusqlite::types::Value>(i)
                                .map(|v| format!("{v:?}"))
                        })
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .map(|values| values.join("|"))
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            rows.sort();
            (table, rows)
        })
        .collect()
}

/// WIST-3 §7 and §8 "Catch-up decision".
#[test]
fn snapshot_keys_catch_up_cases_install_or_reject_against_the_held_registry() {
    let vector = vector();
    let history = &vector["history"];
    let log_id = history["log_id"].as_str().unwrap();
    let mut replayed = 0;
    for case in vector["cases"].as_array().unwrap() {
        let Some(consumer_registry) = case.get("consumer_registry") else {
            continue;
        };
        let name = case["name"].as_str().unwrap();
        let verified_head = consumer_registry["verified_head"].as_u64().unwrap();
        let target = tempfile::tempdir().unwrap();
        let log_dir = graven::registry::log_dir(target.path(), log_id);
        cold_start(history, holding_case(&vector, verified_head), target.path());
        if name == "a tuple for a key the Consumer's registry does not hold" {
            Connection::open(log_dir.join("index.sqlite"))
                .unwrap()
                .execute(
                    "DELETE FROM aggregator_keys WHERE key_id = 'test-snap-d'",
                    [],
                )
                .unwrap();
        }
        let expected_registry: Vec<Value> = consumer_registry["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| serde_json::json!([entry[1], entry[2], entry[3], entry[4]]))
            .collect();
        assert_eq!(held_registry(&log_dir), expected_registry, "{name}");
        let held = sync_state(&log_dir);
        assert_eq!(held.epoch_number, verified_head, "{name}");

        let (dir, base_url) = serve(history, case);
        let anchor = dir.path().join("log/anchor.json");
        let mut registered = graven::registry::load(target.path()).unwrap();
        registered.logs[0].anchor = anchor.to_str().unwrap().to_owned();
        registered.logs[0].base = base_url.clone();
        graven::registry::save(target.path(), &registered).unwrap();
        let report = graven::sync::follow(
            &graven::sync::Follow {
                anchor: anchor.to_str().unwrap(),
                log_base: &base_url,
                mirrors: &[],
                witnesses: &[],
                tier1: false,
                allow_http: true,
                catch_up_epochs: Some(0),
            },
            target.path(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(report.epoch_number_before, Some(verified_head), "{name}");
        assert_eq!(report.head, 3, "{name}");
        let caught_up = sync_state(&log_dir);
        match case["expected"].as_str().unwrap() {
            "accept" => {
                assert!(report.snapshot_rejected.is_none(), "{name}: {report}");
                assert_eq!(
                    serde_json::json!(key_ids_valid_at(&log_dir, 3)),
                    case["key_ids_at_adopted_head"],
                    "{name}"
                );
                assert_eq!(caught_up.walk_floor, Some(3), "{name}");
                let fresh = tempfile::tempdir().unwrap();
                graven::sync::run(
                    anchor.to_str().unwrap(),
                    &base_url,
                    fresh.path(),
                    true,
                    false,
                )
                .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    table_dump(&log_dir),
                    table_dump(&graven::registry::log_dir(fresh.path(), log_id)),
                    "{name}"
                );
            }
            code => {
                let rejection = report.snapshot_rejected.clone().unwrap_or_default();
                assert!(rejection.contains(code), "{name}: {report}");
                assert_eq!(caught_up.walk_floor, held.walk_floor, "{name}");
                assert_eq!(caught_up.content_digest, held.content_digest, "{name}");
            }
        }
        replayed += 1;
    }
    assert_eq!(replayed, 4);
}
