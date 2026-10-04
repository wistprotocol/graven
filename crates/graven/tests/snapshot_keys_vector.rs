mod common;

use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use wist_core::crypto::{hex_encode, PublicKey};
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

/// `tools/gen_vectors.py` `agg_key`.
fn key_of(key_id: &str) -> common::Signer {
    common::Signer::new(Sha256::digest(format!("wist aggregator snapshot {key_id}")).into())
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
/// and verifies the three documents under the keys valid at the adopted head. The cases that hold
/// a Consumer registry describe a catch-up through a Snapshot, which this Consumer does not make.
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
