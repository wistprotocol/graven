mod common;

use common::Signer;
use graven::store::MultiStore;
use serde_json::Value;
use std::path::{Path, PathBuf};
use wist_core::crypto::hex_decode;

fn load_vector() -> Option<Value> {
    let dir = std::env::var("WIST_SPEC_DIR").ok()?;
    let path = Path::new(&dir).join("vectors/multilog/dedup.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("reading spec vector at {}: {e}", path.display()));
    Some(serde_json::from_slice(&bytes).unwrap())
}

struct LogFixture {
    _dir: tempfile::TempDir,
    anchor_path: PathBuf,
    base_url: String,
}

fn build_log_fixture(vector: &Value, log: &Value) -> LogFixture {
    let dir = tempfile::tempdir().unwrap();

    let anchor_path = dir.path().join("anchor.json");
    std::fs::write(&anchor_path, serde_json::to_vec(&log["anchor"]).unwrap()).unwrap();

    for block in log["blocks"].as_array().unwrap() {
        let number = block["header"]["block_number"].as_u64().unwrap();
        common::write_block(dir.path(), number, block);
    }

    let checkpoint_path = dir.path().join("log/checkpoint.json");
    std::fs::create_dir_all(checkpoint_path.parent().unwrap()).unwrap();
    std::fs::write(
        &checkpoint_path,
        serde_json::to_vec(&log["checkpoint"]).unwrap(),
    )
    .unwrap();

    let delta_id = vector["delta_id"].as_str().unwrap();
    let hex = delta_id.trim_start_matches("sha256:");
    common::write_payload(dir.path(), hex, &vector["payload"]);

    let seed_hex = log["genesis_seed_hex"].as_str().unwrap();
    let seed: [u8; 32] = hex_decode(seed_hex).unwrap().try_into().unwrap();
    let signer = Signer::new(seed);

    let block0_header = &log["blocks"][0]["header"];
    let anchor_block_hash = wist_core::block::block_hash(block0_header).unwrap();

    let domain = vector["publisher_declaration"]["publisher"]["domain"]
        .as_str()
        .unwrap()
        .to_string();
    let snapshot_date = "2026-08-02".to_string();
    let snapdir = dir.path().join("snapshots").join(&snapshot_date);

    let sqlite_bytes = common::write_tier0(&snapdir.join("tier0/index.sqlite"), &[]);
    let content_digest_value = wist_core::snapshot::content_digest(&[]).unwrap();

    let (state_bytes, state_digest_value) = common::write_state(
        &snapdir.join("state.json"),
        &signer,
        3600,
        &[(domain, vector["publisher_declaration"].clone())],
        &[],
        0,
    );

    common::write_manifest(
        &snapdir.join("manifest.json"),
        &signer,
        &snapshot_date,
        0,
        &anchor_block_hash,
        &content_digest_value,
        &state_bytes,
        &state_digest_value,
        &sqlite_bytes,
    );

    common::write_index(
        &dir.path().join("snapshots/index.json"),
        &signer,
        &snapshot_date,
        0,
        &format!("/snapshots/{snapshot_date}/manifest.json"),
        &content_digest_value,
    );

    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
    LogFixture {
        _dir: dir,
        anchor_path,
        base_url,
    }
}

#[test]
fn multilog_dedup_vector() {
    let Some(vector) = load_vector() else {
        println!("skip: WIST_SPEC_DIR not set, skipping spec multi-log dedup vector test");
        return;
    };

    let logs = vector["logs"].as_array().unwrap();
    let fixtures: Vec<LogFixture> = logs
        .iter()
        .map(|log| build_log_fixture(&vector, log))
        .collect();

    let target = tempfile::tempdir().unwrap();
    for fixture in &fixtures {
        graven::sync::run(
            fixture.anchor_path.to_str().unwrap(),
            &fixture.base_url,
            target.path(),
            true,
            false,
        )
        .unwrap();
    }

    let store = MultiStore::open_read_only(target.path()).unwrap();
    assert_eq!(store.logs().len(), logs.len());

    let expected = vector["expected"]["merged_records"].as_array().unwrap();
    assert_eq!(expected.len(), 1);
    let expected = &expected[0];
    let url = expected["url"].as_str().unwrap();

    let hit = store.get(url).unwrap().expect("merged record present");
    assert_eq!(hit.url, url);
    assert_eq!(hit.publisher, expected["publisher"].as_str().unwrap());
    assert_eq!(hit.delta_id, expected["delta_id"].as_str().unwrap());

    let mut sources: Vec<&str> = hit.provenance.iter().map(|p| p.log_id.as_str()).collect();
    sources.sort_unstable();
    let mut expected_sources: Vec<&str> = expected["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    expected_sources.sort_unstable();
    assert_eq!(sources, expected_sources);
}
