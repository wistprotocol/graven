mod common;

use common::Signer;
use graven::store::MultiStore;
use serde_json::Value;
use std::path::PathBuf;
use wist_core::crypto::hex_decode;

fn load_vector() -> Value {
    let dir = std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"));
    let path = dir.join("vectors/multilog/dedup.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("reading spec vector at {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap()
}

struct LogFixture {
    _dir: tempfile::TempDir,
    anchor_path: PathBuf,
    base_url: String,
}

fn build_log_fixture(vector: &Value, log: &Value) -> LogFixture {
    let dir = tempfile::tempdir().unwrap();

    let anchor_path = dir.path().join("log/anchor.json");
    std::fs::create_dir_all(anchor_path.parent().unwrap()).unwrap();
    std::fs::write(&anchor_path, serde_json::to_vec(&log["anchor"]).unwrap()).unwrap();

    let seed_hex = log["genesis_seed_hex"].as_str().unwrap();
    let seed: [u8; 32] = hex_decode(seed_hex).unwrap().try_into().unwrap();
    let signer = Signer::new(seed);
    let mut published = common::Log::empty(
        dir.path(),
        Signer::new(seed),
        log["log_id"].as_str().unwrap(),
    );
    let mut anchor_root = String::new();
    let mut anchor_size = 0u64;
    for (index, epoch) in log["epochs"].as_array().unwrap().iter().enumerate() {
        let entries: Vec<Value> = epoch["entries"].as_array().cloned().unwrap_or_default();
        published.adopt(epoch["checkpoint"].as_str().unwrap(), &entries);
        if index == 0 {
            anchor_root = published.head().root_token();
            anchor_size = published.head().tree_size();
        }
    }

    let delta_id = vector["delta_id"].as_str().unwrap();
    let hex = delta_id.trim_start_matches("sha256:");
    common::write_payload(dir.path(), hex, &vector["payload"]);

    let domain = vector["publisher_declaration"]["publisher"]["domain"]
        .as_str()
        .unwrap()
        .to_string();
    let snapshot_date = "2026-08-02".to_string();
    let snapdir = dir.path().join("snapshots").join(&snapshot_date);

    let sqlite_bytes = common::write_tier0(&snapdir.join("tier0/index.sqlite"), &[]);
    let content_digest_value = wist_core::snapshot::content_digest(&[]).unwrap();

    // WIST-3 §7: the state carries an `aggregator_key` tuple for the
    // Anchor's genesis key, which this Log's Anchor names itself.
    let genesis = &log["anchor"]["anchor"]["genesis_key"];
    let (state_bytes, state_digest_value) = common::write_state_with(
        &snapdir.join("state.json"),
        &signer,
        3600,
        &[(domain, vector["publisher_declaration"].clone())],
        &[],
        anchor_size,
        vec![wist_core::objects::StateEntry::AggregatorKey(
            wist_core::objects::AggregatorKeyEntry {
                key_id: genesis["key_id"].as_str().unwrap().to_string(),
                public_key: genesis["public_key"].as_str().unwrap().to_string(),
                added_height: 0,
                removed_height: None,
            },
        )],
        0,
    );

    common::write_manifest(
        &snapdir.join("manifest.json"),
        &signer,
        &snapshot_date,
        0,
        anchor_size,
        &anchor_root,
        &content_digest_value,
        &state_bytes,
        &state_digest_value,
        &sqlite_bytes,
    );

    common::write_index(
        &dir.path().join("snapshots/index.json"),
        &signer,
        &snapshot_date,
        anchor_size,
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
    let vector = load_vector();

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
