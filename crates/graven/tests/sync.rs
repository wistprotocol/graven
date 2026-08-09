mod common;

use graven::store::Store;

#[test]
fn cold_sync_verifies_chain_and_populates_store() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();

    assert_eq!(report.log_position_before, None);
    assert_eq!(report.head, 1);

    let sync_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(target.path().join("sync.json")).unwrap()).unwrap();
    assert_eq!(sync_json["log_position"], 0);
    assert_eq!(sync_json["head_number"], 1);
    assert!(sync_json["head_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    assert!(target.path().join("index.sqlite").exists());
    assert!(!target.path().join("index.sqlite.verifying").exists());

    let store = Store::open(target.path()).unwrap();
    let alpha = store.get("https://records.example/alpha").unwrap().unwrap();
    assert_eq!(alpha.title, "Alpha Title");
    assert_eq!(alpha.publisher, fx.domain);
    assert_eq!(alpha.weight, "full");

    let beta = store.get("https://records.example/beta").unwrap().unwrap();
    assert_eq!(beta.title, "Beta Title");
    assert_eq!(beta.r#abstract.as_deref(), Some("Beta abstract"));
    assert_eq!(beta.publisher, fx.domain);

    let hits = store.search("Beta", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].url, "https://records.example/beta");
}

#[test]
fn cold_sync_accepts_anchor_fetched_over_http() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    let anchor_url = format!("{}/anchor.json", fx.base_url);

    let report = graven::sync::run(&anchor_url, &fx.base_url, target.path(), true).unwrap();

    assert_eq!(report.head, 1);
}

#[test]
fn cold_sync_records_post_snapshot_delta_with_unfetchable_payload_as_empty() {
    let fx = common::build_fixture(false, false);
    let target = tempfile::tempdir().unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();
    assert_eq!(report.head, 1);

    let store = Store::open(target.path()).unwrap();
    let beta = store.get("https://records.example/beta").unwrap().unwrap();
    assert_eq!(beta.title, "");
    assert!(beta.r#abstract.is_none());
}

#[test]
fn cold_sync_rejects_tampered_block_file() {
    let fx = common::build_fixture(true, false);
    let block1_path = fx.dir.path().join("log/blocks/000000001.json.zst");
    let mut bytes = std::fs::read(&block1_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&block1_path, bytes).unwrap();

    let target = tempfile::tempdir().unwrap();
    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    );

    assert!(result.is_err());
    assert!(!target.path().join("sync.json").exists());
    assert!(!target.path().join("index.sqlite").exists());
}

#[test]
fn cold_sync_rejects_wrong_manifest_content_digest() {
    let fx = common::build_fixture(true, false);
    common::corrupt_manifest_content_digest(fx.dir.path(), &fx.log, &fx.snapshot_date);

    let target = tempfile::tempdir().unwrap();
    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    );

    assert!(result.is_err());
    assert!(!target.path().join("sync.json").exists());
}

#[test]
fn cold_sync_rejects_checkpoint_signed_by_wrong_key() {
    let fx = common::build_fixture(true, false);
    common::resign_checkpoint_with_wrong_key(fx.dir.path(), &fx.other);

    let target = tempfile::tempdir().unwrap();
    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    );

    assert!(result.is_err());
    assert!(!target.path().join("sync.json").exists());
}

#[test]
fn cold_sync_leaves_no_partial_state_when_tier0_mutation_fails() {
    let fx = common::build_fixture(true, true);
    let target = tempfile::tempdir().unwrap();

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    );

    assert!(result.is_err());
    assert!(!target.path().join("index.sqlite").exists());
    assert!(!target.path().join("index.sqlite.verifying").exists());
    assert!(!target.path().join("sync.json").exists());
}

#[test]
fn cold_sync_refuses_when_sync_json_already_exists() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("sync.json"), b"{}").unwrap();

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    );

    assert!(result.is_err());
}
