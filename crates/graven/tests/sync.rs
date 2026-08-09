mod common;

use graven::store::Store;
use rusqlite::Connection;

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
fn cold_sync_rejects_wrong_state_digest_in_manifest() {
    let fx = common::build_fixture(true, false);
    common::corrupt_state_digest(fx.dir.path(), &fx.log, &fx.snapshot_date);

    let target = tempfile::tempdir().unwrap();
    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.to_lowercase().contains("state_digest"),
        "error was: {err}"
    );
    assert!(!target.path().join("sync.json").exists());
}

#[test]
fn cold_sync_rejects_state_signed_by_wrong_key() {
    let fx = common::build_fixture(true, false);
    common::resign_state_with_wrong_key(fx.dir.path(), &fx.log, &fx.other, &fx.snapshot_date);

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
fn continuous_sync_advances_head_and_applies_new_delta() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();

    let report1 = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();
    assert_eq!(report1.head, 1);

    let new_url = common::extend_fixture(&fx);

    let report2 = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();
    assert_eq!(report2.head, 2);
    assert_eq!(report2.log_position_before, Some(1));

    let sync_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(target.path().join("sync.json")).unwrap()).unwrap();
    assert_eq!(sync_json["log_position"], 0);
    assert_eq!(sync_json["head_number"], 2);

    let store = Store::open(target.path()).unwrap();
    let extra = store.get(&new_url).unwrap().unwrap();
    assert_eq!(extra.title, "Extra Title");
    assert_eq!(extra.r#abstract.as_deref(), Some("Extra abstract"));

    let alpha = store.get("https://records.example/alpha").unwrap();
    assert!(alpha.is_some());
}

#[test]
fn continuous_sync_is_noop_when_checkpoint_unchanged() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();

    assert_eq!(report.head, 1);
    assert_eq!(report.log_position_before, Some(1));
}

#[test]
fn continuous_sync_rejects_rollback_checkpoint() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();

    let old_checkpoint_bytes = std::fs::read(fx.dir.path().join("log/checkpoint.json")).unwrap();
    common::extend_fixture(&fx);

    let report2 = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();
    assert_eq!(report2.head, 2);

    std::fs::write(
        fx.dir.path().join("log/checkpoint.json"),
        &old_checkpoint_bytes,
    )
    .unwrap();

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    );

    let err = result.unwrap_err().to_string();
    assert!(err.to_lowercase().contains("rollback"), "error was: {err}");
}

#[test]
fn continuous_sync_rejects_same_height_different_hash_checkpoint() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();

    common::extend_fixture(&fx);
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    )
    .unwrap();

    let forged_hash = format!("sha256:{}", "ab".repeat(32));
    common::write_checkpoint(
        fx.dir.path(),
        &fx.log,
        2,
        &forged_hash,
        "2026-08-09T20:00:00Z",
    );

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
    );

    assert!(result.is_err());
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

#[test]
fn continuous_sync_upserts_update_delta_preserving_publisher_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = common::Signer::new([9u8; 32]);
    let publisher = common::Signer::new([1u8; 32]);
    let domain = "records.example:8443".to_string();
    let snapshot_date = "2026-08-09".to_string();
    let url = "https://records.example:8443/alpha".to_string();

    common::write_anchor(&dir.path().join("anchor.json"), &log);

    let declaration_env = common::build_declaration(&publisher, "pk1", &domain);
    let wrapped_declaration =
        serde_json::json!({"type": "publisher_declaration", "body": declaration_env});

    let (id1, delta1_env, payload1) = common::build_delta(
        &publisher,
        "pk1",
        &url,
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    let hex1 = id1.strip_prefix("sha256:").unwrap();
    common::write_payload(dir.path(), hex1, &payload1);
    let wrapped_delta1 = serde_json::json!({"type": "publisher_delta", "body": delta1_env});

    let (block0, block0_hash) = common::build_block(
        &log,
        0,
        "sha256:genesis",
        "2026-08-09T12:00:00Z",
        &[wrapped_declaration, wrapped_delta1],
    );
    common::write_block(dir.path(), 0, &block0);

    let record1 = common::RecordFixture {
        url: url.clone(),
        publisher: domain.clone(),
        delta_id: id1.clone(),
        observed_at: "2026-08-09T12:00:00Z".into(),
        weight: "full".into(),
        title: "Alpha Title".into(),
        abstract_text: Some("Alpha abstract".into()),
        lang: "en".into(),
    };

    let snapdir = dir.path().join("snapshots").join(&snapshot_date);
    let sqlite_bytes = common::write_tier0(
        &snapdir.join("tier0/index.sqlite"),
        std::slice::from_ref(&record1),
    );
    let content_digest_value = wist_core::snapshot::content_digest(&[serde_json::json!({
        "url": record1.url,
        "publisher": record1.publisher,
        "delta_id": record1.delta_id,
        "observed_at": record1.observed_at,
        "weight": record1.weight,
    })])
    .unwrap();

    let (state_bytes, state_digest_value) = common::write_state(
        &snapdir.join("state.json"),
        &log,
        3600,
        &[(domain.clone(), declaration_env.clone())],
        std::slice::from_ref(&record1),
        0,
    );

    common::write_manifest(
        &snapdir.join("manifest.json"),
        &log,
        &snapshot_date,
        0,
        &block0_hash,
        &content_digest_value,
        &state_bytes,
        &state_digest_value,
        &sqlite_bytes,
    );

    common::write_index(
        &dir.path().join("snapshots/index.json"),
        &log,
        &snapshot_date,
        0,
        &format!("/snapshots/{snapshot_date}/manifest.json"),
        &content_digest_value,
    );

    let (id2, delta2_env, payload2) = common::build_delta(
        &publisher,
        "pk1",
        &url,
        "Alpha Title",
        Some("Alpha abstract updated"),
        "alpha body updated",
        Some(&id1),
    );
    let hex2 = id2.strip_prefix("sha256:").unwrap();
    common::write_payload(dir.path(), hex2, &payload2);
    let wrapped_delta2 = serde_json::json!({"type": "publisher_delta", "body": delta2_env});

    let (block1, block1_hash) = common::build_block(
        &log,
        1,
        &block0_hash,
        "2026-08-09T13:00:00Z",
        &[wrapped_delta2],
    );
    common::write_block(dir.path(), 1, &block1);
    common::write_checkpoint(dir.path(), &log, 1, &block1_hash, "2026-08-09T13:00:00Z");

    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));

    let target = tempfile::tempdir().unwrap();
    let report = graven::sync::run(
        dir.path().join("anchor.json").to_str().unwrap(),
        &base_url,
        target.path(),
        true,
    )
    .unwrap();
    assert_eq!(report.head, 1);

    let conn = Connection::open(target.path().join("index.sqlite")).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM records WHERE url = ?1", [&url], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        count, 1,
        "an update delta to an already-snapshotted URL must upsert in place, not duplicate the row"
    );

    let (publisher_col, delta_id_col, title_col): (String, String, String) = conn
        .query_row(
            "SELECT publisher, delta_id, title FROM records WHERE url = ?1",
            [&url],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        publisher_col, domain,
        "the materialized publisher must preserve the URL's port"
    );
    assert_eq!(
        delta_id_col, id2,
        "the materialized record must reflect the update delta, not the snapshot original"
    );
    assert_eq!(title_col, "Alpha Title");
}
