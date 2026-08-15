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
        false,
    )
    .unwrap();

    assert_eq!(report.log_position_before, None);
    assert_eq!(report.head, 1);

    let sync_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target.path()).join("sync.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sync_json["log_position"], 0);
    assert_eq!(sync_json["head_number"], 1);
    assert!(sync_json["head_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    assert!(common::synced_log_dir(target.path())
        .join("index.sqlite")
        .exists());
    assert!(!common::synced_log_dir(target.path())
        .join("index.sqlite.verifying")
        .exists());

    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
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

    let report = graven::sync::run(&anchor_url, &fx.base_url, target.path(), true, false).unwrap();

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
        false,
    )
    .unwrap();
    assert_eq!(report.head, 1);

    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
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
        false,
    );

    assert!(result.is_err());
    assert!(!common::synced_log_dir(target.path())
        .join("sync.json")
        .exists());
    assert!(!common::synced_log_dir(target.path())
        .join("index.sqlite")
        .exists());
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
        false,
    );

    assert!(result.is_err());
    assert!(!common::synced_log_dir(target.path())
        .join("sync.json")
        .exists());
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
        false,
    );

    let err = result.unwrap_err().to_string();
    assert!(
        err.to_lowercase().contains("state_digest"),
        "error was: {err}"
    );
    assert!(!common::synced_log_dir(target.path())
        .join("sync.json")
        .exists());
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
        false,
    );

    assert!(result.is_err());
    assert!(!common::synced_log_dir(target.path())
        .join("sync.json")
        .exists());
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
        false,
    );

    assert!(result.is_err());
    assert!(!common::synced_log_dir(target.path())
        .join("sync.json")
        .exists());
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
        false,
    );

    assert!(result.is_err());
    assert!(!common::synced_log_dir(target.path())
        .join("index.sqlite")
        .exists());
    assert!(!common::synced_log_dir(target.path())
        .join("index.sqlite.verifying")
        .exists());
    assert!(!common::synced_log_dir(target.path())
        .join("sync.json")
        .exists());
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
        false,
    )
    .unwrap();
    assert_eq!(report1.head, 1);

    let new_url = common::extend_fixture(&fx);

    let report2 = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report2.head, 2);
    assert_eq!(report2.log_position_before, Some(1));

    let sync_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target.path()).join("sync.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sync_json["log_position"], 0);
    assert_eq!(sync_json["head_number"], 2);

    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
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
        false,
    )
    .unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
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
        false,
    )
    .unwrap();

    let old_checkpoint_bytes = std::fs::read(fx.dir.path().join("log/checkpoint.json")).unwrap();
    common::extend_fixture(&fx);

    let report2 = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
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
        false,
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
        false,
    )
    .unwrap();

    common::extend_fixture(&fx);
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
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
        false,
    );

    assert!(result.is_err());
}

#[test]
fn cold_sync_refuses_when_sync_json_already_exists() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    let log_dir = common::synced_log_dir(target.path());
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::write(log_dir.join("sync.json"), b"{}").unwrap();

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
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

    common::write_anchor(&dir.path().join("anchor.json"), &log, "graven-test-log");

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
        false,
    )
    .unwrap();
    assert_eq!(report.head, 1);

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
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

#[test]
fn delta_signed_by_undeclared_key_fails_sync() {
    let fx = common::build_fixture(true, false);
    common::extend_fixture_with_forged_delta(&fx);
    let dir = tempfile::tempdir().unwrap();
    let err = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("publisher verify"));
}

#[test]
fn delta_after_rotation_signed_by_old_key_fails_sync() {
    let fx = common::build_fixture(true, false);
    let old = common::Signer::new([1u8; 32]);
    let new_key = common::Signer::new([2u8; 32]);

    let checkpoint_path = fx.dir.path().join("log/checkpoint.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    let prev_number = doc["checkpoint"]["block_number"].as_u64().unwrap();
    let prev_hash = doc["checkpoint"]["block_hash"]
        .as_str()
        .unwrap()
        .to_string();

    let decl0 = common::build_declaration(&old, "pk1", &fx.domain);
    let hash0 = common::declaration_hash(&decl0);

    let rotation_number = prev_number + 1;
    let rotation_decl = common::build_declaration_full(
        &old,
        "pk1",
        &fx.domain,
        1,
        Some(&hash0),
        &[("pk2", &new_key, "2026-08-09T00:00:00Z")],
    );
    let wrapped_decl = serde_json::json!({"type": "publisher_declaration", "body": rotation_decl});
    let sealed_at1 = format!("2026-08-09T{:02}:00:00Z", 14 + rotation_number);
    let (block1, hash1) = common::build_block(
        &fx.log,
        rotation_number,
        &prev_hash,
        &sealed_at1,
        &[wrapped_decl],
    );
    common::write_block(fx.dir.path(), rotation_number, &block1);
    common::write_checkpoint(fx.dir.path(), &fx.log, rotation_number, &hash1, &sealed_at1);

    let delta_number = rotation_number + 1;
    let url = format!("https://records.example/extra-{delta_number}");
    let (_id, delta_env, _payload) =
        common::build_delta(&old, "pk1", &url, "Stale Title", None, "stale body", None);
    let wrapped_delta = serde_json::json!({"type": "publisher_delta", "body": delta_env});
    let sealed_at2 = format!("2026-08-09T{:02}:00:00Z", 14 + delta_number);
    let (block2, hash2) =
        common::build_block(&fx.log, delta_number, &hash1, &sealed_at2, &[wrapped_delta]);
    common::write_block(fx.dir.path(), delta_number, &block2);
    common::write_checkpoint(fx.dir.path(), &fx.log, delta_number, &hash2, &sealed_at2);

    let dir = tempfile::tempdir().unwrap();
    let err = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("publisher verify"));
}

#[test]
fn rotation_then_new_key_delta_syncs() {
    let fx = common::build_fixture(true, false);
    let new_key = common::Signer::new([2u8; 32]);
    let new_url = common::extend_fixture_with_rotation(&fx, &new_key);
    let dir = tempfile::tempdir().unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, 3);

    let store = Store::open(&common::synced_log_dir(dir.path())).unwrap();
    let record = store.get(&new_url).unwrap().unwrap();
    assert_eq!(record.title, "Rotated Title");
}

#[test]
fn incremental_sync_reloads_declarations() {
    let fx = common::build_fixture(true, false);
    let dir = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();

    let new_url = common::extend_fixture(&fx);

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, 2);

    let store = Store::open(&common::synced_log_dir(dir.path())).unwrap();
    let record = store.get(&new_url).unwrap().unwrap();
    assert_eq!(record.title, "Extra Title");
}

#[test]
fn withdrawal_removes_record_from_local_index() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let publisher = common::Signer::new([1u8; 32]);
    let (alpha_id, _, _) = common::build_delta(
        &publisher,
        "pk1",
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    common::extend_fixture_with_withdrawal(&fx, &alpha_id);

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.withdrawn, 1);

    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_none());
    assert!(store.get("https://records.example/beta").unwrap().is_some());
}

#[test]
fn withdrawal_for_unknown_delta_is_noop() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let unknown_id = format!("sha256:{}", "f".repeat(64));
    common::extend_fixture_with_withdrawal(&fx, &unknown_id);

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.withdrawn, 0);

    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_some());
    assert!(store.get("https://records.example/beta").unwrap().is_some());
}

#[test]
fn delete_delta_removes_record() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let publisher = common::Signer::new([1u8; 32]);
    let (alpha_id, _, _) = common::build_delta(
        &publisher,
        "pk1",
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    common::extend_fixture_with_delete(&fx, "https://records.example/alpha", &alpha_id);

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_none());
    assert!(store.get("https://records.example/beta").unwrap().is_some());
}

#[test]
fn cold_start_applies_withdrawals_after_snapshot_position() {
    let fx = common::build_fixture(true, false);
    let publisher = common::Signer::new([1u8; 32]);
    let (alpha_id, _, _) = common::build_delta(
        &publisher,
        "pk1",
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    common::extend_fixture_with_withdrawal(&fx, &alpha_id);

    let target = tempfile::tempdir().unwrap();
    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, 2);

    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_none());
    assert!(store.get("https://records.example/beta").unwrap().is_some());
}

#[test]
fn withdrawal_removes_tier1_and_embedding_rows_when_present() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let publisher = common::Signer::new([1u8; 32]);
    let (alpha_id, _, _) = common::build_delta(
        &publisher,
        "pk1",
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    conn.execute_batch(
        "CREATE TABLE extracts(url TEXT, publisher TEXT, delta_id TEXT, extract TEXT);
         CREATE TABLE links(source_url TEXT, target_url TEXT, position INTEGER);
         CREATE TABLE embeddings(delta_id TEXT PRIMARY KEY, url TEXT, publisher TEXT, vector BLOB);",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO extracts(url, publisher, delta_id, extract) VALUES (?1, ?2, ?3, ?4)",
        (
            "https://records.example/alpha",
            &fx.domain,
            &alpha_id,
            "alpha body",
        ),
    )
    .unwrap();
    conn.execute(
        "INSERT INTO links(source_url, target_url, position) VALUES (?1, ?2, ?3)",
        (
            "https://records.example/alpha",
            "https://records.example/other",
            0i64,
        ),
    )
    .unwrap();
    conn.execute(
        "INSERT INTO embeddings(delta_id, url, publisher, vector) VALUES (?1, ?2, ?3, ?4)",
        (
            &alpha_id,
            "https://records.example/alpha",
            &fx.domain,
            vec![0u8; 4],
        ),
    )
    .unwrap();
    drop(conn);

    common::extend_fixture_with_withdrawal(&fx, &alpha_id);
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let extracts_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM extracts", [], |r| r.get(0))
        .unwrap();
    let links_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM links", [], |r| r.get(0))
        .unwrap();
    let embeddings_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM embeddings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(extracts_count, 0);
    assert_eq!(links_count, 0);
    assert_eq!(embeddings_count, 0);
}

#[test]
fn failed_incremental_leaves_index_unchanged() {
    let fx = common::build_fixture(true, false);
    let dir = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();

    let sync_before = std::fs::read(common::synced_log_dir(dir.path()).join("sync.json")).unwrap();

    common::extend_fixture_with_forged_delta(&fx);

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    );
    assert!(result.is_err());

    let sync_after = std::fs::read(common::synced_log_dir(dir.path()).join("sync.json")).unwrap();
    assert_eq!(sync_before, sync_after);

    let store = Store::open(&common::synced_log_dir(dir.path())).unwrap();
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_some());
    assert!(store.get("https://records.example/beta").unwrap().is_some());
    assert!(store
        .get("https://records.example/extra-2")
        .unwrap()
        .is_none());

    let conn = Connection::open(common::synced_log_dir(dir.path()).join("index.sqlite")).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn sync_creates_registry_and_per_log_layout() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.log_id, "graven-test-log");

    let registry: graven::registry::Registry =
        serde_json::from_slice(&std::fs::read(target.path().join("logs.json")).unwrap()).unwrap();
    assert_eq!(registry.logs.len(), 1);
    assert_eq!(registry.logs[0].log_id, "graven-test-log");
    assert_eq!(registry.logs[0].anchor, fx.anchor_path().to_str().unwrap());
    assert_eq!(registry.logs[0].base, fx.base_url);
    assert!(!registry.logs[0].tier1);

    let log_dir = common::synced_log_dir(target.path());
    assert!(log_dir.join("index.sqlite").exists());
    assert!(log_dir.join("sync.json").exists());
    assert!(!target.path().join("index.sqlite").exists());
    assert!(!target.path().join("sync.json").exists());
}

#[test]
fn legacy_layout_migrates_on_sync() {
    let fx = common::build_fixture(true, false);
    let synced = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        synced.path(),
        true,
        false,
    )
    .unwrap();

    let legacy = tempfile::tempdir().unwrap();
    let synced_log_dir = common::synced_log_dir(synced.path());
    std::fs::copy(
        synced_log_dir.join("index.sqlite"),
        legacy.path().join("index.sqlite"),
    )
    .unwrap();
    std::fs::copy(
        synced_log_dir.join("sync.json"),
        legacy.path().join("sync.json"),
    )
    .unwrap();

    let new_url = common::extend_fixture(&fx);

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        legacy.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, 2);

    assert!(!legacy.path().join("index.sqlite").exists());
    assert!(!legacy.path().join("sync.json").exists());

    let migrated_dir = common::synced_log_dir(legacy.path());
    assert!(migrated_dir.join("index.sqlite").exists());
    assert!(migrated_dir.join("sync.json").exists());

    let registry: graven::registry::Registry =
        serde_json::from_slice(&std::fs::read(legacy.path().join("logs.json")).unwrap()).unwrap();
    assert_eq!(registry.logs.len(), 1);
    assert_eq!(registry.logs[0].log_id, "graven-test-log");

    let store = Store::open(&migrated_dir).unwrap();
    let extra = store.get(&new_url).unwrap().unwrap();
    assert_eq!(extra.title, "Extra Title");
}

#[test]
fn conflicting_base_for_same_log_id_errors() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        "http://127.0.0.1:1/different-base",
        target.path(),
        true,
        false,
    );

    assert!(result.is_err());
}

#[test]
fn run_all_syncs_every_registered_log() {
    let fx1 = common::build_fixture_with_log_id("log-one", 11);
    let fx2 = common::build_fixture_with_log_id("log-two", 12);
    let dir = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx1.anchor_path().to_str().unwrap(),
        &fx1.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    graven::sync::run(
        fx2.anchor_path().to_str().unwrap(),
        &fx2.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();

    let new_url1 = common::extend_fixture(&fx1);
    let new_url2 = common::extend_fixture(&fx2);

    let reports = graven::sync::run_all(dir.path(), true).unwrap();
    assert_eq!(reports.len(), 2);
    for report in &reports {
        assert_eq!(report.head, 2);
    }

    let store1 = Store::open(&graven::registry::log_dir(dir.path(), "log-one")).unwrap();
    assert!(store1.get(&new_url1).unwrap().is_some());
    let store2 = Store::open(&graven::registry::log_dir(dir.path(), "log-two")).unwrap();
    assert!(store2.get(&new_url2).unwrap().is_some());
}

#[test]
fn run_all_errors_clearly_on_unmigrated_legacy_dir() {
    let fx = common::build_fixture(true, false);
    let synced = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        synced.path(),
        true,
        false,
    )
    .unwrap();

    let legacy = tempfile::tempdir().unwrap();
    let synced_log_dir = common::synced_log_dir(synced.path());
    std::fs::copy(
        synced_log_dir.join("index.sqlite"),
        legacy.path().join("index.sqlite"),
    )
    .unwrap();
    std::fs::copy(
        synced_log_dir.join("sync.json"),
        legacy.path().join("sync.json"),
    )
    .unwrap();

    let err = graven::sync::run_all(legacy.path(), true).unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("sync") && msg.contains("anchor"),
        "error was: {msg}"
    );
}

#[test]
fn tier1_flag_is_sticky_once_enabled() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        true,
    )
    .unwrap();

    let registry: graven::registry::Registry =
        serde_json::from_slice(&std::fs::read(target.path().join("logs.json")).unwrap()).unwrap();
    assert!(registry.logs[0].tier1);

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let registry: graven::registry::Registry =
        serde_json::from_slice(&std::fs::read(target.path().join("logs.json")).unwrap()).unwrap();
    assert!(
        registry.logs[0].tier1,
        "tier1 must never be turned off by a later call that omits --tier1"
    );
}

#[test]
fn log_id_that_escapes_logs_dir_is_rejected() {
    let fx = common::build_fixture_with_log_id("..", 31);
    let target = tempfile::tempdir().unwrap();

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    );

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains(".."), "error was: {msg}");

    assert!(!target.path().join("index.sqlite").exists());
    assert!(!target.path().join("sync.json").exists());
    assert!(!target.path().join("logs.json").exists());
    assert!(!target.path().join("logs").exists());
}

#[test]
fn failed_migration_restores_legacy_layout_and_registers_nothing() {
    let fx_a = common::build_fixture(true, false);
    let fx_b = common::build_fixture_with_log_id("other-log", 21);

    let synced = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx_a.anchor_path().to_str().unwrap(),
        &fx_a.base_url,
        synced.path(),
        true,
        false,
    )
    .unwrap();

    let legacy = tempfile::tempdir().unwrap();
    let synced_log_dir = common::synced_log_dir(synced.path());
    std::fs::copy(
        synced_log_dir.join("index.sqlite"),
        legacy.path().join("index.sqlite"),
    )
    .unwrap();
    std::fs::copy(
        synced_log_dir.join("sync.json"),
        legacy.path().join("sync.json"),
    )
    .unwrap();

    // fixture content is deterministic, so two logs can coincidentally hash
    // identically at height 1; forge fx_b's hash to force equivocation.
    let forged_hash = format!("sha256:{}", "cd".repeat(32));
    common::write_checkpoint(
        fx_b.dir.path(),
        &fx_b.log,
        1,
        &forged_hash,
        "2026-08-09T13:00:00Z",
    );

    let result = graven::sync::run(
        fx_b.anchor_path().to_str().unwrap(),
        &fx_b.base_url,
        legacy.path(),
        true,
        false,
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("equivocation"),
        "error was: {err}"
    );

    assert!(legacy.path().join("index.sqlite").exists());
    assert!(legacy.path().join("sync.json").exists());
    assert!(!legacy.path().join("logs.json").exists());
    assert!(!graven::registry::log_dir(legacy.path(), "other-log").exists());

    let report = graven::sync::run(
        fx_a.anchor_path().to_str().unwrap(),
        &fx_a.base_url,
        legacy.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, 1);

    let migrated_dir = common::synced_log_dir(legacy.path());
    assert!(migrated_dir.join("index.sqlite").exists());
    assert!(migrated_dir.join("sync.json").exists());
    assert!(!legacy.path().join("index.sqlite").exists());
    assert!(!legacy.path().join("sync.json").exists());

    let store = Store::open(&migrated_dir).unwrap();
    let alpha = store.get("https://records.example/alpha").unwrap().unwrap();
    assert_eq!(alpha.title, "Alpha Title");
}

#[test]
fn cold_sync_with_tier1_flag_imports_extracts_and_links() {
    let fx = common::build_fixture_with_tier1();
    let target = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        true,
    )
    .unwrap();

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let (url, publisher, extract): (String, String, String) = conn
        .query_row("SELECT url, publisher, extract FROM extracts", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(url, "https://records.example/alpha");
    assert_eq!(publisher, fx.domain);
    assert_eq!(extract, "alpha body");

    let (source_url, target_url, position): (String, String, i64) = conn
        .query_row(
            "SELECT source_url, target_url, position FROM links",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(source_url, "https://records.example/alpha");
    assert_eq!(target_url, "https://records.example/other");
    assert_eq!(position, 0);

    let fts_extract: String = conn
        .query_row(
            "SELECT extract FROM extracts_fts WHERE extracts_fts MATCH 'alpha'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fts_extract, "alpha body");
}

#[test]
fn cold_sync_without_tier1_flag_leaves_extracts_absent() {
    let fx = common::build_fixture_with_tier1();
    let target = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let table_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'extracts'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(table_count, 0);
}

#[test]
fn mid_migration_rename_failure_restores_first_file_via_public_api() {
    let fx = common::build_fixture(true, false);
    let dir = tempfile::tempdir().unwrap();

    std::fs::write(dir.path().join("index.sqlite"), b"legacy-index-bytes").unwrap();
    std::fs::write(dir.path().join("sync.json"), b"legacy-sync-bytes").unwrap();

    let target_dir = graven::registry::log_dir(dir.path(), "graven-test-log");
    std::fs::create_dir_all(target_dir.join("sync.json")).unwrap();

    let result = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    );

    assert!(result.is_err());
    assert_eq!(
        std::fs::read(dir.path().join("index.sqlite")).unwrap(),
        b"legacy-index-bytes"
    );
    assert!(!target_dir.join("index.sqlite").exists());
    assert!(!dir.path().join("logs.json").exists());
}

#[test]
fn incremental_sync_with_tier1_populates_extract_for_new_url() {
    let fx = common::build_fixture_with_tier1();
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        true,
    )
    .unwrap();

    let new_url = common::extend_fixture(&fx);

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        true,
    )
    .unwrap();

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let extract: String = conn
        .query_row(
            "SELECT extract FROM extracts WHERE url = ?1",
            [&new_url],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(extract, "extra body");
}

#[test]
fn incremental_sync_with_tier1_replaces_links_and_extract_on_update() {
    let fx = common::build_fixture_with_tier1();
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        true,
    )
    .unwrap();

    let publisher = common::Signer::new([1u8; 32]);
    let (alpha_id, _, _) = common::build_delta(
        &publisher,
        "pk1",
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );

    let checkpoint_path = fx.dir.path().join("log/checkpoint.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    let prev_number = doc["checkpoint"]["block_number"].as_u64().unwrap();
    let prev_hash = doc["checkpoint"]["block_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let next_number = prev_number + 1;

    let (id2, delta2_env, payload2) = common::build_delta_with_links(
        &publisher,
        "pk1",
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body v2",
        &["https://records.example/second"],
        Some(&alpha_id),
    );
    let hex2 = id2.strip_prefix("sha256:").unwrap();
    common::write_payload(fx.dir.path(), hex2, &payload2);
    let wrapped_delta2 = serde_json::json!({"type": "publisher_delta", "body": delta2_env});

    let sealed_at = format!("2026-08-09T{:02}:00:00Z", 14 + next_number);
    let (block, new_hash) = common::build_block(
        &fx.log,
        next_number,
        &prev_hash,
        &sealed_at,
        &[wrapped_delta2],
    );
    common::write_block(fx.dir.path(), next_number, &block);
    common::write_checkpoint(fx.dir.path(), &fx.log, next_number, &new_hash, &sealed_at);

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        true,
    )
    .unwrap();

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let extract: String = conn
        .query_row(
            "SELECT extract FROM extracts WHERE url = ?1",
            ["https://records.example/alpha"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(extract, "alpha body v2");

    let mut stmt = conn
        .prepare("SELECT target_url, position FROM links WHERE source_url = ?1 ORDER BY position")
        .unwrap();
    let rows: Vec<(String, i64)> = stmt
        .query_map(["https://records.example/alpha"], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![("https://records.example/second".to_string(), 0)]
    );
}

#[test]
fn incremental_sync_leaves_tier1_absent_when_payload_fetch_fails() {
    let fx = common::build_fixture_with_tier1();
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        true,
    )
    .unwrap();

    let publisher = common::Signer::new([1u8; 32]);
    let checkpoint_path = fx.dir.path().join("log/checkpoint.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    let prev_number = doc["checkpoint"]["block_number"].as_u64().unwrap();
    let prev_hash = doc["checkpoint"]["block_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let next_number = prev_number + 1;

    let url = "https://records.example/no-payload".to_string();
    let (_id, delta_env, _payload) = common::build_delta(
        &publisher,
        "pk1",
        &url,
        "No Payload Title",
        None,
        "unreachable extract",
        None,
    );
    let wrapped_delta = serde_json::json!({"type": "publisher_delta", "body": delta_env});

    let sealed_at = format!("2026-08-09T{:02}:00:00Z", 14 + next_number);
    let (block, new_hash) = common::build_block(
        &fx.log,
        next_number,
        &prev_hash,
        &sealed_at,
        &[wrapped_delta],
    );
    common::write_block(fx.dir.path(), next_number, &block);
    common::write_checkpoint(fx.dir.path(), &fx.log, next_number, &new_hash, &sealed_at);

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        true,
    )
    .unwrap();

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let title: String = conn
        .query_row("SELECT title FROM records WHERE url = ?1", [&url], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(title, "");

    let extract_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM extracts WHERE url = ?1",
            [&url],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(extract_count, 0);
}
