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

    assert_eq!(report.block_number_before, None);
    assert_eq!(report.head, 1);

    let sync_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target.path()).join("sync.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sync_json["block_number"], 1);
    assert_eq!(sync_json["log_position"], fx.head_tree_size());
    assert!(sync_json["root"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(sync_json["unwitnessed"], true);

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
    let anchor_url = format!("{}/log/anchor.json", fx.base_url);

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

/// WIST-3 §6: an entry bundle is verified only by recomputation against
/// the root a verified Checkpoint states, so altered octets are
/// `WIST3-E03` and nothing above the head is applied.
#[test]
fn cold_sync_rejects_a_tampered_entry_bundle() {
    let fx = common::build_fixture(true, false);
    let bundle = fx
        .dir
        .path()
        .join(format!("tile/entries/000.p/{}", fx.head_tree_size()));
    let mut bytes = std::fs::read(&bundle).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&bundle, bytes).unwrap();

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
    common::resign_checkpoint_with_wrong_key(&fx, &fx.other);

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
    assert_eq!(report2.block_number_before, Some(1));

    let sync_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target.path()).join("sync.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sync_json["block_number"], 2);

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
    assert_eq!(report.block_number_before, Some(1));
}

#[test]
fn a_checkpoint_below_the_verified_head_does_not_regress_it_and_is_no_error() {
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

    let old_checkpoint_bytes = std::fs::read(fx.dir.path().join("checkpoint")).unwrap();
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

    std::fs::write(fx.dir.path().join("checkpoint"), &old_checkpoint_bytes).unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    assert_eq!(
        report.head, 2,
        "WIST-3 §5: a source serving an old Checkpoint has shown only that it is behind; the verified head stands and there is no error code"
    );
    assert_eq!(
        graven::store::synced_state(&common::synced_log_dir(target.path()))
            .unwrap()
            .block_number,
        2
    );
}

#[test]
fn a_differing_checkpoint_at_a_retained_block_number_is_equivocation_with_an_evidence_bundle() {
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

    common::forge_head_note(&fx, [0xab; 32], &fx.log);

    let error = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("WIST3-E02"), "error was: {error}");
    let bundle =
        common::synced_log_dir(target.path()).join("evidence/equivocation-block-000000002");
    assert!(
        bundle.join("retained.checkpoint").exists() && bundle.join("offered.checkpoint").exists(),
        "both Checkpoints must be preserved in {}",
        bundle.display()
    );
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
fn continuous_sync_upserts_update_delta_preserving_signed_publisher() {
    let dir = tempfile::tempdir().unwrap();
    let log = common::Signer::new([9u8; 32]);
    let publisher = common::Signer::new([1u8; 32]);
    let domain = "records.example".to_string();
    let snapshot_date = "2026-08-09".to_string();
    let url = "https://records.example/alpha".to_string();

    let mut state = common::Log::new(
        dir.path(),
        common::Signer::new([9u8; 32]),
        "graven-test-log",
    );

    let declaration_env = common::build_declaration(&publisher, &domain);
    let wrapped_declaration =
        serde_json::json!({"type": "publisher_declaration", "body": declaration_env});

    let (id1, delta1_env, payload1) = common::build_delta(
        &publisher,
        &url,
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    let hex1 = id1.strip_prefix("sha256:").unwrap();
    common::write_payload(dir.path(), hex1, &payload1);
    let wrapped_delta1 = serde_json::json!({"type": "publisher_delta", "body": delta1_env});

    let block0 = state.seal(
        "2026-08-09T12:00:00Z",
        &[wrapped_declaration, wrapped_delta1],
    );

    let record1 = common::RecordFixture {
        url: url.clone(),
        publisher: domain.clone(),
        delta_id: id1.clone(),
        observed_at: "2026-08-09T12:00:00Z".into(),
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
    })])
    .unwrap();

    let (state_bytes, state_digest_value) = common::write_state(
        &snapdir.join("state.json"),
        &log,
        3600,
        &[(domain.clone(), declaration_env.clone())],
        std::slice::from_ref(&record1),
        block0.tree_size(),
    );

    common::write_manifest(
        &snapdir.join("manifest.json"),
        &log,
        &snapshot_date,
        0,
        block0.tree_size(),
        &block0.root_token(),
        &content_digest_value,
        &state_bytes,
        &state_digest_value,
        &sqlite_bytes,
    );

    common::write_index(
        &dir.path().join("snapshots/index.json"),
        &log,
        &snapshot_date,
        block0.tree_size(),
        &format!("/snapshots/{snapshot_date}/manifest.json"),
        &content_digest_value,
    );

    let (id2, delta2_env, payload2) = common::build_delta(
        &publisher,
        &url,
        "Alpha Title",
        Some("Alpha abstract updated"),
        "alpha body updated",
        Some(&id1),
    );
    let hex2 = id2.strip_prefix("sha256:").unwrap();
    common::write_payload(dir.path(), hex2, &payload2);
    let wrapped_delta2 = serde_json::json!({"type": "publisher_delta", "body": delta2_env});

    state.seal("2026-08-09T13:00:00Z", &[wrapped_delta2]);

    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));

    let target = tempfile::tempdir().unwrap();
    let report = graven::sync::run(
        dir.path().join("log/anchor.json").to_str().unwrap(),
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
fn delta_signed_by_undeclared_key_is_ignored_like_a_fork() {
    let fx = common::build_fixture(true, false);
    common::extend_fixture_with_forged_delta(&fx);
    let dir = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    let store = Store::open(&common::synced_log_dir(dir.path())).unwrap();
    assert!(store
        .get("https://records.example/extra-2")
        .unwrap()
        .is_none());
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_some());
}

#[test]
fn delta_after_rotation_signed_by_old_key_is_ignored_like_a_fork() {
    let fx = common::build_fixture(true, false);
    let old = common::Signer::new([1u8; 32]);
    let new_key = common::Signer::new([2u8; 32]);

    let decl0 = common::build_declaration(&old, &fx.domain);
    let hash0 = common::declaration_hash(&decl0);

    let rotation_decl = common::build_declaration_full(
        &old,
        &fx.domain,
        1,
        Some(&hash0),
        &[(&new_key, "2026-08-09T00:00:00Z")],
    );
    let at = common::next_instant(&fx);
    common::seal_next(
        &fx,
        &at,
        &[serde_json::json!({"type": "publisher_declaration", "body": rotation_decl})],
    );

    let delta_number = fx.head_number() + 1;
    let url = format!("https://records.example/extra-{delta_number}");
    let (_id, delta_env, _payload) =
        common::build_delta(&old, &url, "Stale Title", None, "stale body", None);
    let at = common::next_instant(&fx);
    common::seal_next(
        &fx,
        &at,
        &[serde_json::json!({"type": "publisher_delta", "body": delta_env})],
    );

    let dir = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    let store = Store::open(&common::synced_log_dir(dir.path())).unwrap();
    assert!(store.get(&url).unwrap().is_none());
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
fn an_ignored_delta_leaves_the_index_unchanged() {
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

    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();

    let sync_after = std::fs::read(common::synced_log_dir(dir.path()).join("sync.json")).unwrap();
    assert_ne!(
        sync_before, sync_after,
        "the sync advances past a Block whose only Delta is ignored"
    );

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
fn distinct_log_ids_that_sanitize_identically_are_rejected() {
    let fx1 = common::build_fixture_with_log_id("host:9", 13);
    let fx2 = common::build_fixture_with_log_id("host-9", 14);
    let dir = tempfile::tempdir().unwrap();

    graven::sync::run(
        fx1.anchor_path().to_str().unwrap(),
        &fx1.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();

    let store_before = Store::open(&graven::registry::log_dir(dir.path(), "host:9")).unwrap();
    let alpha_before = store_before
        .get("https://records.example/alpha")
        .unwrap()
        .unwrap();

    let result = graven::sync::run(
        fx2.anchor_path().to_str().unwrap(),
        &fx2.base_url,
        dir.path(),
        true,
        false,
    );

    let err = result.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("host:9") && msg.contains("host-9"),
        "error should name both colliding log_ids, was: {msg}"
    );

    let registry: graven::registry::Registry =
        serde_json::from_slice(&std::fs::read(dir.path().join("logs.json")).unwrap()).unwrap();
    assert_eq!(
        registry.logs.len(),
        1,
        "rejected registration must not add a second entry"
    );

    let store_after = Store::open(&graven::registry::log_dir(dir.path(), "host:9")).unwrap();
    let alpha_after = store_after
        .get("https://records.example/alpha")
        .unwrap()
        .unwrap();
    assert_eq!(
        alpha_before.delta_id, alpha_after.delta_id,
        "the surviving log's index must be untouched by the rejected collision"
    );
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

    // The second Log's Checkpoints carry its own origin line and its own
    // key, so its Checkpoint 1 differs from the one the migrated store
    // retains at that Block and no key valid there signs it: WIST3-E03,
    // and the migration is rolled back.

    let result = graven::sync::run(
        fx_b.anchor_path().to_str().unwrap(),
        &fx_b.base_url,
        legacy.path(),
        true,
        false,
    );
    let err = result.unwrap_err();
    assert!(err.to_string().contains("WIST3-E03"), "error was: {err}");
    assert!(
        !graven::registry::log_dir(legacy.path(), "other-log")
            .join("evidence")
            .exists(),
        "a Checkpoint no valid key signs is preserved as nothing"
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
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );

    let (id2, delta2_env, payload2) = common::build_delta_with_links(
        &publisher,
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

    let sealed_at = common::next_instant(&fx);
    common::seal_next(&fx, &sealed_at, &[wrapped_delta2]);

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

    let url = "https://records.example/no-payload".to_string();
    let (_id, delta_env, _payload) = common::build_delta(
        &publisher,
        &url,
        "No Payload Title",
        None,
        "unreachable extract",
        None,
    );
    let wrapped_delta = serde_json::json!({"type": "publisher_delta", "body": delta_env});

    let sealed_at = common::next_instant(&fx);
    common::seal_next(&fx, &sealed_at, &[wrapped_delta]);

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

#[test]
fn incremental_sync_purges_stale_tier1_rows_when_update_payload_fetch_fails() {
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
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );

    let (id2, delta2_env, _payload2) = common::build_delta(
        &publisher,
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body v2",
        Some(&alpha_id),
    );
    let wrapped_delta2 = serde_json::json!({"type": "publisher_delta", "body": delta2_env});

    let sealed_at = common::next_instant(&fx);
    common::seal_next(&fx, &sealed_at, &[wrapped_delta2]);

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
    let (delta_id, title): (String, String) = conn
        .query_row(
            "SELECT delta_id, title FROM records WHERE url = ?1",
            ["https://records.example/alpha"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        delta_id, id2,
        "record must reflect the failed-fetch update delta"
    );
    assert_eq!(title, "");

    let extract_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM extracts WHERE url = ?1",
            ["https://records.example/alpha"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        extract_count, 0,
        "stale extract from the prior successful sync must not survive a failed-fetch update"
    );

    let links_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM links WHERE source_url = ?1",
            ["https://records.example/alpha"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        links_count, 0,
        "stale links from the prior successful sync must not survive a failed-fetch update"
    );
}

#[test]
fn a_manifest_disagreeing_with_its_index_entry_is_rejected() {
    let fx = common::build_fixture(true, false);
    let index_path = fx.dir.path().join("snapshots/index.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
    let mut index = doc["index"].clone();
    index["snapshots"][0]["content_digest"] = format!("sha256:{}", "9".repeat(64)).into();
    let envelope = wist_core::envelope::sign_envelope(&index, "index", "log1", &fx.log.sk).unwrap();
    std::fs::write(&index_path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let err = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("WIST3-E04"), "{err}");
}

#[test]
fn a_log_that_rotates_its_aggregator_key_stays_syncable() {
    let fx = common::build_fixture(true, false);
    let next = common::Signer::new([21u8; 32]);

    let add = common::key_act(
        &fx,
        "aggregator_key_add",
        "log1",
        &fx.log,
        "log2",
        Some(&next),
        "2026-08-09T15:00:00Z",
    );
    let sealed_at = common::next_instant(&fx);
    common::seal_next(&fx, &sealed_at, &[add]);

    // The next Block's Checkpoint is signed by the key the previous one
    // admitted.
    let sealed_after = common::next_instant(&fx);
    let after = fx
        .log_state()
        .seal_signed_by(&next, &sealed_after, &[])
        .block_number();

    let dir = tempfile::tempdir().unwrap();
    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, after);
}

#[test]
fn malformed_signed_publisher_does_not_abort_sync_or_advance_a_chain() {
    for field in [
        None,
        Some(serde_json::json!("RECORDS.EXAMPLE")),
        Some(serde_json::Value::Null),
    ] {
        let fx = common::build_fixture(true, false);
        let signer = common::Signer::new([1u8; 32]);
        let (_, envelope, _) = common::build_delta(
            &signer,
            "https://records.example/malformed",
            "Malformed",
            None,
            "body",
            None,
        );
        let mut inner = envelope["delta"].clone();
        match field {
            Some(value) => inner["publisher"] = value,
            None => {
                inner.as_object_mut().unwrap().remove("publisher");
            }
        }
        let signed =
            wist_core::envelope::sign_envelope(&inner, "delta", &signer.kid(), &signer.sk).unwrap();
        let wrapped = serde_json::json!({"type":"publisher_delta", "body":signed});
        let at = common::next_instant(&fx);
        common::seal_next(&fx, &at, &[wrapped]);
        let target = tempfile::tempdir().unwrap();
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
            .get("https://records.example/malformed")
            .unwrap()
            .is_none());
        assert!(store
            .get("https://records.example/alpha")
            .unwrap()
            .is_some());
        let conn =
            Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chain_tips WHERE url = ?1",
                ["https://records.example/malformed"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}

#[test]
fn cold_start_enforces_the_adopted_sequence_floor() {
    let fx = common::build_fixture_with_state(Vec::new(), 5);
    let new_key = common::Signer::new([7u8; 32]);
    common::extend_fixture_with_rotation(&fx, &new_key);
    let target = tempfile::tempdir().unwrap();
    let error = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default();
    assert!(
        error.contains("WIST1-E08") && error.contains("does not exceed accepted floor"),
        "a rotation to seq 1 must not pass a floor of 5: {error}"
    );
}

#[test]
fn cold_start_adopts_withdrawal_and_label_tuples() {
    use wist_core::objects::{LabelEntry, StateEntry, WithdrawalEntry};
    let publisher = common::Signer::new([1u8; 32]);
    let (alpha_id, _, _) = common::build_delta(
        &publisher,
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    let extra = vec![
        StateEntry::Withdrawal(WithdrawalEntry {
            delta_id: alpha_id.clone(),
            publisher: "records.example".into(),
            sealing_height: 0,
        }),
        StateEntry::Label(LabelEntry {
            labeler: "labeler.example.net".into(),
            subject: "https://records.example/alpha".into(),
            name: "wist:spam".into(),
            value: None,
            asserted_at: "2026-08-09T12:00:00Z".into(),
            expires_at: None,
            delta: None,
            label_id: format!("sha256:{}", "c".repeat(64)),
            sealing_height: 0,
        }),
    ];
    let fx = common::build_fixture_with_state(extra, 0);
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
    let withdrawn: Vec<(String, String, i64)> = conn
        .prepare("SELECT delta_id, publisher, height FROM withdrawals")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        withdrawn,
        vec![(alpha_id, "records.example".to_string(), 0)]
    );
    drop(conn);
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(
        store
            .get("https://records.example/alpha")
            .unwrap()
            .is_none(),
        "a withdrawn Delta's content leaves the adopted index"
    );
    assert!(store.get("https://records.example/beta").unwrap().is_some());
}

#[test]
fn a_withdrawal_sealed_beside_its_delta_keeps_the_delta_out_of_the_index() {
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
    let url = "https://records.example/gamma";
    let (gamma_id, delta_env, payload) =
        common::build_delta(&publisher, url, "Gamma Title", None, "gamma body", None);
    common::write_payload(
        fx.dir.path(),
        gamma_id.trim_start_matches("sha256:"),
        &payload,
    );
    let update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "payload_withdrawal",
        "subject": fx.domain,
        "details": {"delta_id": gamma_id, "legal_basis": "court order", "jurisdiction": "EU"},
        "effective_at": "2026-08-09T14:00:00Z",
    });
    let withdrawal =
        wist_core::envelope::sign_envelope(&update, "update", "log1", &fx.log.sk).unwrap();
    seal_next(
        &fx,
        "2026-08-09T14:00:00Z",
        &[
            serde_json::json!({"type": "registry_update", "body": withdrawal}),
            serde_json::json!({"type": "publisher_delta", "body": delta_env}),
        ],
    );

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
    assert!(store.get(url).unwrap().is_none());
    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let tip: String = conn
        .query_row("SELECT tip FROM chain_tips WHERE url = ?1", [url], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(tip, gamma_id, "a withdrawn Delta still moves its chain tip");
}

fn parameter_change(
    fx: &common::Fixture,
    parameter: &str,
    value: i64,
    effective_at: &str,
) -> serde_json::Value {
    let update = serde_json::json!({
        "wist_version": "1.0.0", "action": "parameter_change", "subject": parameter,
        "details": {"parameter": parameter, "value": value}, "effective_at": effective_at,
    });
    let body = wist_core::envelope::sign_envelope(&update, "update", "log1", &fx.log.sk).unwrap();
    serde_json::json!({"type": "registry_update", "body": body})
}

/// A `block_decompressed_cap_bytes` above WIST-4 §5's floor of 65 537 —
/// the octets one Entry of the largest admissible size occupies — and low
/// enough that a few hundred Deltas cross it.
const CAP: i64 = 70_000;

fn bulk_deltas(fx: &common::Fixture, count: usize) -> Vec<serde_json::Value> {
    let publisher = common::Signer::new([1u8; 32]);
    (0..count)
        .map(|i| {
            let (id, delta_env, payload) = common::build_delta(
                &publisher,
                &format!("https://records.example/bulk-{i}"),
                &format!("Bulk title {i} {}", "x".repeat(120)),
                Some(&"y".repeat(200)),
                "bulk body",
                None,
            );
            common::write_payload(fx.dir.path(), id.strip_prefix("sha256:").unwrap(), &payload);
            serde_json::json!({"type": "publisher_delta", "body": delta_env})
        })
        .collect()
}

/// Seals the next Block, reporting its number and WIST-3 §6's Block
/// size: the octets its Entries occupy in entry bundles.
fn seal_next(fx: &common::Fixture, sealed_at: &str, entries: &[serde_json::Value]) -> (u64, u64) {
    let mut ordered = entries.to_vec();
    wist_core::block::sort_entries(&mut ordered).unwrap();
    let octets = wist_core::block::block_octets(&ordered).unwrap();
    (common::seal_next(fx, sealed_at, entries), octets)
}

fn cold_sync(fx: &common::Fixture) -> Result<(graven::sync::SyncReport, i64), String> {
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .map(|report| {
        let conn =
            Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
        let accepted = conn
            .query_row(
                "SELECT COUNT(*) FROM parameters WHERE parameter = 'block_decompressed_cap_bytes'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (report, accepted)
    })
    .map_err(|e| e.to_string())
}

#[test]
fn an_accepted_cap_reduction_rejects_a_later_block_above_it() {
    let fx = common::build_fixture(true, false);
    let (_, size) = seal_next(
        &fx,
        "2026-08-09T14:00:00Z",
        &[parameter_change(
            &fx,
            "block_decompressed_cap_bytes",
            CAP,
            "2026-08-16T14:00:00Z",
        )],
    );
    assert!(size <= CAP as u64);
    let (_, size) = seal_next(&fx, "2026-08-16T14:00:00Z", &bulk_deltas(&fx, 200));
    assert!(size > CAP as u64);
    let error = cold_sync(&fx).unwrap_err();
    assert!(
        error.contains("exceeds the accepted size schedule"),
        "the reduced cap applies at its effective instant: {error}"
    );
}

#[test]
fn a_cap_reduction_accepts_blocks_within_it() {
    let fx = common::build_fixture(true, false);
    let (_, _) = seal_next(
        &fx,
        "2026-08-09T14:00:00Z",
        &[parameter_change(
            &fx,
            "block_decompressed_cap_bytes",
            CAP,
            "2026-08-16T14:00:00Z",
        )],
    );
    let (head, size) = seal_next(&fx, "2026-08-16T14:00:00Z", &bulk_deltas(&fx, 1));
    assert!(size <= CAP as u64);
    let (report, accepted) = cold_sync(&fx).unwrap();
    assert_eq!(report.head, head);
    assert_eq!(accepted, 1);
}

#[test]
fn a_cap_below_a_sealed_block_is_not_accepted() {
    let fx = common::build_fixture(true, false);
    let mut entries = bulk_deltas(&fx, 200);
    entries.push(parameter_change(
        &fx,
        "block_decompressed_cap_bytes",
        CAP,
        "2026-08-16T14:00:00Z",
    ));
    let (head, size) = seal_next(&fx, "2026-08-09T14:00:00Z", &entries);
    assert!(size > CAP as u64);
    let (report, accepted) = cold_sync(&fx).unwrap();
    assert_eq!(report.head, head);
    assert_eq!(
        accepted, 0,
        "a cap below a sealed Block's size is WIST4-E03 and stays ignored"
    );
}

#[test]
fn a_fractional_block_timestamp_fails_the_sync() {
    let fx = common::build_fixture(true, false);
    fx.log_state()
        .seal_off_profile("2026-08-09T14:00:00.5Z", &[]);
    let error = cold_sync(&fx).unwrap_err();
    assert!(
        error.contains("WIST3-E03") && error.contains("sealed_at"),
        "WIST-3 §3.1 whole-second instants: {error}"
    );
}

#[test]
fn an_off_grid_block_timestamp_fails_the_sync() {
    let fx = common::build_fixture(true, false);
    fx.log_state().seal_off_profile("2026-08-09T14:00:01Z", &[]);
    let error = cold_sync(&fx).unwrap_err();
    assert!(error.contains("off the cadence grid"), "{error}");
}

fn delta_observed(
    publisher: &common::Signer,
    url: &str,
    observed_at: &str,
    version: &str,
) -> (String, serde_json::Value, serde_json::Value) {
    let salt = wist_core::crypto::b64u_encode(&[7u8; 16]);
    let content = serde_json::json!({
        "extract": format!("body of {url}"),
        "links": {"total": 0, "urls": []},
        "summary": {"title": format!("Title of {url}")},
    });
    let payload = serde_json::json!({"wist_version": "1.0.0", "salt": salt, "content": content});
    let delta = serde_json::json!({
        "wist_version": version,
        "publisher": "records.example",
        "url": url,
        "change_type": "new",
        "observed_at": observed_at,
        "payload": {
            "commitment": wist_core::delta::make_commitment(&salt, &content).unwrap(),
            "alg": "HMAC-SHA256",
            "bytes": wist_core::delta::content_bytes(&content).unwrap(),
        },
        "meta": {"lang": "en"},
    });
    let envelope =
        wist_core::envelope::sign_envelope(&delta, "delta", &publisher.kid(), &publisher.sk)
            .unwrap();
    (
        wist_core::delta::delta_id(&delta).unwrap(),
        envelope,
        payload,
    )
}

#[test]
fn sealed_deltas_are_checked_against_their_block_clock_and_accepted_allowance() {
    let fx = common::build_fixture(true, false);
    let publisher = common::Signer::new([1u8; 32]);
    let mut entries = vec![parameter_change(
        &fx,
        "clock_skew_seconds",
        0,
        "2026-08-16T14:00:00Z",
    )];
    let mut sealed = Vec::new();
    for (url, observed_at, version) in [
        (
            "https://records.example/within-default",
            "2026-08-09T14:10:00Z",
            "1.0.0",
        ),
        (
            "https://records.example/beyond-default",
            "2026-08-09T14:10:00.000000000000000001Z",
            "1.0.0",
        ),
        (
            "https://records.example/patch-version",
            "2026-08-09T13:00:00Z",
            "1.7.3",
        ),
        (
            "https://records.example/other-major",
            "2026-08-09T13:00:00Z",
            "2.0.0",
        ),
    ] {
        let (id, envelope, payload) = delta_observed(&publisher, url, observed_at, version);
        common::write_payload(fx.dir.path(), id.strip_prefix("sha256:").unwrap(), &payload);
        sealed.push(url);
        entries.push(serde_json::json!({"type": "publisher_delta", "body": envelope}));
    }
    seal_next(&fx, "2026-08-09T14:00:00Z", &entries);
    let mut entries = Vec::new();
    for (url, observed_at) in [
        (
            "https://records.example/at-zero-allowance",
            "2026-08-16T14:00:00Z",
        ),
        (
            "https://records.example/past-zero-allowance",
            "2026-08-16T14:00:00.5Z",
        ),
    ] {
        let (id, envelope, payload) = delta_observed(&publisher, url, observed_at, "1.0.0");
        common::write_payload(fx.dir.path(), id.strip_prefix("sha256:").unwrap(), &payload);
        sealed.push(url);
        entries.push(serde_json::json!({"type": "publisher_delta", "body": envelope}));
    }
    let (head, _) = seal_next(&fx, "2026-08-16T14:00:00Z", &entries);
    let target = tempfile::tempdir().unwrap();
    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, head);
    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let mut stmt = conn
        .prepare("SELECT url FROM records WHERE url LIKE 'https://records.example/%' ORDER BY url")
        .unwrap();
    let urls: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let materialized: Vec<&str> = sealed
        .iter()
        .copied()
        .filter(|url| urls.iter().any(|u| u == url))
        .collect();
    assert_eq!(
        materialized,
        [
            "https://records.example/within-default",
            "https://records.example/patch-version",
            "https://records.example/at-zero-allowance",
        ],
        "materialized {urls:?}"
    );
    let tips: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM chain_tips WHERE url IN ('https://records.example/beyond-default', 'https://records.example/other-major', 'https://records.example/past-zero-allowance')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tips, 0, "an ignored Delta moves no chain tip");
}

fn synced_state(target: &std::path::Path) -> graven::sync::SyncState {
    graven::store::synced_state(&common::synced_log_dir(target)).unwrap()
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn a_sync_that_cannot_commit_leaves_cursor_keys_and_index_unchanged() {
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
    let index = common::synced_log_dir(dir.path()).join("index.sqlite");
    let before = synced_state(dir.path());
    assert_eq!(before.block_number, 1);
    let snapshot = |conn: &Connection| {
        (
            count(conn, "records"),
            count(conn, "aggregator_keys"),
            count(conn, "parameters"),
            count(conn, "declarations"),
        )
    };
    let counts_before = snapshot(&Connection::open(&index).unwrap());

    let new_url = common::extend_fixture(&fx);
    let holder = Connection::open(&index).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    let failed = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    );
    assert!(
        failed.is_err(),
        "the index was locked against the sync's commit"
    );
    holder.execute_batch("ROLLBACK").unwrap();
    drop(holder);

    let after = synced_state(dir.path());
    assert_eq!(after.block_number, 1);
    assert_eq!(after.root, before.root);
    let conn = Connection::open(&index).unwrap();
    assert_eq!(snapshot(&conn), counts_before);
    let store = Store::open(&common::synced_log_dir(dir.path())).unwrap();
    assert!(store.get(&new_url).unwrap().is_none());
    drop(store);
    drop(conn);

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, 2);
    assert_eq!(synced_state(dir.path()).block_number, 2);
    let store = Store::open(&common::synced_log_dir(dir.path())).unwrap();
    assert!(store.get(&new_url).unwrap().is_some());
}

#[test]
fn the_sync_cursor_lives_in_the_index_not_the_mirror_file() {
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
    let log_dir = common::synced_log_dir(dir.path());
    std::fs::remove_file(log_dir.join("sync.json")).unwrap();
    common::extend_fixture(&fx);

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.block_number_before, Some(1));
    assert_eq!(report.head, 2);
    let mirrored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(log_dir.join("sync.json")).unwrap()).unwrap();
    assert_eq!(mirrored["block_number"], 2);
    assert_eq!(synced_state(dir.path()).block_number, 2);
}

#[test]
fn a_store_carrying_only_the_sync_file_is_read_and_imported() {
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
    let log_dir = common::synced_log_dir(dir.path());
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    conn.execute_batch("DROP TABLE sync_state").unwrap();
    drop(conn);
    assert_eq!(synced_state(dir.path()).block_number, 1);
    common::extend_fixture(&fx);

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.block_number_before, Some(1));
    assert_eq!(report.head, 2);
}

#[test]
fn a_cold_start_replaces_the_verifying_index_a_crash_left_behind() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    let log_dir = common::synced_log_dir(target.path());
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::write(log_dir.join("index.sqlite.verifying"), b"not a database").unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.head, 1);
    assert!(!log_dir.join("index.sqlite.verifying").exists());
    assert_eq!(synced_state(target.path()).block_number, 1);
}
