mod common;

use graven::store::Store;
use rusqlite::Connection;

#[test]
fn cold_sync_verifies_chain_and_populates_store() {
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    assert_eq!(report.epoch_number_before, None);
    assert_eq!(report.head, 1);

    let sync_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target.path()).join("sync.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sync_json["epoch_number"], 1);
    assert_eq!(sync_json["tree_size"], fx.head_tree_size());
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

    assert!(common::holds_declaration(
        &common::synced_log_dir(target.path()),
        common::BETA_DOMAIN
    ));

    let hits = store.search("Alpha", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].url, "https://records.example/alpha");
}

#[test]
fn cold_sync_accepts_anchor_fetched_over_http() {
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();
    let anchor_url = format!("{}/log/anchor.json", fx.base_url);

    let report = graven::sync::run(&anchor_url, &fx.base_url, target.path(), true, false).unwrap();

    assert_eq!(report.head, 1);
}

/// WIST-3 §6 and §8 step 8.
#[test]
fn cold_sync_rejects_a_tampered_entry_bundle_and_keeps_the_snapshots_checkpoint() {
    let fx = common::build_fixture(false);
    let bundle = fx
        .dir
        .path()
        .join(format!("tile/entries/000.p/{}", fx.head_tree_size()));
    let mut bytes = std::fs::read(&bundle).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&bundle, bytes).unwrap();

    let target = tempfile::tempdir().unwrap();
    let error = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("WIST3-E03"), "{error}");
    assert_eq!(
        graven::store::synced_state(&common::synced_log_dir(target.path()))
            .unwrap()
            .epoch_number,
        0,
        "the Snapshot's Checkpoint is the head the run reached"
    );
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_some());
    assert!(
        !common::holds_declaration(&common::synced_log_dir(target.path()), common::BETA_DOMAIN),
        "no Entry above the adopted Checkpoint's tree size is applied"
    );
}

#[test]
fn cold_sync_rejects_wrong_manifest_content_digest() {
    let fx = common::build_fixture(false);
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
    let fx = common::build_fixture(false);
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

/// WIST-3 §8 step 8.
#[test]
fn cold_sync_rejects_state_signed_by_wrong_key() {
    let fx = common::build_fixture(false);
    common::resign_state_with_wrong_key(fx.dir.path(), &fx.log, &fx.other, &fx.snapshot_date);

    let target = tempfile::tempdir().unwrap();
    let error = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap_err()
    .to_string();

    assert!(
        error.contains("WIST3-E04")
            && error.contains("the Snapshot state file")
            && error.contains("verifies at no height"),
        "error was: {error}"
    );
    assert!(!target.path().join("logs.json").exists());
    assert!(!common::synced_log_dir(target.path())
        .join("sync.json")
        .exists());
}

/// WIST-3 §5 and §8 step 8.
#[test]
fn cold_sync_rejects_checkpoint_signed_by_wrong_key_and_keeps_the_snapshots_checkpoint() {
    let fx = common::build_fixture(false);
    common::resign_checkpoint_with_wrong_key(&fx, &fx.other);

    let target = tempfile::tempdir().unwrap();
    let error = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("WIST3-E03"), "{error}");
    assert_eq!(
        graven::store::synced_state(&common::synced_log_dir(target.path()))
            .unwrap()
            .epoch_number,
        0,
        "the Snapshot's Checkpoint is the head the run reached"
    );
    assert!(
        !common::holds_declaration(&common::synced_log_dir(target.path()), common::BETA_DOMAIN),
        "the Epoch whose Checkpoint failed the signature rules is not applied"
    );
}

#[test]
fn cold_sync_leaves_no_partial_state_when_tier0_mutation_fails() {
    let fx = common::build_fixture(true);
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
fn continuous_sync_advances_head_and_applies_the_new_epoch() {
    let fx = common::build_fixture(false);
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
    assert_eq!(report2.epoch_number_before, Some(1));

    let sync_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target.path()).join("sync.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sync_json["epoch_number"], 2);

    assert!(common::holds_declaration(
        &common::synced_log_dir(target.path()),
        &new_url
    ));
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();

    let alpha = store.get("https://records.example/alpha").unwrap();
    assert!(alpha.is_some());
}

#[test]
fn continuous_sync_is_noop_when_checkpoint_unchanged() {
    let fx = common::build_fixture(false);
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
    assert_eq!(report.epoch_number_before, Some(1));
}

#[test]
fn a_checkpoint_below_the_verified_head_does_not_regress_it_and_is_no_error() {
    let fx = common::build_fixture(false);
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
            .epoch_number,
        2
    );
}

#[test]
fn a_differing_checkpoint_at_a_retained_epoch_number_is_equivocation_with_an_evidence_bundle() {
    let fx = common::build_fixture(false);
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
        common::synced_log_dir(target.path()).join("evidence/equivocation-epoch-000000002");
    assert!(
        bundle.join("retained.checkpoint").exists() && bundle.join("offered.checkpoint").exists(),
        "both Checkpoints must be preserved in {}",
        bundle.display()
    );
}

#[test]
fn cold_sync_refuses_when_sync_json_already_exists() {
    let fx = common::build_fixture(false);
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

const FORGED_SUBJECT: &str = "https://other.example/forged";

#[test]
fn a_label_signed_by_an_undeclared_key_is_ignored() {
    let fx = common::build_fixture(false);
    let attacker = common::Signer::new([7u8; 32]);
    let at = common::next_instant(&fx);
    common::seal_next(
        &fx,
        &at,
        &[common::label_by(&attacker, &fx.domain, FORGED_SUBJECT)],
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
    assert!(!common::labeled(
        &common::synced_log_dir(dir.path()),
        FORGED_SUBJECT
    ));
    let store = Store::open(&common::synced_log_dir(dir.path())).unwrap();
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_some());
}

#[test]
fn a_label_after_rotation_signed_by_the_old_key_is_ignored() {
    let fx = common::build_fixture(false);
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

    let subject = "https://other.example/stale";
    let at = common::next_instant(&fx);
    common::seal_next(&fx, &at, &[common::label_by(&old, &fx.domain, subject)]);

    let dir = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    assert!(!common::labeled(
        &common::synced_log_dir(dir.path()),
        subject
    ));
}

#[test]
fn a_label_signed_by_the_rotated_key_syncs() {
    let fx = common::build_fixture(false);
    let new_key = common::Signer::new([2u8; 32]);
    common::extend_fixture_with_rotation(&fx, &new_key);
    let subject = "https://other.example/rotated";
    let at = common::next_instant(&fx);
    common::seal_next(&fx, &at, &[common::label_by(&new_key, &fx.domain, subject)]);
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

    assert!(common::labeled(
        &common::synced_log_dir(dir.path()),
        subject
    ));
}

/// WIST-3 §7.
#[test]
fn a_cold_start_adopts_one_declaration_named_by_several_tuples() {
    use wist_core::objects::{PendingDeclarationEntry, RecoveryWindowEntry, StateEntry};
    let publisher = common::Signer::new([1u8; 32]);
    let declaration = common::build_declaration(&publisher, "records.example");
    let fx = common::build_fixture_with_state(
        vec![
            StateEntry::RecoveryWindow(RecoveryWindowEntry {
                domain: "records.example".into(),
                declaration_height: 0,
                window_end: "2026-08-16T12:00:00Z".into(),
                head: declaration.clone(),
                head_height: 0,
            }),
            StateEntry::PendingDeclaration(PendingDeclarationEntry {
                domain: "records.example".into(),
                head: declaration.clone(),
                sealing_height: 0,
                activation_height: 4,
            }),
        ],
        0,
    );

    let target = tempfile::tempdir().unwrap();
    assert_eq!(
        graven::sync::run(
            fx.anchor_path().to_str().unwrap(),
            &fx.base_url,
            target.path(),
            true,
            false,
        )
        .unwrap()
        .head,
        1
    );
    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM declarations WHERE domain = 'records.example' AND height = 0",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1,
        "the Declaration the three tuples name is recorded once"
    );
}

#[test]
fn incremental_sync_reloads_declarations() {
    let fx = common::build_fixture(false);
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

    assert!(common::holds_declaration(
        &common::synced_log_dir(dir.path()),
        &new_url
    ));
}

#[test]
fn withdrawal_removes_record_from_local_index() {
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let alpha_id = common::item_id_of("https://records.example/alpha");
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
}

#[test]
fn withdrawal_for_unknown_item_is_noop() {
    let fx = common::build_fixture(false);
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
}

#[test]
fn cold_start_applies_withdrawals_after_snapshot_position() {
    let fx = common::build_fixture(false);
    let alpha_id = common::item_id_of("https://records.example/alpha");
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
}

#[test]
fn withdrawal_removes_tier1_and_embedding_rows_when_present() {
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let alpha_id = common::item_id_of("https://records.example/alpha");

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    conn.execute_batch(
        "CREATE TABLE extracts(url TEXT, publisher TEXT, item_id TEXT, extract TEXT);
         CREATE TABLE links(source_url TEXT, target_url TEXT, position INTEGER);
         CREATE TABLE embeddings(item_id TEXT PRIMARY KEY, url TEXT, publisher TEXT, vector BLOB);",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO extracts(url, publisher, item_id, extract) VALUES (?1, ?2, ?3, ?4)",
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
        "INSERT INTO embeddings(item_id, url, publisher, vector) VALUES (?1, ?2, ?3, ?4)",
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
fn sync_creates_registry_and_per_log_layout() {
    let fx = common::build_fixture(false);
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
    let fx = common::build_fixture(false);
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

    assert!(common::holds_declaration(&migrated_dir, &new_url));
}

#[test]
fn conflicting_base_for_same_log_id_errors() {
    let fx = common::build_fixture(false);
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
        alpha_before.item_id, alpha_after.item_id,
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

    assert!(common::holds_declaration(
        &graven::registry::log_dir(dir.path(), "log-one"),
        &new_url1
    ));
    assert!(common::holds_declaration(
        &graven::registry::log_dir(dir.path(), "log-two"),
        &new_url2
    ));
}

#[test]
fn run_all_errors_clearly_on_unmigrated_legacy_dir() {
    let fx = common::build_fixture(false);
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
    let fx = common::build_fixture(false);
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
    let fx_a = common::build_fixture(false);
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

    // WIST-3 §7 (`WIST3-E04`): the first Log's key tuples do not chain to the second Log's Anchor.

    let result = graven::sync::run(
        fx_b.anchor_path().to_str().unwrap(),
        &fx_b.base_url,
        legacy.path(),
        true,
        false,
    );
    let err = result.unwrap_err();
    assert!(err.to_string().contains("WIST3-E04"), "error was: {err}");
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
    let fx = common::build_fixture(false);
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
fn a_manifest_disagreeing_with_its_index_entry_is_rejected() {
    let fx = common::build_fixture(false);
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
    let fx = common::build_fixture(false);
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

    let sealed_after = common::next_instant(&fx);
    let after = fx
        .log_state()
        .seal_signed_by(&next, &sealed_after, &[])
        .epoch_number();

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
    let rotated = fx.log_state().head_number();
    assert!(
        error.contains("WIST1-E08")
            && error.contains("the Epoch is rejected")
            && error.contains(&format!("stopped at epoch {rotated}")),
        "a rotation to seq 1 must not pass a floor of 5: {error}"
    );
}

#[test]
fn cold_start_adopts_withdrawal_and_label_tuples() {
    use wist_core::objects::{LabelEntry, StateEntry, WithdrawalEntry};
    let alpha_id = common::item_id_of("https://records.example/alpha");
    let extra = vec![
        StateEntry::Withdrawal(WithdrawalEntry {
            item_id: alpha_id.clone(),
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
        .prepare("SELECT item_id, publisher, height FROM withdrawals")
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
        "a withdrawn Item's content leaves the adopted index"
    );
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

/// Above WIST-4 §5's floor of 65 537 octets; low enough that a few hundred Declarations cross it.
const CAP: i64 = 70_000;

fn bulk_declarations(count: usize) -> Vec<serde_json::Value> {
    let publisher = common::Signer::new([1u8; 32]);
    (0..count)
        .map(|i| {
            common::declaration_entry(&publisher, &format!("bulk-{i}-{}.example", "x".repeat(50)))
        })
        .collect()
}

/// WIST-3 §6's Epoch size: the octets its Entries occupy in entry bundles.
fn seal_next(fx: &common::Fixture, sealed_at: &str, entries: &[serde_json::Value]) -> (u64, u64) {
    let mut ordered = entries.to_vec();
    wist_core::epoch::sort_entries(&mut ordered).unwrap();
    let octets = wist_core::epoch::epoch_octets(&ordered).unwrap();
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
                "SELECT COUNT(*) FROM parameters WHERE parameter = 'epoch_cap_bytes'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (report, accepted)
    })
    .map_err(|e| e.to_string())
}

#[test]
fn an_accepted_cap_reduction_rejects_a_later_epoch_above_it() {
    let fx = common::build_fixture(false);
    let (_, size) = seal_next(
        &fx,
        "2026-08-09T14:00:00Z",
        &[parameter_change(
            &fx,
            "epoch_cap_bytes",
            CAP,
            "2026-08-16T14:00:00Z",
        )],
    );
    assert!(size <= CAP as u64);
    let (_, size) = seal_next(&fx, "2026-08-16T14:00:00Z", &bulk_declarations(200));
    assert!(size > CAP as u64);
    let error = cold_sync(&fx).unwrap_err();
    assert!(
        error.contains("exceeds the accepted size schedule"),
        "the reduced cap applies at its effective instant: {error}"
    );
}

#[test]
fn a_cap_reduction_accepts_epochs_within_it() {
    let fx = common::build_fixture(false);
    let (_, _) = seal_next(
        &fx,
        "2026-08-09T14:00:00Z",
        &[parameter_change(
            &fx,
            "epoch_cap_bytes",
            CAP,
            "2026-08-16T14:00:00Z",
        )],
    );
    let (head, size) = seal_next(&fx, "2026-08-16T14:00:00Z", &bulk_declarations(1));
    assert!(size <= CAP as u64);
    let (report, accepted) = cold_sync(&fx).unwrap();
    assert_eq!(report.head, head);
    assert_eq!(accepted, 1);
}

#[test]
fn a_cap_below_a_sealed_epoch_is_not_accepted() {
    let fx = common::build_fixture(false);
    let mut entries = bulk_declarations(200);
    entries.push(parameter_change(
        &fx,
        "epoch_cap_bytes",
        CAP,
        "2026-08-16T14:00:00Z",
    ));
    let (head, size) = seal_next(&fx, "2026-08-09T14:00:00Z", &entries);
    assert!(size > CAP as u64);
    let (report, accepted) = cold_sync(&fx).unwrap();
    assert_eq!(report.head, head);
    assert_eq!(
        accepted, 0,
        "a cap below a sealed Epoch's size is WIST4-E03 and stays ignored"
    );
}

#[test]
fn a_fractional_epoch_timestamp_fails_the_sync() {
    let fx = common::build_fixture(false);
    fx.log_state()
        .seal_off_profile("2026-08-09T14:00:00.5Z", &[]);
    let error = cold_sync(&fx).unwrap_err();
    assert!(
        error.contains("WIST3-E03") && error.contains("sealed_at"),
        "WIST-3 §3.1 whole-second instants: {error}"
    );
}

#[test]
fn an_off_grid_epoch_timestamp_fails_the_sync() {
    let fx = common::build_fixture(false);
    fx.log_state().seal_off_profile("2026-08-09T14:00:01Z", &[]);
    let error = cold_sync(&fx).unwrap_err();
    assert!(error.contains("off the cadence grid"), "{error}");
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
    let fx = common::build_fixture(false);
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
    assert_eq!(before.epoch_number, 1);
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
    assert_eq!(after.epoch_number, 1);
    assert_eq!(after.root, before.root);
    let conn = Connection::open(&index).unwrap();
    assert_eq!(snapshot(&conn), counts_before);
    assert!(!common::holds_declaration(
        &common::synced_log_dir(dir.path()),
        &new_url
    ));
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
    assert_eq!(synced_state(dir.path()).epoch_number, 2);
    assert!(common::holds_declaration(
        &common::synced_log_dir(dir.path()),
        &new_url
    ));
}

#[test]
fn the_sync_cursor_lives_in_the_index_not_the_mirror_file() {
    let fx = common::build_fixture(false);
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
    assert_eq!(report.epoch_number_before, Some(1));
    assert_eq!(report.head, 2);
    let mirrored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(log_dir.join("sync.json")).unwrap()).unwrap();
    assert_eq!(mirrored["epoch_number"], 2);
    assert_eq!(synced_state(dir.path()).epoch_number, 2);
}

#[test]
fn a_store_carrying_only_the_sync_file_is_read_and_imported() {
    let fx = common::build_fixture(false);
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
    assert_eq!(synced_state(dir.path()).epoch_number, 1);
    common::extend_fixture(&fx);

    let report = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir.path(),
        true,
        false,
    )
    .unwrap();
    assert_eq!(report.epoch_number_before, Some(1));
    assert_eq!(report.head, 2);
}

#[test]
fn a_cold_start_replaces_the_verifying_index_a_crash_left_behind() {
    let fx = common::build_fixture(false);
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
    assert_eq!(synced_state(target.path()).epoch_number, 1);
}
