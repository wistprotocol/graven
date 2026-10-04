mod common;

use rusqlite::Connection;
use serde_json::Value;

fn duplicate(raw: &[u8], name: &str, escaped: &str) -> Vec<u8> {
    let text = std::str::from_utf8(raw).unwrap();
    let changed = text.replacen(
        &format!("\"{name}\":"),
        &format!("\"{name}\":null,\"{escaped}\":"),
        1,
    );
    assert_ne!(changed, text);
    assert_eq!(
        serde_json::from_str::<Value>(&changed).unwrap(),
        serde_json::from_slice::<Value>(raw).unwrap()
    );
    changed.into_bytes()
}

fn cold_sync(
    fx: &common::Fixture,
) -> Result<(graven::sync::SyncReport, tempfile::TempDir), String> {
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .map(|report| (report, target))
    .map_err(|e| e.to_string())
}

/// WIST-3 §3.3 and WIST-1 §4: a `publisher_declaration` body that is not JCS input rejects its
/// Epoch.
#[test]
fn a_declaration_whose_leaf_data_repeats_a_member_rejects_its_epoch() {
    for (name, escaped) in [("domain", "domai\\u006e"), ("seq", "se\\u0071")] {
        let fx = common::build_fixture(false);
        let publisher = common::Signer::new([1u8; 32]);
        let entry = common::declaration_entry(&publisher, "repeated.example");
        let original = wist_core::jcs::canonicalize(&entry).unwrap();
        let sealed_at = common::next_instant(&fx);
        fx.log_state()
            .seal_leaf_bytes(&sealed_at, &[duplicate(&original, name, escaped)]);
        let rejected = fx.log_state().head_number();
        let (report, target) = cold_sync(&fx).unwrap();
        assert_eq!(report.head, rejected, "{name}");
        assert_eq!(
            report
                .rejected
                .iter()
                .map(|epoch| (epoch.epoch_number, epoch.codes.clone()))
                .collect::<Vec<_>>(),
            [(rejected, vec!["WIST1-E05".to_owned()])],
            "{name}"
        );
        let log_dir = common::synced_log_dir(target.path());
        assert!(
            !common::holds_declaration(&log_dir, "repeated.example"),
            "{name}"
        );
        let later = common::extend_fixture(&fx);
        let report = graven::sync::run(
            fx.anchor_path().to_str().unwrap(),
            &fx.base_url,
            target.path(),
            true,
            false,
        )
        .unwrap();
        assert!(report.rejected.is_empty(), "{name}: {report}");
        assert!(common::holds_declaration(&log_dir, &later), "{name}");
        assert!(
            !common::holds_declaration(&log_dir, "repeated.example"),
            "{name}"
        );
    }
}

#[test]
fn an_anchor_with_a_repeated_member_fails_the_sync() {
    let fx = common::build_fixture(false);
    let path = fx.dir.path().join("log/anchor.json");
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, duplicate(&original, "key_id", "key_i\\u0064")).unwrap();
    let error = cold_sync(&fx).unwrap_err();
    assert!(error.contains("duplicate JSON member name"), "{error}");
}

#[test]
fn a_pack_with_a_repeated_member_imports_nothing() {
    let fx = common::build_fixture(false);
    let (_, target) = cold_sync(&fx).unwrap();
    let sync_json: Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target.path()).join("sync.json")).unwrap(),
    )
    .unwrap();
    let alpha_id = common::item_id_of("https://records.example/alpha");
    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        sync_json["content_digest"].as_str().unwrap(),
        sync_json["tree_size"].as_u64().unwrap(),
        &[(
            alpha_id.as_str(),
            "https://records.example/alpha",
            fx.domain.as_str(),
            vec![0.1, 0.2, 0.3],
        )],
        3,
        "cosine",
    );
    let original = std::fs::read(&pack_path).unwrap();
    std::fs::write(&pack_path, duplicate(&original, "metric", "metri\\u0063")).unwrap();
    let error = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.log.public_b64u(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("duplicate JSON member name"), "{error}");
    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let embeddings: i64 = conn
        .query_row("SELECT COUNT(*) FROM embeddings", [], |r| r.get(0))
        .unwrap_or(0);
    assert_eq!(embeddings, 0);
}

#[test]
fn a_payload_with_a_repeated_member_never_materializes_its_fields() {
    let fx = common::build_fixture_without_records();
    let publisher = common::Signer::new([1u8; 32]);
    let beta = "https://records.example/beta";
    let gamma = "https://records.example/gamma";
    let (beta_item, beta_payload) = common::page(
        common::RECORDS,
        beta,
        common::OBSERVED,
        &common::Content::of("Beta Title"),
    );
    let (gamma_item, gamma_payload) = common::page(
        common::RECORDS,
        gamma,
        common::OBSERVED,
        &common::Content::of("Gamma Title"),
    );
    common::serve_payload(fx.dir.path(), &beta_item, &beta_payload);
    common::serve_payload(fx.dir.path(), &gamma_item, &gamma_payload);
    let path = common::payload_path(fx.dir.path(), &beta_item);
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, duplicate(&original, "title", "\\u0074itle")).unwrap();
    common::seal_catalog(
        &fx,
        &publisher,
        common::RECORDS,
        &[beta_item, gamma_item],
        &[],
    );
    let (report, target) = cold_sync(&fx).unwrap();
    assert_eq!(report.head, 2);
    let log_dir = common::synced_log_dir(target.path());
    common::assert_records_materialized(&log_dir);
    let store = graven::store::Store::open(&log_dir).unwrap();
    let held = store.get(beta).unwrap().unwrap();
    assert_eq!(held.title, None, "a rejected Payload supplies no fields");
    assert_eq!(held.r#abstract, None);
    let other = store.get(gamma).unwrap().unwrap();
    assert_eq!(other.title.as_deref(), Some("Gamma Title"));
}
