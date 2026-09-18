mod common;

use graven::store::Store;
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

/// WIST-3 §4: an Entry's leaf data is its JCS serialization, so leaf
/// octets that carry a repeated member are no Entry, whatever leaf hash
/// the tree states for them.
#[test]
fn an_entry_whose_leaf_data_repeats_a_member_fails_the_sync() {
    for (name, escaped) in [
        ("publisher", "publishe\\u0072"),
        ("observed_at", "observed_a\\u0074"),
    ] {
        let fx = common::build_fixture(true, false);
        let publisher = common::Signer::new([1u8; 32]);
        let (_, delta_env, _) = common::build_delta(
            &publisher,
            "https://records.example/repeated",
            "Repeated",
            None,
            "body",
            None,
        );
        let entry = serde_json::json!({"type": "publisher_delta", "body": delta_env});
        let original = wist_core::jcs::canonicalize(&entry).unwrap();
        let sealed_at = common::next_instant(&fx);
        fx.log_state()
            .seal_leaf_bytes(&sealed_at, &[duplicate(&original, name, escaped)]);
        let error = cold_sync(&fx).unwrap_err();
        assert!(
            error.contains("duplicate JSON member name"),
            "{name}: {error}"
        );
    }
}

#[test]
fn an_anchor_with_a_repeated_member_fails_the_sync() {
    let fx = common::build_fixture(true, false);
    let path = fx.dir.path().join("log/anchor.json");
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, duplicate(&original, "key_id", "key_i\\u0064")).unwrap();
    let error = cold_sync(&fx).unwrap_err();
    assert!(error.contains("duplicate JSON member name"), "{error}");
}

#[test]
fn a_payload_with_a_repeated_member_never_materializes_its_fields() {
    let fx = common::build_fixture(true, false);
    let publisher = common::Signer::new([1u8; 32]);
    let (beta_id, _, _) = common::build_delta(
        &publisher,
        "https://records.example/beta",
        "Beta Title",
        Some("Beta abstract"),
        "beta body",
        None,
    );
    let path = fx
        .dir
        .path()
        .join(format!("payloads/{}.json", &beta_id[7..]));
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, duplicate(&original, "title", "\\u0074itle")).unwrap();
    let (report, target) = cold_sync(&fx).unwrap();
    assert_eq!(report.head, 1);
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    let beta = store.get("https://records.example/beta").unwrap().unwrap();
    assert_eq!(beta.title, "", "a rejected Payload supplies no fields");
    assert_eq!(beta.r#abstract, None);
    let alpha = store.get("https://records.example/alpha").unwrap().unwrap();
    assert_eq!(alpha.title, "Alpha Title");
}

#[test]
fn a_pack_with_a_repeated_member_imports_nothing() {
    let fx = common::build_fixture(true, false);
    let (_, target) = cold_sync(&fx).unwrap();
    let sync_json: Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target.path()).join("sync.json")).unwrap(),
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
