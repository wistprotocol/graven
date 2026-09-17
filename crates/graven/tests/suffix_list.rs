mod common;

use serde_json::Value;
use wist_core::envelope::sign_envelope;
use wist_core::objects::{ParameterEntry, StateEntry, SuffixListEntry};

const LIST: &[u8] = b"// ===BEGIN ICANN DOMAINS===\ncom\nexample\n// ===END ICANN DOMAINS===\n";

fn serve_list(fx: &common::Fixture, octets: &[u8]) -> String {
    let identifier = wist_core::suffix_list::identifier(octets);
    let dir = fx.dir.path().join("log/suffix-lists");
    std::fs::create_dir_all(&dir).unwrap();
    let hex = identifier.strip_prefix("sha256:").unwrap();
    std::fs::write(dir.join(format!("{hex}.dat")), octets).unwrap();
    identifier
}

fn head(fx: &common::Fixture) -> (u64, String) {
    let doc: Value =
        serde_json::from_slice(&std::fs::read(fx.dir.path().join("log/checkpoint.json")).unwrap())
            .unwrap();
    (
        doc["checkpoint"]["block_number"].as_u64().unwrap(),
        doc["checkpoint"]["block_hash"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

fn append_block(fx: &common::Fixture, entries: &[Value]) -> u64 {
    let (prev_number, prev_hash) = head(fx);
    let next = prev_number + 1;
    let sealed_at = format!("2026-08-09T{:02}:00:00Z", 14 + next);
    let (block, hash) = common::build_block(&fx.log, next, &prev_hash, &sealed_at, entries);
    common::write_block(fx.dir.path(), next, &block);
    common::write_checkpoint(fx.dir.path(), &fx.log, next, &hash, &sealed_at);
    next
}

fn suffix_act(fx: &common::Fixture, identifier: &str, bytes: usize) -> Value {
    let update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "suffix_list_update",
        "subject": identifier,
        "details": {"sha256": identifier, "bytes": bytes},
        "effective_at": "2026-08-09T15:00:00Z",
    });
    let body = sign_envelope(&update, "update", "log1", &fx.log.sk).unwrap();
    serde_json::json!({"type": "registry_update", "body": body})
}

fn delta_entry(url: &str) -> Value {
    let publisher = common::Signer::new([7u8; 32]);
    let (_, envelope, _) = common::build_delta(&publisher, url, "T", None, "body", None);
    serde_json::json!({"type": "publisher_delta", "body": envelope})
}

fn sync(
    fx: &common::Fixture,
    target: &std::path::Path,
) -> graven::error::Result<graven::sync::SyncReport> {
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target,
        true,
        false,
    )
}

fn held(target: &std::path::Path) -> (Vec<String>, Vec<(i64, String)>) {
    let conn =
        rusqlite::Connection::open(common::synced_log_dir(target).join("index.sqlite")).unwrap();
    let files = conn
        .prepare("SELECT sha256 FROM suffix_lists ORDER BY sha256")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let acts = conn
        .prepare("SELECT height, sha256 FROM suffix_list_acts ORDER BY seq")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    (files, acts)
}

#[test]
fn a_pinned_snapshot_is_obtained_verified_and_held() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    assert_eq!(held(target.path()), (Vec::new(), Vec::new()));

    let identifier = serve_list(&fx, LIST);
    let height = append_block(&fx, &[suffix_act(&fx, &identifier, LIST.len())]);
    sync(&fx, target.path()).unwrap();
    assert_eq!(
        held(target.path()),
        (
            vec![identifier.clone()],
            vec![(height as i64, identifier.clone())]
        )
    );

    append_block(&fx, &[suffix_act(&fx, &identifier, LIST.len() + 1)]);
    sync(&fx, target.path()).unwrap();
    assert_eq!(held(target.path()).1.len(), 1);

    let unserved = wist_core::suffix_list::identifier(b"net\n");
    append_block(&fx, &[suffix_act(&fx, &unserved, 4)]);
    let err = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(err.contains("WIST3-E01"), "{err}");
}

#[test]
fn a_served_file_that_does_not_hash_to_its_name_fails_the_sync() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    let identifier = serve_list(&fx, LIST);
    let hex = identifier.strip_prefix("sha256:").unwrap();
    std::fs::write(
        fx.dir.path().join(format!("log/suffix-lists/{hex}.dat")),
        b"net\n",
    )
    .unwrap();
    append_block(&fx, &[suffix_act(&fx, &identifier, LIST.len())]);
    let err = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(err.contains("WIST3-E03"), "{err}");
}

#[test]
fn capacity_is_counted_per_registrable_domain_under_the_adopted_tuple() {
    let identifier = wist_core::suffix_list::identifier(LIST);
    let caps = |extra: &mut Vec<StateEntry>| {
        for name in ["domain_block_entries_max", "labeler_block_entries_max"] {
            extra.push(StateEntry::Parameter(ParameterEntry {
                name: name.into(),
                effective_at: "2026-08-09T13:00:00Z".into(),
                value: 1,
            }));
        }
    };
    let mut with_tuple = vec![StateEntry::SuffixList(SuffixListEntry {
        identifier: identifier.clone(),
        sealing_height: 0,
    })];
    caps(&mut with_tuple);
    let fx = common::build_fixture_with_state(with_tuple, 0);
    assert_eq!(serve_list(&fx, LIST), identifier);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    assert_eq!(held(target.path()).1, vec![(0, identifier.clone())]);
    append_block(
        &fx,
        &[
            delta_entry("https://a.example.com/x"),
            delta_entry("https://b.example.com/x"),
        ],
    );
    let err = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(
        err.contains("WIST3-E03") && err.contains("example.com"),
        "{err}"
    );

    let mut without_tuple = Vec::new();
    caps(&mut without_tuple);
    let fx = common::build_fixture_with_state(without_tuple, 0);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    append_block(
        &fx,
        &[
            delta_entry("https://a.example.com/x"),
            delta_entry("https://b.example.com/x"),
        ],
    );
    sync(&fx, target.path()).unwrap();
    append_block(
        &fx,
        &[
            delta_entry("https://a.example.com/x"),
            delta_entry("https://a.example.com/y"),
        ],
    );
    let err = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(err.contains("WIST3-E03"), "{err}");
}
