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

fn append_epoch(fx: &common::Fixture, entries: &[Value]) -> u64 {
    let sealed_at = common::next_instant(fx);
    common::seal_next(fx, &sealed_at, entries)
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

struct Publisher {
    signer: common::Signer,
    host: &'static str,
}

fn declare(fx: &common::Fixture, publishers: &[Publisher]) {
    let entries: Vec<Value> = publishers
        .iter()
        .map(|p| common::declaration_entry(&p.signer, p.host))
        .collect();
    append_epoch(fx, &entries);
}

fn catalog_of(fx: &common::Fixture, publisher: &Publisher, paths: &[&str]) -> common::Published {
    let generated_at = common::next_instant(fx);
    let items: Vec<Value> = paths
        .iter()
        .map(|path| {
            common::page_item(
                publisher.host,
                &format!("https://{}/{path}", publisher.host),
                "2026-08-09T12:00:00Z",
            )
        })
        .collect();
    common::publish(
        &publisher.signer,
        publisher.host,
        "default",
        &generated_at,
        &items,
    )
}

fn publishers() -> [Publisher; 2] {
    [
        Publisher {
            signer: common::Signer::new([31u8; 32]),
            host: "a.example.com",
        },
        Publisher {
            signer: common::Signer::new([32u8; 32]),
            host: "b.example.com",
        },
    ]
}

fn rejected_at(error: &str, height: u64) -> bool {
    error.contains("the Epoch is rejected (WIST3-E03)")
        && error.contains(&format!("stopped at epoch {height} "))
}

fn record_urls(target: &std::path::Path) -> Vec<String> {
    common::state_tuples(&common::synced_log_dir(target))
        .into_iter()
        .filter(|tuple| tuple[0] == "record")
        .map(|tuple| tuple[2].as_str().unwrap().to_owned())
        .collect()
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
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    assert_eq!(held(target.path()), (Vec::new(), Vec::new()));

    let identifier = serve_list(&fx, LIST);
    let height = append_epoch(&fx, &[suffix_act(&fx, &identifier, LIST.len())]);
    sync(&fx, target.path()).unwrap();
    assert_eq!(
        held(target.path()),
        (
            vec![identifier.clone()],
            vec![(height as i64, identifier.clone())]
        )
    );

    append_epoch(&fx, &[suffix_act(&fx, &identifier, LIST.len() + 1)]);
    sync(&fx, target.path()).unwrap();
    assert_eq!(held(target.path()).1.len(), 1);

    let unserved = wist_core::suffix_list::identifier(b"net\n");
    append_epoch(&fx, &[suffix_act(&fx, &unserved, 4)]);
    let err = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(err.contains("WIST3-E01"), "{err}");
}

#[test]
fn a_served_file_that_does_not_hash_to_its_name_fails_the_sync() {
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    let identifier = serve_list(&fx, LIST);
    let hex = identifier.strip_prefix("sha256:").unwrap();
    std::fs::write(
        fx.dir.path().join(format!("log/suffix-lists/{hex}.dat")),
        b"net\n",
    )
    .unwrap();
    append_epoch(&fx, &[suffix_act(&fx, &identifier, LIST.len())]);
    let err = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(err.contains("WIST3-E03"), "{err}");
}

#[test]
fn capacity_is_counted_per_registrable_domain_under_the_adopted_tuple() {
    let identifier = wist_core::suffix_list::identifier(LIST);
    let caps = |extra: &mut Vec<StateEntry>| {
        for name in ["domain_epoch_entries_max", "labeler_epoch_entries_max"] {
            extra.push(StateEntry::Parameter(ParameterEntry {
                name: name.into(),
                effective_at: "2026-08-09T13:00:00Z".into(),
                value: 1,
            }));
        }
    };
    let [a, b] = publishers();

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
    declare(&fx, &[a, b]);
    let [a, b] = publishers();
    let a_list = catalog_of(&fx, &a, &["x"]);
    append_epoch(&fx, std::slice::from_ref(&a_list.catalog));
    let b_list = catalog_of(&fx, &b, &["x"]);
    append_epoch(&fx, std::slice::from_ref(&b_list.catalog));
    let catalogs = sync(&fx, target.path()).unwrap().head;
    let height = append_epoch(&fx, &[a_list.items[0].clone(), b_list.items[0].clone()]);
    let err = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(rejected_at(&err, height), "{err}");
    assert_eq!(
        graven::store::synced_state(&common::synced_log_dir(target.path()))
            .unwrap()
            .epoch_number,
        catalogs,
        "the rejected Epoch leaves the verified head"
    );
    assert!(record_urls(target.path()).is_empty());

    let mut without_tuple = Vec::new();
    caps(&mut without_tuple);
    let fx = common::build_fixture_with_state(without_tuple, 0);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    let [a, b] = publishers();
    declare(&fx, &[a, b]);
    let [a, b] = publishers();
    let a_list = catalog_of(&fx, &a, &["x", "y"]);
    append_epoch(&fx, std::slice::from_ref(&a_list.catalog));
    let b_list = catalog_of(&fx, &b, &["x"]);
    append_epoch(&fx, std::slice::from_ref(&b_list.catalog));
    let a_x = a_list
        .items
        .iter()
        .find(|entry| entry["body"]["item"]["url"] == "https://a.example.com/x")
        .unwrap()
        .clone();
    append_epoch(&fx, &[a_x, b_list.items[0].clone()]);
    sync(&fx, target.path()).unwrap();
    assert_eq!(
        record_urls(target.path()),
        ["https://a.example.com/x", "https://b.example.com/x"]
    );
    let height = append_epoch(&fx, &a_list.items);
    let err = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(rejected_at(&err, height), "{err}");
}
