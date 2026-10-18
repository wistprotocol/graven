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

fn rejected_at(report: &graven::sync::SyncReport, height: u64) -> bool {
    report.head == height
        && report
            .rejected
            .iter()
            .any(|epoch| epoch.epoch_number == height && epoch.codes == ["WIST3-E03"])
}

fn record_urls(target: &std::path::Path) -> Vec<String> {
    common::state_tuples(&common::synced_log_dir(target))
        .into_iter()
        .filter(|tuple| tuple[0] == "record" && tuple[1] != common::RECORDS)
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
    assert!(height > catalogs);
    let report = sync(&fx, target.path()).unwrap();
    assert!(rejected_at(&report, height), "{report}");
    assert!(
        record_urls(target.path()).is_empty(),
        "the rejected Epoch applies none of its Items"
    );
    append_epoch(&fx, &[b_list.items[0].clone()]);
    let report = sync(&fx, target.path()).unwrap();
    assert!(report.rejected.is_empty(), "{report}");
    assert_eq!(record_urls(target.path()), ["https://b.example.com/x"]);

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
    let report = sync(&fx, target.path()).unwrap();
    assert!(rejected_at(&report, height), "{report}");
    let a_y = a_list
        .items
        .iter()
        .find(|entry| entry["body"]["item"]["url"] == "https://a.example.com/y")
        .unwrap()
        .clone();
    append_epoch(&fx, &[a_y]);
    sync(&fx, target.path()).unwrap();
    assert_eq!(
        record_urls(target.path()),
        [
            "https://a.example.com/x",
            "https://a.example.com/y",
            "https://b.example.com/x"
        ]
    );
}

fn sync_with_mirror(
    fx: &common::Fixture,
    target: &std::path::Path,
    mirror: &str,
) -> graven::error::Result<graven::sync::SyncReport> {
    graven::sync::follow(
        &graven::sync::Follow {
            anchor: fx.anchor_path().to_str().unwrap(),
            log_base: &fx.base_url,
            mirrors: &[mirror.to_owned()],
            witnesses: &[],
            tier1: false,
            allow_http: true,
            catch_up_epochs: None,
            payload_fetches: graven::sync::DEFAULT_PAYLOAD_FETCHES,
        },
        target,
    )
}

type Requests = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

fn mirror_of(fx: &common::Fixture) -> (tempfile::TempDir, String, Requests) {
    let dir = tempfile::tempdir().unwrap();
    common::copy_dir(fx.dir.path(), dir.path());
    let (addr, requests) = common::serve_recording(dir.path().to_path_buf());
    (dir, format!("http://{addr}"), requests)
}

fn list_path(identifier: &str) -> String {
    format!(
        "/log/suffix-lists/{}.dat",
        identifier.strip_prefix("sha256:").unwrap()
    )
}

fn asked_for(requests: &Requests, path: &str) -> bool {
    requests
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|seen| seen == path)
}

/// WIST-3 §9 `WIST3-E01`.
#[test]
fn a_suffix_list_snapshot_missing_at_the_primary_is_fetched_from_the_mirror_during_the_walk() {
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    let identifier = serve_list(&fx, LIST);
    let height = append_epoch(&fx, &[suffix_act(&fx, &identifier, LIST.len())]);
    let (_mirror_dir, mirror, requests) = mirror_of(&fx);
    std::fs::remove_file(fx.dir.path().join(&list_path(&identifier)[1..])).unwrap();

    let report = sync_with_mirror(&fx, target.path(), &mirror).unwrap();
    assert_eq!(report.head, height);
    assert!(asked_for(&requests, &list_path(&identifier)));
    assert_eq!(
        held(target.path()),
        (vec![identifier.clone()], vec![(height as i64, identifier)])
    );
}

/// WIST-3 §6 and §9 `WIST3-E03`: integrity never depends on the source.
#[test]
fn a_suffix_list_file_not_hashing_to_its_name_at_the_primary_is_fetched_from_the_mirror() {
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    let identifier = serve_list(&fx, LIST);
    let height = append_epoch(&fx, &[suffix_act(&fx, &identifier, LIST.len())]);
    let (_mirror_dir, mirror, requests) = mirror_of(&fx);
    std::fs::write(fx.dir.path().join(&list_path(&identifier)[1..]), b"net\n").unwrap();

    let report = sync_with_mirror(&fx, target.path(), &mirror).unwrap();
    assert_eq!(report.head, height);
    assert!(asked_for(&requests, &list_path(&identifier)));
}

/// WIST-3 §9 `WIST3-E01`.
#[test]
fn a_suffix_list_snapshot_no_source_serves_fails_the_walk_with_e01() {
    let fx = common::build_fixture(false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path()).unwrap();
    let identifier = serve_list(&fx, LIST);
    append_epoch(&fx, &[suffix_act(&fx, &identifier, LIST.len())]);
    let (mirror_dir, mirror, requests) = mirror_of(&fx);
    for served in [fx.dir.path(), mirror_dir.path()] {
        std::fs::remove_file(served.join(&list_path(&identifier)[1..])).unwrap();
    }

    let error = sync_with_mirror(&fx, target.path(), &mirror)
        .unwrap_err()
        .to_string();
    assert!(error.contains("WIST3-E01"), "{error}");
    assert!(asked_for(&requests, &list_path(&identifier)));
}

/// WIST-3 §8 step 4 and §9 `WIST3-E01`.
#[test]
fn a_cold_start_fetches_the_suffix_list_in_force_from_the_mirror_when_the_primary_lacks_it() {
    let identifier = wist_core::suffix_list::identifier(LIST);
    let tuple = vec![StateEntry::SuffixList(SuffixListEntry {
        identifier: identifier.clone(),
        sealing_height: 0,
    })];
    let fx = common::build_fixture_with_state(tuple.clone(), 0);
    let (mirror_dir, mirror, requests) = mirror_of(&fx);
    let hex = identifier.strip_prefix("sha256:").unwrap();
    std::fs::create_dir_all(mirror_dir.path().join("log/suffix-lists")).unwrap();
    std::fs::write(
        mirror_dir
            .path()
            .join(format!("log/suffix-lists/{hex}.dat")),
        LIST,
    )
    .unwrap();

    let target = tempfile::tempdir().unwrap();
    sync_with_mirror(&fx, target.path(), &mirror).unwrap();
    assert!(asked_for(&requests, &list_path(&identifier)));
    assert_eq!(held(target.path()).1, vec![(0, identifier.clone())]);

    let fx = common::build_fixture_with_state(tuple, 0);
    let (_mirror_dir, mirror, _requests) = mirror_of(&fx);
    let target = tempfile::tempdir().unwrap();
    let error = sync_with_mirror(&fx, target.path(), &mirror)
        .unwrap_err()
        .to_string();
    assert!(error.contains("WIST3-E01"), "{error}");
}
