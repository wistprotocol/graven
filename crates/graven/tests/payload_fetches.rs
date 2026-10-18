mod common;

use common::{Content, Fixture, Signer, OBSERVED, RECORDS};
use rusqlite::Connection;
use serde_json::Value;
use std::path::Path;

const PAGES: usize = 12;
const FORGED: usize = 3;
const MISSING: usize = 7;

fn url_of(index: usize) -> String {
    format!("https://records.example/page-{index}")
}

fn publish_batch(fx: &Fixture) -> Vec<Value> {
    let mut items = Vec::new();
    for index in 0..PAGES {
        let url = url_of(index);
        let title = format!("Title {index}");
        let extract = format!("Body {index}");
        let links = [format!(
            "https://elsewhere.example/page-{}",
            (index + 1) % PAGES
        )];
        let links: Vec<&str> = links.iter().map(String::as_str).collect();
        let (item, payload) = common::page(
            RECORDS,
            &url,
            OBSERVED,
            &Content {
                title: &title,
                r#abstract: None,
                extract: &extract,
                links: &links,
            },
        );
        match index {
            FORGED => {
                let (_, forged) = common::page(RECORDS, &url, OBSERVED, &Content::of("Forged"));
                common::serve_payload(fx.dir.path(), &item, &forged);
            }
            MISSING => {}
            _ => common::serve_payload(fx.dir.path(), &item, &payload),
        }
        items.push(item);
    }
    common::seal_catalog(fx, &Signer::new([1u8; 32]), RECORDS, &items, &[]);
    items
}

fn sync_with(fx: &Fixture, base: &str, dir: &Path, payload_fetches: usize) {
    graven::sync::follow(
        &graven::sync::Follow {
            anchor: fx.anchor_path().to_str().unwrap(),
            log_base: base,
            mirrors: &[],
            witnesses: &[],
            tier1: true,
            allow_http: true,
            catch_up_epochs: None,
            payload_fetches,
        },
        dir,
    )
    .unwrap();
    common::assert_records_materialized(&common::synced_log_dir(dir));
}

fn dump(dir: &Path) -> Vec<String> {
    let conn = Connection::open(common::synced_log_dir(dir).join("index.sqlite")).unwrap();
    let mut rows = Vec::new();
    for query in [
        "SELECT url || '|' || publisher || '|' || item_id || '|' || IFNULL(title, '-') || '|' || IFNULL(abstract, '-') FROM records ORDER BY url, publisher",
        "SELECT url || '|' || publisher || '|' || item_id || '|' || extract FROM extracts ORDER BY url, publisher",
        "SELECT source_url || '|' || target_url || '|' || position FROM links ORDER BY source_url, position",
        "SELECT url || '|' || publisher || '|' || height FROM record_heights ORDER BY url, publisher",
    ] {
        let mut stmt = conn.prepare(query).unwrap();
        rows.extend(
            stmt.query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap),
        );
    }
    rows
}

fn payload_requests(seen: &std::sync::Mutex<Vec<String>>, item: &Value) -> usize {
    let path = common::payload_path(Path::new("/"), item);
    let wanted = path.to_str().unwrap();
    seen.lock().unwrap().iter().filter(|p| *p == wanted).count()
}

#[test]
fn concurrent_payload_fetches_materialize_the_store_a_sequential_sync_does() {
    let fx = common::build_fixture_without_records();
    publish_batch(&fx);
    let sequential = tempfile::tempdir().unwrap();
    let concurrent = tempfile::tempdir().unwrap();
    sync_with(&fx, &fx.base_url, sequential.path(), 1);
    sync_with(&fx, &fx.base_url, concurrent.path(), 4);
    assert_eq!(dump(sequential.path()), dump(concurrent.path()));
}

#[test]
fn concurrently_fetched_payloads_are_verified_individually() {
    let fx = common::build_fixture_without_records();
    publish_batch(&fx);
    let target = tempfile::tempdir().unwrap();
    sync_with(&fx, &fx.base_url, target.path(), 4);
    let log_dir = common::synced_log_dir(target.path());
    for index in 0..PAGES {
        let url = url_of(index);
        let (_, _, title) = common::record_row(&log_dir, &url).unwrap();
        let extracts = common::count_where(&log_dir, "extracts", "url", &url);
        if index == FORGED || index == MISSING {
            assert_eq!(title, None, "{url} carries no content");
            assert_eq!(extracts, 0, "{url} carries no extract");
        } else {
            assert_eq!(title.as_deref(), Some(format!("Title {index}").as_str()));
            assert_eq!(extracts, 1, "{url} carries its extract");
        }
    }
}

#[test]
fn concurrent_payload_fetches_request_each_payload_once() {
    let fx = common::build_fixture_without_records();
    let items = publish_batch(&fx);
    let (base, seen) = common::serve_recording(fx.dir.path().to_path_buf());
    let target = tempfile::tempdir().unwrap();
    sync_with(&fx, &format!("http://{base}"), target.path(), 4);
    for item in &items {
        assert_eq!(payload_requests(&seen, item), 1);
    }
}
