mod common;

use common::{Content, Fixture, Signer, OBSERVED, RECORDS};
use graven::store::Store;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

struct Harness {
    fx: Fixture,
    target: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let fx = common::build_fixture_without_records();
        let target = tempfile::tempdir().unwrap();
        common::sync(&fx, target.path(), true);
        Harness { fx, target }
    }

    fn log_dir(&self) -> PathBuf {
        common::synced_log_dir(self.target.path())
    }

    fn page(&self, publisher: &str, url: &str, title: &str, links: &[&str]) -> Value {
        let extract = format!("{title} body");
        let (item, payload) = common::page(
            publisher,
            url,
            OBSERVED,
            &Content {
                title,
                r#abstract: None,
                extract: &extract,
                links,
            },
        );
        common::serve_payload(self.fx.dir.path(), &item, &payload);
        item
    }

    fn declare(&self, entries: &[Value]) {
        let at = common::next_instant(&self.fx);
        common::seal_next(&self.fx, &at, entries);
    }

    fn publish(&self, signer: &Signer, publisher: &str, items: &[Value], extra: &[Value]) {
        common::seal_catalog(&self.fx, signer, publisher, items, extra);
    }

    fn sync(&self) {
        common::sync(&self.fx, self.target.path(), true);
        common::assert_records_materialized(&self.log_dir());
    }

    fn row(&self, url: &str) -> Option<(String, String, Option<String>)> {
        common::record_row(&self.log_dir(), url)
    }

    fn extracts(&self, url: &str) -> i64 {
        common::count_where(&self.log_dir(), "extracts", "url", url)
    }

    fn links(&self, url: &str) -> i64 {
        common::count_where(&self.log_dir(), "links", "source_url", url)
    }

    fn height_of(&self, url: &str) -> Option<u64> {
        use rusqlite::OptionalExtension;
        rusqlite::Connection::open(self.log_dir().join("index.sqlite"))
            .unwrap()
            .query_row(
                "SELECT h.height FROM record_heights h JOIN records r ON r.url = h.url AND r.publisher = h.publisher WHERE r.url = ?1",
                [url],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .unwrap()
            .map(|height| height as u64)
    }

    fn holds_record(&self, publisher: &str, url: &str) -> bool {
        common::holds_record_tuple(&self.log_dir(), publisher, url)
    }
}

fn owner() -> Signer {
    Signer::new([1u8; 32])
}

fn parent() -> Signer {
    Signer::new([11u8; 32])
}

fn child() -> Signer {
    Signer::new([12u8; 32])
}

fn title(row: Option<(String, String, Option<String>)>) -> Option<String> {
    row.and_then(|(_, _, title)| title)
}

fn publisher_of(row: Option<(String, String, Option<String>)>) -> Option<String> {
    row.map(|(publisher, _, _)| publisher)
}

#[test]
fn parent_scope_is_excluded_once_the_subdomain_self_declares() {
    let h = Harness::new();
    let url = "https://a.example.com/page";
    h.declare(&[common::scoped_declaration_entry(
        &parent(),
        "example.com",
        &["a.example.com"],
    )]);
    let first = h.page(
        "example.com",
        url,
        "Parent Title",
        &["https://other.example/x"],
    );
    h.publish(&parent(), "example.com", &[first], &[]);
    h.sync();
    assert_eq!(publisher_of(h.row(url)).as_deref(), Some("example.com"));
    assert_eq!(title(h.row(url)).as_deref(), Some("Parent Title"));
    assert_eq!(h.extracts(url), 1);
    assert_eq!(h.links(url), 1);

    h.declare(&[common::declaration_entry(&child(), "a.example.com")]);
    h.sync();
    assert!(
        h.row(url).is_none(),
        "the parent's record is not materialized once the host self-declares"
    );
    assert_eq!(
        h.extracts(url),
        0,
        "the parent's extract leaves with its row"
    );
    assert_eq!(h.links(url), 0);
    assert!(h.holds_record("example.com", url), "it stays a record");

    let second = h.page("example.com", url, "Parent Title Updated", &[]);
    h.publish(&parent(), "example.com", &[second], &[]);
    h.sync();
    assert!(
        h.row(url).is_none(),
        "a later parent Item for a self-declared host's URL materializes nothing"
    );
}

#[test]
fn scoped_url_on_a_nondefault_port_is_excluded_by_self_declaration_too() {
    let h = Harness::new();
    let url = "https://a.example.com:8443/page";
    h.declare(&[common::scoped_declaration_entry(
        &parent(),
        "example.com",
        &["a.example.com"],
    )]);
    let item = h.page("example.com", url, "Parent Title", &[]);
    h.publish(&parent(), "example.com", &[item], &[]);
    h.sync();
    assert_eq!(publisher_of(h.row(url)).as_deref(), Some("example.com"));

    h.declare(&[common::declaration_entry(&child(), "a.example.com")]);
    h.sync();
    assert!(
        h.row(url).is_none(),
        "the port does not hide a URL from its host's self-declaration"
    );
}

fn setup_two_ancestors() -> (Harness, String) {
    let h = Harness::new();
    let url = "https://a.b.example.com/page".to_string();
    h.declare(&[
        common::scoped_declaration_entry(&parent(), "example.com", &["a.b.example.com"]),
        common::scoped_declaration_entry(&child(), "b.example.com", &["a.b.example.com"]),
    ]);
    let far = h.page("example.com", &url, "Parent Title", &[]);
    h.publish(&parent(), "example.com", &[far], &[]);
    let near = h.page("b.example.com", &url, "B Title", &[]);
    h.publish(&child(), "b.example.com", &[near], &[]);
    h.sync();
    (h, url)
}

#[test]
fn nearest_ancestor_materializes_and_the_farther_ones_record_stays_unmaterialized() {
    let (h, url) = setup_two_ancestors();
    assert_eq!(publisher_of(h.row(&url)).as_deref(), Some("b.example.com"));
    assert_eq!(title(h.row(&url)).as_deref(), Some("B Title"));
    assert!(h.holds_record("example.com", &url));
}

#[test]
fn farther_ancestors_record_returns_with_its_content_when_the_nearest_is_removed() {
    let (h, url) = setup_two_ancestors();
    let removed = common::removed_item("b.example.com", &url, OBSERVED);
    h.publish(&child(), "b.example.com", &[removed], &[]);
    h.declare(&[common::declaration_entry(
        &Signer::new([15u8; 32]),
        "later.example",
    )]);
    h.sync();
    let removing = h.fx.head_number() - 1;
    assert_eq!(
        h.height_of(&url),
        Some(removing),
        "the row's height is that of the Epoch that made it"
    );
    assert_eq!(
        publisher_of(h.row(&url)).as_deref(),
        Some("example.com"),
        "the farther ancestor's record returns once the nearer one leaves"
    );
    assert_eq!(
        title(h.row(&url)).as_deref(),
        Some("Parent Title"),
        "its Payload is fetched when it becomes materialized"
    );
    assert_eq!(h.extracts(&url), 1);
}

#[test]
fn a_farther_ancestors_later_item_does_not_displace_the_nearest() {
    let (h, url) = setup_two_ancestors();
    let later = h.page("example.com", &url, "Parent Second Title", &[]);
    h.publish(&parent(), "example.com", &[later], &[]);
    h.sync();
    assert_eq!(publisher_of(h.row(&url)).as_deref(), Some("b.example.com"));
    assert_eq!(title(h.row(&url)).as_deref(), Some("B Title"));
}

#[test]
fn the_greater_non_ancestor_does_not_displace_the_least_in_octet_order() {
    let h = Harness::new();
    let url = "https://host.example.org/page";
    let alpha = Signer::new([13u8; 32]);
    let zeta = Signer::new([14u8; 32]);
    h.declare(&[
        common::scoped_declaration_entry(&alpha, "alpha.example", &["host.example.org"]),
        common::scoped_declaration_entry(&zeta, "zeta.example", &["host.example.org"]),
    ]);
    let first = h.page("alpha.example", url, "Alpha Title", &[]);
    h.publish(&alpha, "alpha.example", &[first], &[]);
    h.sync();
    let second = h.page("zeta.example", url, "Zeta Title", &[]);
    h.publish(&zeta, "zeta.example", &[second], &[]);
    h.sync();
    assert_eq!(publisher_of(h.row(url)).as_deref(), Some("alpha.example"));
    assert!(h.holds_record("zeta.example", url));
}

#[test]
fn a_removed_item_removes_the_row_and_its_derived_content() {
    let h = Harness::new();
    let url = "https://records.example/gone";
    let item = h.page(RECORDS, url, "Gone", &["https://other.example/y"]);
    let kept = h.page(RECORDS, "https://records.example/kept", "Kept", &[]);
    h.publish(&owner(), RECORDS, &[item, kept], &[]);
    h.sync();
    assert!(h.row(url).is_some());

    let removed = common::removed_item(RECORDS, url, OBSERVED);
    h.publish(&owner(), RECORDS, &[removed], &[]);
    h.sync();
    assert!(h.row(url).is_none());
    assert_eq!(h.extracts(url), 0);
    assert_eq!(h.links(url), 0);
    assert!(h.row("https://records.example/kept").is_some());
}

#[test]
fn a_withdrawal_removes_the_row_and_leaves_the_record() {
    let h = Harness::new();
    let url = "https://records.example/withdrawn";
    let item = h.page(RECORDS, url, "Withdrawn", &["https://other.example/z"]);
    h.publish(&owner(), RECORDS, std::slice::from_ref(&item), &[]);
    h.sync();
    assert_eq!(h.extracts(url), 1);

    let withdrawal = common::withdrawal_entry(&h.fx.log, "log1", &item, "2026-08-09T15:00:00Z");
    h.declare(&[withdrawal]);
    let report = common::sync(&h.fx, h.target.path(), true);
    common::assert_records_materialized(&h.log_dir());
    assert_eq!(report.withdrawn, 1);
    assert!(h.row(url).is_none());
    assert_eq!(h.extracts(url), 0);
    assert_eq!(h.links(url), 0);
    assert!(h.holds_record(RECORDS, url));
}

#[test]
fn narrowing_removes_the_rows_outside_the_new_scope() {
    let h = Harness::new();
    let inside = "https://records.example/blog/kept";
    let outside = "https://records.example/old/dropped";
    let kept = h.page(RECORDS, inside, "Kept", &[]);
    let dropped = h.page(RECORDS, outside, "Dropped", &[]);
    h.publish(&owner(), RECORDS, &[kept, dropped], &[]);
    h.sync();
    assert!(h.row(outside).is_some());

    let first = common::build_declaration(&owner(), RECORDS);
    let mut narrowed = first["publisher"].clone();
    narrowed["seq"] = json!(1);
    narrowed["prev_declaration"] = json!(common::declaration_hash(&first));
    narrowed["collections"] = json!([{
        "name": "default",
        "scope": [{"url": "https://records.example/blog/", "match": "prefix"}],
    }]);
    let body =
        wist_core::envelope::sign_envelope(&narrowed, "publisher", &owner().kid(), &owner().sk)
            .unwrap();
    h.declare(&[json!({"type": "publisher_declaration", "body": body})]);
    h.sync();
    assert!(h.row(outside).is_none());
    assert!(!h.holds_record(RECORDS, outside));
    assert!(h.row(inside).is_some());
    assert_eq!(h.extracts(outside), 0);
}

#[test]
fn a_base_removes_the_rows_its_catalog_does_not_seal_again() {
    let h = Harness::new();
    let again = "https://records.example/again";
    let dropped = "https://records.example/dropped";
    let first = h.page(RECORDS, again, "Again", &[]);
    let other = h.page(RECORDS, dropped, "Dropped", &[]);
    h.publish(&owner(), RECORDS, &[first.clone(), other], &[]);
    h.sync();
    assert!(h.row(dropped).is_some());

    let at = "2027-02-10T00:00:00Z";
    let entries = common::catalog_entries(&owner(), RECORDS, at, &[first]);
    common::seal_next(&h.fx, at, &entries);
    h.sync();
    assert!(h.row(dropped).is_none(), "the base removes the record");
    assert!(!h.holds_record(RECORDS, dropped));
    let row = h.row(again).unwrap();
    assert_eq!(row.2.as_deref(), Some("Again"));
    let attested: String = rusqlite::Connection::open(h.log_dir().join("index.sqlite"))
        .unwrap()
        .query_row(
            "SELECT attested_at FROM records WHERE url = ?1",
            [again],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        attested, at,
        "the Item sealed again carries its new Catalog"
    );
}

fn payload_requests(seen: &std::sync::Mutex<Vec<String>>, item: &Value) -> usize {
    let path = common::payload_path(Path::new("/"), item);
    let wanted = path.to_str().unwrap();
    seen.lock().unwrap().iter().filter(|p| *p == wanted).count()
}

#[test]
fn a_payload_that_cannot_be_obtained_leaves_the_row_without_content_until_it_can() {
    let fx = common::build_fixture_without_records();
    let (base, seen) = common::serve_recording(fx.dir.path().to_path_buf());
    let base_url = format!("http://{base}");
    let target = tempfile::tempdir().unwrap();
    let run = || {
        graven::sync::run(
            fx.anchor_path().to_str().unwrap(),
            &base_url,
            target.path(),
            true,
            true,
        )
        .unwrap()
    };
    run();
    let url = "https://records.example/late";
    let (item, payload) = common::page(RECORDS, url, OBSERVED, &Content::of("Late"));
    common::seal_catalog(&fx, &owner(), RECORDS, std::slice::from_ref(&item), &[]);
    let report = run();
    let log_dir = common::synced_log_dir(target.path());
    common::assert_records_materialized(&log_dir);
    assert_eq!(report.head, 2, "a missing Payload never stops the run");
    let held = Store::open(&log_dir).unwrap().get(url).unwrap().unwrap();
    assert_eq!(held.title, None);
    assert_eq!(held.r#abstract, None);
    assert_eq!(common::count_where(&log_dir, "extracts", "url", url), 0);
    assert_eq!(payload_requests(&seen, &item), 1);

    run();
    assert_eq!(
        payload_requests(&seen, &item),
        1,
        "a run that adopts no Checkpoint changes nothing"
    );

    common::serve_payload(fx.dir.path(), &item, &payload);
    common::extend_fixture(&fx);
    run();
    common::assert_records_materialized(&log_dir);
    let held = Store::open(&log_dir).unwrap().get(url).unwrap().unwrap();
    assert_eq!(held.title.as_deref(), Some("Late"));
    assert_eq!(common::count_where(&log_dir, "extracts", "url", url), 1);
}

#[test]
fn a_payload_that_fails_its_commitment_supplies_no_content() {
    let h = Harness::new();
    let url = "https://records.example/forged";
    let item = h.page(RECORDS, url, "Signed Title", &[]);
    let (_, forged) = common::page(RECORDS, url, OBSERVED, &Content::of("Forged Title"));
    common::serve_payload(h.fx.dir.path(), &item, &forged);
    h.publish(&owner(), RECORDS, &[item], &[]);
    h.sync();
    assert!(h.row(url).is_some());
    assert_eq!(title(h.row(url)), None);
    assert_eq!(h.extracts(url), 0);
}
