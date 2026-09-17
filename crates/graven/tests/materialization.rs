mod common;

use common::{
    key_entry, serve_static, write_anchor, write_block, write_checkpoint, write_index,
    write_manifest, write_payload, write_state, write_tier0, Signer,
};
use graven::store::Store;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;
use wist_core::crypto::b64u_encode;
use wist_core::delta::{content_bytes, delta_id, make_commitment};
use wist_core::envelope::sign_envelope;

fn build_scoped_declaration(signing: &Signer, domain: &str, scope: Option<&[&str]>) -> Value {
    let mut doc = json!({
        "wist_version": "1.0.0",
        "domain": domain,
        "keys": [key_entry(signing, "2026-08-09T00:00:00Z")],
        "seq": 0,
    });
    if let Some(scope) = scope {
        doc["subdomain_scope"] = json!(scope);
    }
    sign_envelope(&doc, "publisher", &signing.kid(), &signing.sk).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn build_declared_delta(
    publisher_domain: &str,
    signer: &Signer,
    url: &str,
    change_type: &str,
    title: &str,
    extract: &str,
    links: &[&str],
    prev: Option<&str>,
    observed_at: &str,
) -> (String, Value, Value) {
    let salt = b64u_encode(&[5u8; 16]);
    let content = json!({
        "extract": extract,
        "links": {"total": links.len() as u64, "urls": links},
        "summary": {"title": title},
    });
    let payload = json!({
        "wist_version": "1.0.0",
        "salt": salt,
        "content": content,
    });
    let commitment = make_commitment(&salt, &content).unwrap();
    let bytes = content_bytes(&content).unwrap();
    let mut delta = json!({
        "wist_version": "1.0.0",
        "publisher": publisher_domain,
        "url": url,
        "change_type": change_type,
        "observed_at": observed_at,
        "payload": {"commitment": commitment, "alg": "HMAC-SHA256", "bytes": bytes},
        "meta": {"lang": "en"},
    });
    if let Some(p) = prev {
        delta["prev"] = p.into();
    }
    let id = delta_id(&delta).unwrap();
    let env = sign_envelope(&delta, "delta", &signer.kid(), &signer.sk).unwrap();
    (id, env, payload)
}

fn build_declared_delete(
    publisher_domain: &str,
    signer: &Signer,
    url: &str,
    prev: &str,
    observed_at: &str,
) -> (String, Value) {
    let delta = json!({
        "wist_version": "1.0.0",
        "publisher": publisher_domain,
        "url": url,
        "change_type": "delete",
        "observed_at": observed_at,
        "prev": prev,
        "meta": {"lang": "en"},
    });
    let id = delta_id(&delta).unwrap();
    (
        id,
        sign_envelope(&delta, "delta", &signer.kid(), &signer.sk).unwrap(),
    )
}

fn wrap_declaration(d: &Value) -> Value {
    json!({"type": "publisher_declaration", "body": d})
}

fn wrap_delta(d: &Value) -> Value {
    json!({"type": "publisher_delta", "body": d})
}

/// A from-scratch Log with an empty Snapshot at `log_position` 0, so every
/// Declaration and Delta this suite cares about is a walked Block rather
/// than adopted Snapshot state.
struct Harness {
    dir: tempfile::TempDir,
    target: tempfile::TempDir,
    log: Signer,
    prev_hash: String,
    next_number: u64,
    base_url: String,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let log = Signer::new([61u8; 32]);
        write_anchor(
            &dir.path().join("anchor.json"),
            &log,
            "materialization-test-log",
        );

        let snapshot_date = "2026-08-09";
        let snapdir = dir.path().join("snapshots").join(snapshot_date);
        let sqlite_bytes = write_tier0(&snapdir.join("tier0/index.sqlite"), &[]);
        let content_digest_value = wist_core::snapshot::content_digest(&[]).unwrap();
        let (state_bytes, state_digest_value) =
            write_state(&snapdir.join("state.json"), &log, 60, &[], &[], 0);

        let (block0, block0_hash) =
            write_block_at(&dir, &log, 0, "sha256:genesis", "2026-08-09T00:00:00Z", &[]);
        let _ = block0;

        write_manifest(
            &snapdir.join("manifest.json"),
            &log,
            snapshot_date,
            0,
            &block0_hash,
            &content_digest_value,
            &state_bytes,
            &state_digest_value,
            &sqlite_bytes,
        );
        write_index(
            &dir.path().join("snapshots/index.json"),
            &log,
            snapshot_date,
            0,
            &format!("/snapshots/{snapshot_date}/manifest.json"),
            &content_digest_value,
        );
        write_checkpoint(dir.path(), &log, 0, &block0_hash, "2026-08-09T00:00:00Z");

        let base_url = format!("http://{}", serve_static(dir.path().to_path_buf()));

        Harness {
            dir,
            target,
            log,
            prev_hash: block0_hash,
            next_number: 1,
            base_url,
        }
    }

    fn payload(&self, id: &str, payload: &Value) {
        let hex = id.strip_prefix("sha256:").unwrap();
        write_payload(self.dir.path(), hex, payload);
    }

    fn seal(&mut self, sealed_at: &str, wrapped_entries: &[Value]) {
        let number = self.next_number;
        let (_, hash) = write_block_at(
            &self.dir,
            &self.log,
            number,
            &self.prev_hash,
            sealed_at,
            wrapped_entries,
        );
        write_checkpoint(self.dir.path(), &self.log, number, &hash, sealed_at);
        self.prev_hash = hash;
        self.next_number += 1;
    }

    fn sync(&self, tier1: bool) {
        graven::sync::run(
            self.dir.path().join("anchor.json").to_str().unwrap(),
            &self.base_url,
            self.target.path(),
            true,
            tier1,
        )
        .unwrap();
    }

    fn log_dir(&self) -> PathBuf {
        graven::registry::log_dir(self.target.path(), "materialization-test-log")
    }

    fn store(&self) -> Store {
        Store::open(&self.log_dir()).unwrap()
    }

    fn conn(&self) -> Connection {
        Connection::open(self.log_dir().join("index.sqlite")).unwrap()
    }
}

fn write_block_at(
    dir: &tempfile::TempDir,
    log: &Signer,
    number: u64,
    prev_hash: &str,
    sealed_at: &str,
    wrapped_entries: &[Value],
) -> (Value, String) {
    let (block, hash) = common::build_block(log, number, prev_hash, sealed_at, wrapped_entries);
    write_block(dir.path(), number, &block);
    (block, hash)
}

fn excluded_count(conn: &Connection, url: &str, publisher: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM excluded_records WHERE url = ?1 AND publisher = ?2",
        (url, publisher),
        |r| r.get(0),
    )
    .unwrap()
}

fn excluded_extract(conn: &Connection, url: &str, publisher: &str) -> Option<String> {
    conn.query_row(
        "SELECT extract FROM excluded_records WHERE url = ?1 AND publisher = ?2",
        (url, publisher),
        |r| r.get(0),
    )
    .unwrap()
}

fn excluded_title(conn: &Connection, url: &str, publisher: &str) -> String {
    conn.query_row(
        "SELECT title FROM excluded_records WHERE url = ?1 AND publisher = ?2",
        (url, publisher),
        |r| r.get(0),
    )
    .unwrap()
}

fn extract_count(conn: &Connection, url: &str, publisher: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM extracts WHERE url = ?1 AND publisher = ?2",
        (url, publisher),
        |r| r.get(0),
    )
    .unwrap()
}

fn links_count(conn: &Connection, source_url: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM links WHERE source_url = ?1",
        [source_url],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn parent_scope_is_excluded_once_the_subdomain_self_declares() {
    let parent = Signer::new([1u8; 32]);
    let child = Signer::new([2u8; 32]);
    let mut h = Harness::new();
    let url = "https://a.example.com/page";

    let decl0 = build_scoped_declaration(&parent, "example.com", Some(&["a.example.com"]));
    let (id1, delta1, payload1) = build_declared_delta(
        "example.com",
        &parent,
        url,
        "new",
        "Parent Title",
        "parent body",
        &[],
        None,
        "2026-08-09T13:00:00Z",
    );
    h.payload(&id1, &payload1);
    h.seal(
        "2026-08-09T13:00:00Z",
        &[wrap_declaration(&decl0), wrap_delta(&delta1)],
    );
    h.sync(true);

    let store = h.store();
    let record = store.get(url).unwrap().unwrap();
    assert_eq!(record.publisher, "example.com");
    assert_eq!(record.title, "Parent Title");
    let conn = h.conn();
    assert_eq!(extract_count(&conn, url, "example.com"), 1);
    drop(conn);

    let own_decl = build_scoped_declaration(&child, "a.example.com", None);
    h.seal("2026-08-09T14:00:00Z", &[wrap_declaration(&own_decl)]);
    h.sync(true);

    let store = h.store();
    assert!(
        store.get(url).unwrap().is_none(),
        "the parent's record is excluded exactly as a delete would exclude it"
    );
    let conn = h.conn();
    assert_eq!(
        extract_count(&conn, url, "example.com"),
        0,
        "the parent's extract leaves with its record"
    );
    assert_eq!(links_count(&conn, url), 0);
    drop(conn);

    let (id2, delta2, payload2) = build_declared_delta(
        "example.com",
        &parent,
        url,
        "update",
        "Parent Title Updated",
        "parent body updated",
        &[],
        Some(&id1),
        "2026-08-09T15:00:00Z",
    );
    h.payload(&id2, &payload2);
    h.seal("2026-08-09T15:00:00Z", &[wrap_delta(&delta2)]);
    h.sync(true);

    let store = h.store();
    assert!(
        store.get(url).unwrap().is_none(),
        "a later parent Delta for a self-declared subdomain's URL materializes nothing"
    );
    let conn = h.conn();
    assert_eq!(
        excluded_count(&conn, url, "example.com"),
        0,
        "a Delta that materializes nothing is not shadowed either"
    );
}

#[test]
fn scoped_url_on_a_nondefault_port_is_excluded_by_self_declaration_too() {
    let parent = Signer::new([1u8; 32]);
    let child = Signer::new([2u8; 32]);
    let mut h = Harness::new();
    let url = "https://a.example.com:8443/page";

    let decl0 = build_scoped_declaration(&parent, "example.com", Some(&["a.example.com"]));
    let (id1, delta1, payload1) = build_declared_delta(
        "example.com",
        &parent,
        url,
        "new",
        "Parent Title",
        "parent body",
        &[],
        None,
        "2026-08-09T13:00:00Z",
    );
    h.payload(&id1, &payload1);
    h.seal(
        "2026-08-09T13:00:00Z",
        &[wrap_declaration(&decl0), wrap_delta(&delta1)],
    );
    h.sync(false);

    let store = h.store();
    let record = store.get(url).unwrap().unwrap();
    assert_eq!(record.publisher, "example.com");

    let own_decl = build_scoped_declaration(&child, "a.example.com", None);
    h.seal("2026-08-09T14:00:00Z", &[wrap_declaration(&own_decl)]);
    h.sync(false);

    let store = h.store();
    assert!(
        store.get(url).unwrap().is_none(),
        "a scoped URL keeps its port normalized, and the port must not hide it from the sweep"
    );
}

#[test]
fn nearest_ancestor_materializes_and_the_farther_ones_content_is_held_excluded() {
    let (h, conn, url) = setup_two_ancestors();

    let record = h.store().get(&url).unwrap().unwrap();
    assert_eq!(
        record.publisher, "b.example.com",
        "the nearest ancestor's record materializes"
    );
    assert_eq!(record.title, "B Title");

    assert_eq!(excluded_count(&conn, &url, "example.com"), 1);
    assert_eq!(
        excluded_extract(&conn, &url, "example.com").as_deref(),
        Some("parent body")
    );
    assert_eq!(excluded_title(&conn, &url, "example.com"), "Parent Title");
}

#[test]
fn farther_ancestors_record_returns_when_the_nearest_deletes() {
    let (mut h, _conn, url) = setup_two_ancestors();

    let b = Signer::new([2u8; 32]);
    let (b_delta_id, _, _) = build_declared_delta(
        "b.example.com",
        &b,
        &url,
        "new",
        "B Title",
        "b body",
        &[],
        None,
        "2026-08-09T14:00:00Z",
    );
    let (_, delete_env) = build_declared_delete(
        "b.example.com",
        &b,
        &url,
        &b_delta_id,
        "2026-08-09T15:00:00Z",
    );
    h.seal("2026-08-09T15:00:00Z", &[wrap_delta(&delete_env)]);
    h.sync(true);

    let store = h.store();
    let record = store.get(&url).unwrap().unwrap();
    assert_eq!(
        record.publisher, "example.com",
        "the farther ancestor's record returns once the nearer one leaves"
    );
    assert_eq!(record.title, "Parent Title");

    let conn = h.conn();
    assert_eq!(excluded_count(&conn, &url, "example.com"), 0);
    assert_eq!(extract_count(&conn, &url, "example.com"), 1);
}

fn setup_two_ancestors() -> (Harness, Connection, String) {
    let parent = Signer::new([1u8; 32]);
    let b = Signer::new([2u8; 32]);
    let mut h = Harness::new();
    let url = "https://a.b.example.com/page".to_string();

    let parent_decl = build_scoped_declaration(&parent, "example.com", Some(&["a.b.example.com"]));
    let (id1, delta1, payload1) = build_declared_delta(
        "example.com",
        &parent,
        &url,
        "new",
        "Parent Title",
        "parent body",
        &[],
        None,
        "2026-08-09T13:00:00Z",
    );
    h.payload(&id1, &payload1);
    h.seal(
        "2026-08-09T13:00:00Z",
        &[wrap_declaration(&parent_decl), wrap_delta(&delta1)],
    );

    let b_decl = build_scoped_declaration(&b, "b.example.com", Some(&["a.b.example.com"]));
    let (id2, delta2, payload2) = build_declared_delta(
        "b.example.com",
        &b,
        &url,
        "new",
        "B Title",
        "b body",
        &[],
        None,
        "2026-08-09T14:00:00Z",
    );
    h.payload(&id2, &payload2);
    h.seal(
        "2026-08-09T14:00:00Z",
        &[wrap_declaration(&b_decl), wrap_delta(&delta2)],
    );
    h.sync(true);

    let conn = h.conn();
    (h, conn, url)
}

#[test]
fn a_farther_ancestors_later_delta_does_not_displace_the_nearest() {
    let (mut h, _conn, url) = setup_two_ancestors();

    let parent = Signer::new([1u8; 32]);
    let (id1, _, _) = build_declared_delta(
        "example.com",
        &parent,
        &url,
        "new",
        "Parent Title",
        "parent body",
        &[],
        None,
        "2026-08-09T13:00:00Z",
    );
    let (id3, delta3, payload3) = build_declared_delta(
        "example.com",
        &parent,
        &url,
        "update",
        "Parent Second Title",
        "parent second body",
        &[],
        Some(&id1),
        "2026-08-09T16:00:00Z",
    );
    h.payload(&id3, &payload3);
    h.seal("2026-08-09T16:00:00Z", &[wrap_delta(&delta3)]);
    h.sync(true);

    let record = h.store().get(&url).unwrap().unwrap();
    assert_eq!(
        record.publisher, "b.example.com",
        "a later Delta from a farther ancestor never takes the URL"
    );
    assert_eq!(record.title, "B Title");

    let conn = h.conn();
    assert_eq!(excluded_count(&conn, &url, "example.com"), 1);
    assert_eq!(
        excluded_title(&conn, &url, "example.com"),
        "Parent Second Title",
        "the excluded record keeps its Publisher's newest content"
    );
}

#[test]
fn the_greater_non_ancestor_does_not_displace_the_least_in_octet_order() {
    let alpha = Signer::new([3u8; 32]);
    let zeta = Signer::new([4u8; 32]);
    let mut h = Harness::new();
    let url = "https://host.example.org/page".to_string();

    let alpha_decl = build_scoped_declaration(&alpha, "alpha.example", Some(&["host.example.org"]));
    let (id1, delta1, payload1) = build_declared_delta(
        "alpha.example",
        &alpha,
        &url,
        "new",
        "Alpha Title",
        "alpha body",
        &[],
        None,
        "2026-08-09T13:00:00Z",
    );
    h.payload(&id1, &payload1);
    h.seal(
        "2026-08-09T13:00:00Z",
        &[wrap_declaration(&alpha_decl), wrap_delta(&delta1)],
    );

    let zeta_decl = build_scoped_declaration(&zeta, "zeta.example", Some(&["host.example.org"]));
    let (id2, delta2, payload2) = build_declared_delta(
        "zeta.example",
        &zeta,
        &url,
        "new",
        "Zeta Title",
        "zeta body",
        &[],
        None,
        "2026-08-09T14:00:00Z",
    );
    h.payload(&id2, &payload2);
    h.seal(
        "2026-08-09T14:00:00Z",
        &[wrap_declaration(&zeta_decl), wrap_delta(&delta2)],
    );
    h.sync(true);

    let record = h.store().get(&url).unwrap().unwrap();
    assert_eq!(
        record.publisher, "alpha.example",
        "the least non-ancestor domain in octet order holds the record"
    );
    let conn = h.conn();
    assert_eq!(excluded_count(&conn, &url, "zeta.example"), 1);
    assert_eq!(excluded_title(&conn, &url, "zeta.example"), "Zeta Title");
}
