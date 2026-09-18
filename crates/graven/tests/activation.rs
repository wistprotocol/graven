mod common;

use rusqlite::OptionalExtension;

use graven::store::Store;
use serde_json::Value;
use wist_core::objects::{ParameterEntry, PendingDeclarationEntry, StateEntry};

const NOT_BEFORE: &str = "2026-08-09T00:00:00Z";

fn sealed_at(height: u64) -> String {
    let start = wist_core::timestamp::log_seconds("2026-08-09T12:00:00Z").unwrap();
    wist_core::timestamp::instant(start + 3600 * height as i64).unwrap()
}

fn append(fx: &common::Fixture, entries: &[Value]) -> u64 {
    let next = fx.head_number() + 1;
    common::seal_next(fx, &sealed_at(next), entries)
}

fn sync(fx: &common::Fixture, target: &std::path::Path) -> graven::sync::SyncReport {
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target,
        true,
        false,
    )
    .unwrap()
}

fn delta(fx: &common::Fixture, signer: &common::Signer, path: &str) -> (String, Value) {
    let url = format!("https://records.example/{path}");
    let (id, envelope, payload) = common::build_delta(signer, &url, path, None, "body", None);
    common::write_payload(fx.dir.path(), id.strip_prefix("sha256:").unwrap(), &payload);
    (
        url,
        serde_json::json!({"type": "publisher_delta", "body": envelope}),
    )
}

fn declaration_entry(envelope: Value) -> Value {
    serde_json::json!({"type": "publisher_declaration", "body": envelope})
}

fn owner() -> common::Signer {
    common::Signer::new([1u8; 32])
}

fn fresh_declaration(fx: &common::Fixture, thief: &common::Signer) -> Value {
    let first = common::build_declaration(&owner(), &fx.domain);
    common::build_declaration_full(
        thief,
        &fx.domain,
        1,
        Some(&common::declaration_hash(&first)),
        &[(thief, NOT_BEFORE)],
    )
}

fn present(target: &std::path::Path, url: &str) -> bool {
    Store::open(&common::synced_log_dir(target))
        .unwrap()
        .get(url)
        .unwrap()
        .is_some()
}

#[test]
fn a_fresh_identity_supplies_no_authority_while_pending_and_a_reversal_discards_it() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    let owner = owner();
    let thief = common::Signer::new([7u8; 32]);
    append(&fx, &[declaration_entry(fresh_declaration(&fx, &thief))]);
    let (pending_url, pending_delta) = delta(&fx, &thief, "pending-a");
    let (owner_url, owner_delta) = delta(&fx, &owner, "owner-a");
    append(&fx, &[pending_delta, owner_delta]);
    sync(&fx, target.path());
    assert!(present(target.path(), &owner_url));
    assert!(!present(target.path(), &pending_url));

    let first = common::build_declaration(&owner, &fx.domain);
    let reversal = common::build_declaration_full(
        &owner,
        &fx.domain,
        2,
        Some(&common::declaration_hash(&first)),
        &[(&owner, NOT_BEFORE)],
    );
    append(&fx, &[declaration_entry(reversal)]);
    let (pending_url, pending_delta) = delta(&fx, &thief, "pending-b");
    let (owner_url, owner_delta) = delta(&fx, &owner, "owner-b");
    append(&fx, &[pending_delta, owner_delta]);
    sync(&fx, target.path());
    assert!(present(target.path(), &owner_url));
    assert!(!present(target.path(), &pending_url));
}

#[test]
fn a_fresh_identity_activates_at_the_delay_the_parameter_map_fixes() {
    let fx = common::build_fixture_with_state(
        vec![StateEntry::Parameter(ParameterEntry {
            name: "declaration_activation_epochs".into(),
            effective_at: "2026-08-09T13:00:00Z".into(),
            value: 1,
        })],
        0,
    );
    let target = tempfile::tempdir().unwrap();
    let owner = owner();
    let thief = common::Signer::new([7u8; 32]);
    let sealed = append(&fx, &[declaration_entry(fresh_declaration(&fx, &thief))]);
    let (activated_url, activated_delta) = delta(&fx, &thief, "activated-a");
    let (replaced_url, replaced_delta) = delta(&fx, &owner, "replaced-a");
    let activation = append(&fx, &[activated_delta, replaced_delta]);
    assert_eq!(
        activation,
        sealed + 1,
        "the parameter map fixes a one-Epoch delay"
    );
    sync(&fx, target.path());
    assert!(present(target.path(), &activated_url));
    assert!(!present(target.path(), &replaced_url));
    // WIST-4 §8: the domain's history restarts at the activation height, so
    // a ranking policy reads its age from there and not from the
    // Declarations the fresh identity superseded.
    assert_eq!(identity_start(target.path(), &fx.domain), Some(activation));
}

/// The height the index records as the start of a domain's identity.
fn identity_start(target: &std::path::Path, domain: &str) -> Option<u64> {
    rusqlite::Connection::open(common::synced_log_dir(target).join("index.sqlite"))
        .unwrap()
        .query_row(
            "SELECT height FROM identity_starts WHERE domain = ?1",
            [domain],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .unwrap()
        .map(|height| height.max(0) as u64)
}

#[test]
fn a_pending_declaration_tuple_resumes_into_its_activation() {
    let owner = owner();
    let thief = common::Signer::new([7u8; 32]);
    let first = common::build_declaration(&owner, "records.example");
    let pending = common::build_declaration_full(
        &thief,
        "records.example",
        1,
        Some(&common::declaration_hash(&first)),
        &[(&thief, NOT_BEFORE)],
    );
    let fx = common::build_fixture_with_state(
        vec![StateEntry::PendingDeclaration(PendingDeclarationEntry {
            domain: "records.example".into(),
            head: pending,
            sealing_height: 0,
            activation_height: 1,
        })],
        1,
    );
    let target = tempfile::tempdir().unwrap();
    let (activated_url, activated_delta) = delta(&fx, &thief, "activated-a");
    append(&fx, &[activated_delta]);
    sync(&fx, target.path());
    assert!(present(target.path(), "https://records.example/alpha"));
    assert!(
        !present(target.path(), "https://records.example/beta"),
        "the replaced key signs nothing from the activation Epoch on"
    );
    assert!(present(target.path(), &activated_url));
}
