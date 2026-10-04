mod common;

use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::Path;
use wist_core::envelope::sign_envelope;

const RECORDS: &str = "records.example";

fn sync(fx: &common::Fixture, target: &Path, witnesses: &[String]) -> graven::sync::SyncReport {
    let report = graven::sync::follow(
        &graven::sync::Follow {
            anchor: fx.anchor_path().to_str().unwrap(),
            log_base: &fx.base_url,
            mirrors: &[],
            witnesses,
            tier1: false,
            allow_http: true,
        },
        target,
    )
    .unwrap();
    common::assert_records_materialized(&common::synced_log_dir(target));
    report
}

fn label_on(subject: &str, asserted_at: &str) -> Value {
    let labeler = common::Signer::new([2u8; 32]);
    let inner = json!({
        "wist_version": "1.0.0",
        "labeler": common::BETA_DOMAIN,
        "subject": subject,
        "name": "wist:spam",
        "asserted_at": asserted_at,
    });
    let body = sign_envelope(&inner, "label", &labeler.kid(), &labeler.sk).unwrap();
    json!({"type": "label", "body": body})
}

fn dispute_of(label: &Value, height: u64, asserted_at: &str) -> Value {
    let owner = common::Signer::new([1u8; 32]);
    let inner = json!({
        "wist_version": "1.0.0",
        "disputant": RECORDS,
        "label": wist_core::label::label_id(&label["body"]["label"]).unwrap(),
        "log": "graven-test-log",
        "height": height,
        "asserted_at": asserted_at,
    });
    let body = sign_envelope(&inner, "dispute", &owner.kid(), &owner.sk).unwrap();
    json!({"type": "dispute", "body": body})
}

fn withdrawal_of(fx: &common::Fixture, item: &Value) -> Value {
    let update = json!({
        "wist_version": "1.0.0",
        "action": "payload_withdrawal",
        "subject": RECORDS,
        "details": {
            "delta_id": wist_core::item::item_id(item).unwrap(),
            "legal_basis": "court order",
            "jurisdiction": "EU",
        },
        "effective_at": "2026-08-09T15:00:00Z",
    });
    let body = sign_envelope(&update, "update", "log1", &fx.log.sk).unwrap();
    json!({"type": "registry_update", "body": body})
}

fn rows(log_dir: &Path, query: &str) -> Vec<Vec<String>> {
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    let mut stmt = match conn.prepare(query) {
        Ok(stmt) => stmt,
        Err(error) if error.to_string().contains("no such table") => return Vec::new(),
        Err(error) => panic!("{query}: {error}"),
    };
    let width = stmt.column_count();
    stmt.query_map([], |row| {
        (0..width)
            .map(|index| {
                Ok(match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => "null".to_owned(),
                    rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                    rusqlite::types::ValueRef::Text(text) => {
                        String::from_utf8(text.to_vec()).unwrap()
                    }
                    other => format!("{other:?}"),
                })
            })
            .collect()
    })
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

fn held_state(target: &Path) -> Vec<(String, Vec<Vec<String>>)> {
    let log_dir = common::synced_log_dir(target);
    [
        "SELECT tuple FROM state_tuples ORDER BY seq",
        "SELECT url, publisher, item_id, attested_at, collection, generated_at FROM records ORDER BY url",
        "SELECT state FROM declaration_state",
        "SELECT label_id, labeler, subject, name, height, entry_index FROM labels ORDER BY label_id",
        "SELECT dispute_id, label_id, disputant, height FROM disputes ORDER BY dispute_id",
        "SELECT item_id, publisher, height FROM withdrawals ORDER BY item_id",
        "SELECT parameter, value, epoch_number FROM parameters ORDER BY parameter, epoch_number",
        "SELECT labeler, label_count, first_seen_height, last_sealed_height FROM labelers ORDER BY labeler",
        "SELECT item_id, publisher, kind, height FROM sealed_items ORDER BY item_id, publisher, kind",
    ]
    .into_iter()
    .map(|query| (query.to_owned(), rows(&log_dir, query)))
    .collect()
}

#[test]
fn a_store_resumed_at_every_epoch_holds_what_one_uninterrupted_run_holds() {
    let fx = common::build_fixture_without_records();
    let publisher = common::Signer::new([1u8; 32]);
    let stepwise = tempfile::tempdir().unwrap();
    sync(&fx, stepwise.path(), &[]);

    let alpha = common::page_item(RECORDS, "https://records.example/a", "2026-08-09T12:00:00Z");
    let beta = common::page_item(RECORDS, "https://records.example/b", "2026-08-09T12:00:00Z");
    let first = common::publish(
        &publisher,
        RECORDS,
        "default",
        "2026-08-09T14:00:00Z",
        &[alpha.clone(), beta.clone()],
    );
    let mut entries = vec![first.catalog.clone()];
    entries.extend(first.items.iter().cloned());
    common::seal_next(&fx, "2026-08-09T14:00:00Z", &entries);
    sync(&fx, stepwise.path(), &[]);

    let label = label_on("https://records.example/a", "2026-08-09T15:00:00Z");
    let raise = common::parameter_act(
        "log1",
        &fx.log,
        "catalog_refresh_seconds",
        86_400,
        "2026-08-20T00:00:00Z",
    );
    let label_height = common::seal_next(&fx, "2026-08-09T15:00:00Z", &[label.clone(), raise]);
    sync(&fx, stepwise.path(), &[]);

    let removed =
        common::removed_item(RECORDS, "https://records.example/b", "2026-08-09T15:30:00Z");
    let second = common::publish(
        &publisher,
        RECORDS,
        "default",
        "2026-08-09T16:00:00Z",
        &[alpha.clone(), removed],
    );
    let removal = second
        .items
        .iter()
        .find(|entry| entry["body"]["item"]["url"] == "https://records.example/b")
        .unwrap()
        .clone();
    common::seal_next(
        &fx,
        "2026-08-09T16:00:00Z",
        &[
            second.catalog.clone(),
            removal,
            withdrawal_of(&fx, &alpha),
            dispute_of(&label, label_height, "2026-08-09T16:00:00Z"),
        ],
    );
    sync(&fx, stepwise.path(), &[]);

    let once = tempfile::tempdir().unwrap();
    assert_eq!(
        sync(&fx, once.path(), &[]).head,
        sync(&fx, stepwise.path(), &[]).head
    );
    let held = held_state(stepwise.path());
    assert_eq!(held, held_state(once.path()));

    let tuples = common::state_tuples(&common::synced_log_dir(stepwise.path()));
    let kinds: Vec<&str> = tuples.iter().map(|t| t[0].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        [
            "registry_update",
            "registry_update",
            "collection",
            "record",
            "removal",
            "withdrawal"
        ]
    );
    assert_eq!(held[3].1.len(), 1, "the Label");
    assert_eq!(held[4].1.len(), 1, "the dispute of the Label");
}

#[test]
fn entries_above_the_adopted_checkpoint_are_not_applied() {
    let fx = common::build_fixture_without_records();
    let witness = common::Witness::new("witness-a.example", [77u8; 32]);
    let roster = vec![witness.verifier_key()];
    let publisher = common::Signer::new([1u8; 32]);
    let target = tempfile::tempdir().unwrap();

    let raise = common::parameter_act(
        "log1",
        &fx.log,
        "checkpoint_witness_quorum",
        1,
        "2026-08-16T14:00:00Z",
    );
    common::seal_next(&fx, "2026-08-09T14:00:00Z", &[raise]);
    assert_eq!(sync(&fx, target.path(), &roster).head, 2);

    let item = common::page_item(RECORDS, "https://records.example/a", "2026-08-16T13:00:00Z");
    let published = common::publish(
        &publisher,
        RECORDS,
        "default",
        "2026-08-16T14:00:00Z",
        std::slice::from_ref(&item),
    );
    let witnessed = common::seal_next(
        &fx,
        "2026-08-16T14:00:00Z",
        std::slice::from_ref(&published.catalog),
    );
    fx.log_state().cosign_head(&[&witness], 1_775_000_000);
    let label = label_on("https://records.example/a", "2026-08-16T15:00:00Z");
    let above = common::seal_next(
        &fx,
        "2026-08-16T15:00:00Z",
        &[published.items[0].clone(), label],
    );

    assert_eq!(
        sync(&fx, target.path(), &roster).head,
        witnessed,
        "the newest Checkpoint carrying the quorum"
    );
    let log_dir = common::synced_log_dir(target.path());
    let kinds = |log_dir: &Path| -> Vec<String> {
        common::state_tuples(log_dir)
            .iter()
            .map(|t| t[0].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(kinds(&log_dir), ["registry_update", "collection"]);
    assert!(rows(&log_dir, "SELECT label_id FROM labels").is_empty());

    fx.log_state().cosign_head(&[&witness], 1_775_000_000);
    assert_eq!(sync(&fx, target.path(), &roster).head, above);
    assert_eq!(kinds(&log_dir), ["registry_update", "collection", "record"]);
    assert_eq!(rows(&log_dir, "SELECT label_id FROM labels").len(), 1);
}

/// WIST-4 §5.1: the Snapshot's record tuple shows its Item sealed by its Publisher after a walked
/// Entry replaces the tuple, so an act of another Publisher naming it fails the contract in a later
/// run as in one uninterrupted run.
#[test]
fn a_withdrawal_naming_a_replaced_snapshot_item_of_another_publisher_fails_in_every_run_split() {
    let fx = common::build_fixture(false);
    let publisher = common::Signer::new([1u8; 32]);
    let stepwise = tempfile::tempdir().unwrap();
    sync(&fx, stepwise.path(), &[]);

    let alpha = "https://records.example/alpha";
    let snapshot_item = common::page_item(RECORDS, alpha, common::OBSERVED);
    let replacing = common::page_item(RECORDS, alpha, "2026-08-09T13:30:00Z");
    common::seal_catalog(
        &fx,
        &publisher,
        RECORDS,
        std::slice::from_ref(&replacing),
        &[],
    );
    sync(&fx, stepwise.path(), &[]);
    assert!(
        !common::state_tuples(&common::synced_log_dir(stepwise.path()))
            .iter()
            .any(|tuple| tuple[0] == "record"
                && tuple[3] == serde_json::to_value(&snapshot_item).unwrap())
    );

    let mut act = common::withdrawal_entry(&fx.log, "log1", &snapshot_item, "2026-08-09T15:00:00Z");
    let mut update = act["body"]["update"].clone();
    update["subject"] = json!(common::BETA_DOMAIN);
    act["body"] = sign_envelope(&update, "update", "log1", &fx.log.sk).unwrap();
    let at = common::next_instant(&fx);
    common::seal_next(&fx, &at, &[act]);
    sync(&fx, stepwise.path(), &[]);

    let once = tempfile::tempdir().unwrap();
    sync(&fx, once.path(), &[]);
    let withdrawals = |target: &Path| -> Vec<Value> {
        common::state_tuples(&common::synced_log_dir(target))
            .into_iter()
            .filter(|tuple| tuple[0] == "withdrawal")
            .collect()
    };
    assert!(withdrawals(once.path()).is_empty());
    assert!(withdrawals(stepwise.path()).is_empty());
    assert_eq!(held_state(stepwise.path()), held_state(once.path()));
}

/// WIST-4 §5.1: an Item found nowhere stays found nowhere for a later act of another Publisher,
/// whether the walk resumes between the two acts or not.
#[test]
fn two_publishers_withdrawing_an_item_found_nowhere_get_the_same_verdicts_in_every_run_split() {
    let fx = common::build_fixture(false);
    let stepwise = tempfile::tempdir().unwrap();
    sync(&fx, stepwise.path(), &[]);
    let never = common::page_item(RECORDS, "https://records.example/never", common::OBSERVED);
    let first = common::withdrawal_entry(&fx.log, "log1", &never, "2026-08-09T15:00:00Z");
    let at = common::next_instant(&fx);
    common::seal_next(&fx, &at, std::slice::from_ref(&first));
    sync(&fx, stepwise.path(), &[]);

    let mut update = first["body"]["update"].clone();
    update["subject"] = json!(common::BETA_DOMAIN);
    let second = json!({
        "type": "registry_update",
        "body": sign_envelope(&update, "update", "log1", &fx.log.sk).unwrap(),
    });
    let at = common::next_instant(&fx);
    common::seal_next(&fx, &at, &[second]);
    sync(&fx, stepwise.path(), &[]);

    let once = tempfile::tempdir().unwrap();
    sync(&fx, once.path(), &[]);
    let accepted = |target: &Path| -> usize {
        common::state_tuples(&common::synced_log_dir(target))
            .iter()
            .filter(|tuple| tuple[0] == "registry_update")
            .count()
    };
    assert_eq!(accepted(once.path()), 2, "both acts find the Item nowhere");
    assert_eq!(accepted(stepwise.path()), 2);
    assert_eq!(held_state(stepwise.path()), held_state(once.path()));
}
