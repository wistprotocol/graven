//! WIST-3 §3.4.
mod common;

use rusqlite::Connection;
use std::path::Path;

const EFFECTIVE_AT: &str = "2026-08-09T15:00:00Z";

fn sync(fx: &common::Fixture, dir: &Path) -> Result<graven::sync::SyncReport, graven::Error> {
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        dir,
        true,
        false,
    )
}

fn registry_rows(dir: &Path) -> Vec<(String, u64, Option<u64>)> {
    let conn =
        Connection::open(common::synced_log_dir(dir).join("index.sqlite")).expect("open the index");
    let mut stmt = conn
        .prepare("SELECT key_id, added_height, removed_height FROM aggregator_keys ORDER BY key_id")
        .expect("the store carries the key registry");
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?.max(0) as u64,
                row.get::<_, Option<i64>>(2)?
                    .map(|height| height.max(0) as u64),
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    rows
}

fn accepted_parameter(dir: &Path, parameter: &str) -> i64 {
    let conn =
        Connection::open(common::synced_log_dir(dir).join("index.sqlite")).expect("open the index");
    conn.query_row(
        "SELECT COUNT(*) FROM parameters WHERE parameter = ?1",
        [parameter],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

fn retire_the_genesis_key(fx: &common::Fixture, second: &common::Signer) {
    common::seal_the_genesis_keys_removal(fx, second);
    common::resign_snapshot_documents(fx.dir.path(), &fx.snapshot_date, "log2", second);
}

fn registered_logs(dir: &Path) -> Vec<String> {
    match std::fs::read(dir.join("logs.json")) {
        Err(_) => Vec::new(),
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["logs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["log_id"].as_str().unwrap().to_string())
            .collect(),
    }
}

/// WIST-3 §3.4 and §8 step 8.
#[test]
fn a_snapshot_signed_by_a_key_the_adopted_epoch_retired_is_rejected_and_registers_nothing() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([36u8; 32]);
    common::seal_the_genesis_keys_removal(&fx, &second);

    let target = tempfile::tempdir().unwrap();
    let error = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(
        error.contains("WIST3-E04") && error.contains("the Snapshot index"),
        "the rejection names the document and the code: {error}"
    );
    assert!(
        error.contains("log1") && error.contains("height 3"),
        "the rejection names the key and the height it was judged at: {error}"
    );
    assert!(
        registered_logs(target.path()).is_empty(),
        "a rejected Snapshot leaves the Log unregistered"
    );
    assert!(!common::synced_log_dir(target.path())
        .join("index.sqlite")
        .exists());
}

/// WIST-3 §3.4.
#[test]
fn a_snapshot_re_signed_under_the_remaining_key_cold_starts_across_the_removal() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([37u8; 32]);
    retire_the_genesis_key(&fx, &second);

    let target = tempfile::tempdir().unwrap();
    let report = sync(&fx, target.path()).unwrap();
    assert_eq!(report.head, 3);
    assert_eq!(
        registered_logs(target.path()),
        vec!["graven-test-log".to_string()],
        "an accepted Snapshot registers the Log with the state it adopts"
    );
}

#[test]
fn a_removed_genesis_key_stays_removed_across_a_reload() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([24u8; 32]);
    let target = tempfile::tempdir().unwrap();
    retire_the_genesis_key(&fx, &second);

    let report = sync(&fx, target.path()).unwrap();
    assert_eq!(report.head, 3);
    assert_eq!(
        registry_rows(target.path()),
        vec![
            ("log1".to_string(), 0, Some(3)),
            ("log2".to_string(), 2, None),
        ],
        "the store keeps the genesis key's own removal height"
    );

    let at = common::next_instant(&fx);
    fx.log_state().seal(&at, &[]);
    let error = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(error.contains("WIST3-E03"), "{error}");
    assert_eq!(
        graven::store::synced_state(&common::synced_log_dir(target.path()))
            .unwrap()
            .epoch_number,
        3,
        "the verified head stands"
    );
}

#[test]
fn a_retired_genesis_key_authenticates_no_act_after_a_reload() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([25u8; 32]);
    let target = tempfile::tempdir().unwrap();
    retire_the_genesis_key(&fx, &second);
    assert_eq!(sync(&fx, target.path()).unwrap().head, 3);

    // WIST-4 §5.1: an amendment under the retired genesis key is `WIST4-E11`.
    let at = common::next_instant(&fx);
    let acts = [
        common::parameter_act(
            "log1",
            &fx.log,
            "payload_window_days",
            200,
            "2026-08-20T00:00:00Z",
        ),
        common::parameter_act(
            "log2",
            &second,
            "record_seal_epochs",
            48,
            "2026-08-20T00:00:00Z",
        ),
    ];
    fx.log_state().seal_signed_by(&second, &at, &acts);

    assert_eq!(sync(&fx, target.path()).unwrap().head, 4);
    assert_eq!(
        accepted_parameter(target.path(), "payload_window_days"),
        0,
        "an act the retired genesis key signed changes nothing"
    );
    assert_eq!(
        accepted_parameter(target.path(), "record_seal_epochs"),
        1,
        "an act a key valid at the Epoch signed is accepted"
    );
}

/// WIST-3 §3.4: "The key set valid at N does not depend on the order in which Epoch N's key acts
/// are evaluated".
#[test]
fn an_addition_and_a_removal_in_one_epoch_leave_the_same_registry_in_either_order() {
    let mut seen_orders = std::collections::BTreeSet::new();
    for instant in [
        "2026-08-09T15:00:00Z",
        "2026-08-09T16:00:00Z",
        "2026-08-09T17:00:00Z",
        "2026-08-09T18:00:00Z",
        "2026-08-09T19:00:00Z",
        "2026-08-09T20:00:00Z",
    ] {
        let fx = common::build_fixture(true, false);
        let second = common::Signer::new([26u8; 32]);
        let third = common::Signer::new([27u8; 32]);
        let at = common::next_instant(&fx);
        common::seal_next(
            &fx,
            &at,
            &[common::key_act(
                &fx,
                "aggregator_key_add",
                "log1",
                &fx.log,
                "log2",
                Some(&second),
                EFFECTIVE_AT,
            )],
        );

        let add = common::key_act(
            &fx,
            "aggregator_key_add",
            "log1",
            &fx.log,
            "log3",
            Some(&third),
            instant,
        );
        let remove = common::key_act(
            &fx,
            "aggregator_key_remove",
            "log1",
            &fx.log,
            "log2",
            None,
            EFFECTIVE_AT,
        );
        let ordered = common::canonical_order(&[add.clone(), remove.clone()]);
        seen_orders.insert(
            ordered[0]["body"]["update"]["action"]
                .as_str()
                .unwrap()
                .to_string(),
        );

        let at = common::next_instant(&fx);
        common::seal_next(&fx, &at, &[add, remove]);
        let target = tempfile::tempdir().unwrap();
        assert_eq!(sync(&fx, target.path()).unwrap().head, 3);
        assert_eq!(
            registry_rows(target.path()),
            vec![
                ("log1".to_string(), 0, None),
                ("log2".to_string(), 2, Some(3)),
                ("log3".to_string(), 3, None),
            ],
            "canonical order {:?}",
            ordered[0]["body"]["update"]["action"]
        );
    }
    assert_eq!(
        seen_orders.len(),
        2,
        "both canonical orders of the pair were exercised, got {seen_orders:?}"
    );
}

/// WIST-3 §3.4 and WIST-4 §5.1.
#[test]
fn a_failed_key_act_is_ignored_and_leaves_its_epoch_valid() {
    let second = common::Signer::new([28u8; 32]);
    let third = common::Signer::new([29u8; 32]);
    for (name, act) in [
        (
            "a key_id the Log has admitted",
            ("aggregator_key_add", "log2", Some(&third)),
        ),
        (
            "a note key ID an admitted key derives",
            ("aggregator_key_add", "log4", Some(&second)),
        ),
        (
            "a key_id not valid at the previous height",
            ("aggregator_key_remove", "log9", None),
        ),
    ] {
        let fx = common::build_fixture(true, false);
        let at = common::next_instant(&fx);
        common::seal_next(
            &fx,
            &at,
            &[common::key_act(
                &fx,
                "aggregator_key_add",
                "log1",
                &fx.log,
                "log2",
                Some(&second),
                EFFECTIVE_AT,
            )],
        );
        let (action, key_id, public_key) = act;
        let at = common::next_instant(&fx);
        common::seal_next(
            &fx,
            &at,
            &[common::key_act(
                &fx,
                action,
                "log1",
                &fx.log,
                key_id,
                public_key,
                EFFECTIVE_AT,
            )],
        );

        let target = tempfile::tempdir().unwrap();
        let report = sync(&fx, target.path())
            .unwrap_or_else(|e| panic!("{name}: the Epoch stays valid: {e}"));
        assert_eq!(report.head, 3, "{name}");
        assert_eq!(
            registry_rows(target.path()),
            vec![("log1".to_string(), 0, None), ("log2".to_string(), 2, None),],
            "{name}: the failed act changes no registry state"
        );
    }
}

/// WIST-3 §3.4.
#[test]
fn a_key_added_in_one_epoch_authenticates_no_key_act_of_that_epoch() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([30u8; 32]);
    let third = common::Signer::new([31u8; 32]);
    let at = common::next_instant(&fx);
    common::seal_next(
        &fx,
        &at,
        &[
            common::key_act(
                &fx,
                "aggregator_key_add",
                "log1",
                &fx.log,
                "log2",
                Some(&second),
                EFFECTIVE_AT,
            ),
            common::key_act(
                &fx,
                "aggregator_key_add",
                "log2",
                &second,
                "log3",
                Some(&third),
                EFFECTIVE_AT,
            ),
        ],
    );

    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync(&fx, target.path()).unwrap().head, 2);
    assert_eq!(
        registry_rows(target.path()),
        vec![("log1".to_string(), 0, None), ("log2".to_string(), 2, None),],
        "the act the newly added key signed is WIST4-E11 and admits nothing"
    );
}

/// WIST-3 §3.4.
#[test]
fn an_epochs_other_acts_and_checkpoint_read_the_key_set_its_own_key_acts_leave() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([33u8; 32]);
    let at = common::next_instant(&fx);
    let entries = [
        common::key_act(
            &fx,
            "aggregator_key_add",
            "log1",
            &fx.log,
            "log2",
            Some(&second),
            EFFECTIVE_AT,
        ),
        common::parameter_act(
            "log2",
            &second,
            "record_seal_epochs",
            48,
            "2026-08-20T00:00:00Z",
        ),
    ];
    fx.log_state().seal_signed_by(&second, &at, &entries);

    let at = common::next_instant(&fx);
    let entries = [
        common::key_act(
            &fx,
            "aggregator_key_remove",
            "log1",
            &fx.log,
            "log1",
            None,
            EFFECTIVE_AT,
        ),
        common::parameter_act(
            "log1",
            &fx.log,
            "payload_window_days",
            200,
            "2026-08-20T00:00:00Z",
        ),
    ];
    fx.log_state().seal_signed_by(&second, &at, &entries);
    common::resign_snapshot_documents(fx.dir.path(), &fx.snapshot_date, "log2", &second);

    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync(&fx, target.path()).unwrap().head, 3);
    assert_eq!(
        registry_rows(target.path()),
        vec![
            ("log1".to_string(), 0, Some(3)),
            ("log2".to_string(), 2, None),
        ]
    );
    assert_eq!(
        accepted_parameter(target.path(), "record_seal_epochs"),
        1,
        "a key added in the Epoch signs that Epoch's other acts"
    );
    assert_eq!(
        accepted_parameter(target.path(), "payload_window_days"),
        0,
        "a key removed in the Epoch signs none of its other acts"
    );
}

/// WIST-3 §7.
#[test]
fn a_snapshot_state_that_omits_the_anchors_genesis_key_does_not_verify() {
    use wist_core::objects::{AggregatorKeyEntry, StateEntry};
    let other = common::Signer::new([34u8; 32]);
    let fx = common::build_fixture_with_state(
        vec![StateEntry::AggregatorKey(AggregatorKeyEntry {
            key_id: "log2".into(),
            public_key: other.public_b64u(),
            added_height: 0,
            removed_height: None,
            adding_act: None,
            removing_act: None,
        })],
        0,
    );
    let target = tempfile::tempdir().unwrap();
    let error = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(
        error.contains("genesis key") && error.contains("WIST3-E04"),
        "the Snapshot is refused rather than resumed without the key: {error}"
    );
}

/// WIST-3 §7.
#[test]
fn a_snapshot_resume_keeps_a_retired_keys_tuple() {
    use wist_core::objects::{AggregatorKeyEntry, StateEntry};
    let log = common::Signer::new([9u8; 32]);
    let retired = common::Signer::new([32u8; 32]);
    let fx = common::build_fixture_with_state(
        vec![
            StateEntry::AggregatorKey(AggregatorKeyEntry {
                key_id: "log1".into(),
                public_key: log.public_b64u(),
                added_height: 0,
                removed_height: None,
                adding_act: None,
                removing_act: None,
            }),
            StateEntry::AggregatorKey(AggregatorKeyEntry {
                key_id: "log2".into(),
                public_key: retired.public_b64u(),
                added_height: 0,
                removed_height: None,
                adding_act: Some(common::key_act_envelope(
                    "aggregator_key_add",
                    "log1",
                    &log,
                    "log2",
                    Some(&retired),
                    EFFECTIVE_AT,
                )),
                removing_act: None,
            }),
        ],
        0,
    );
    let at = common::next_instant(&fx);
    common::seal_next(
        &fx,
        &at,
        &[common::key_act(
            &fx,
            "aggregator_key_remove",
            "log1",
            &fx.log,
            "log2",
            None,
            EFFECTIVE_AT,
        )],
    );
    let at = common::next_instant(&fx);
    common::seal_next(
        &fx,
        &at,
        &[common::parameter_act(
            "log2",
            &retired,
            "record_seal_epochs",
            48,
            "2026-08-20T00:00:00Z",
        )],
    );

    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync(&fx, target.path()).unwrap().head, 3);
    assert_eq!(
        registry_rows(target.path()),
        vec![
            ("log1".to_string(), 0, None),
            ("log2".to_string(), 0, Some(2)),
        ],
        "the resumed registry keeps the retired key's tuple"
    );
    assert_eq!(
        accepted_parameter(target.path(), "record_seal_epochs"),
        0,
        "an act the retired key signed changes nothing"
    );
}
