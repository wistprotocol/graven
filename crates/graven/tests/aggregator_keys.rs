//! WIST-3 §3.4 at the Consumer: which key speaks for an Epoch, what a
//! key act is authenticated under, which key acts fail, and that a
//! removed key — the genesis key included — stays removed across the
//! reload every later sync begins with.
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

/// Every key the store holds, with the heights that bound its validity.
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

/// Seals the Epochs that admit a second Aggregator key and retire the
/// genesis key, leaving `second` the only key valid at the head.
fn retire_the_genesis_key(fx: &common::Fixture, second: &common::Signer) {
    let at = common::next_instant(fx);
    common::seal_next(
        fx,
        &at,
        &[common::key_act(
            fx,
            "aggregator_key_add",
            "log1",
            &fx.log,
            "log2",
            Some(second),
            EFFECTIVE_AT,
        )],
    );
    // The removal is authenticated at the height below its Epoch, where
    // the genesis key is still valid; Checkpoint N is signed by the key
    // valid at N, which the removal leaves as `log2` alone.
    let at = common::next_instant(fx);
    let removal = common::key_act(
        fx,
        "aggregator_key_remove",
        "log1",
        &fx.log,
        "log1",
        None,
        EFFECTIVE_AT,
    );
    fx.log_state().seal_signed_by(second, &at, &[removal]);
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

    // The next Epoch's Checkpoint is signed by the retired genesis key
    // alone. A reload that restored it would adopt this Epoch.
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

    // Epoch 4 carries two amendments: one under the retired genesis key,
    // which WIST-4 §5.1 ignores as `WIST4-E11`, and one under the key
    // valid at the Epoch, which is accepted.
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

/// WIST-3 §3.4: "The key set valid at N does not depend on the order in
/// which Epoch N's key acts are evaluated", so one Epoch adding a key and
/// retiring another leaves the same registry whichever Entry order the
/// leaf hashes put them in.
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

/// WIST-3 §3.4 and WIST-4 §5.1: a key act that fails is ignored as
/// `WIST4-E04` — it changes no key registry state and the containing
/// Epoch stays valid.
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

/// WIST-3 §3.4: a key act sealed in Epoch N is authenticated under the
/// keys valid at N−1, so a key added in Epoch N signs no key act of that
/// Epoch.
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

/// WIST-3 §3.4: a key added in Epoch N signs no key act of that Epoch,
/// but may sign its other acts and Checkpoint N; a key removed in Epoch N
/// may sign that Epoch's key acts and signs neither its other acts nor
/// Checkpoint N.
#[test]
fn an_epochs_other_acts_and_checkpoint_read_the_key_set_its_own_key_acts_leave() {
    let fx = common::build_fixture(true, false);
    let second = common::Signer::new([33u8; 32]);
    let at = common::next_instant(&fx);
    // Epoch 2 admits log2 and, under that same key, amends a parameter;
    // its Checkpoint is signed by log2 too.
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

    // Epoch 3 retires the genesis key under its own signature and carries
    // an amendment under it, which the key set valid at Epoch 3 no longer
    // admits.
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

/// WIST-3 §7: a removed key's tuple outlives its key and the genesis key
/// is one like any other once removed, so a state file carrying tuples
/// but not the Anchor's genesis key's omits one §7 keeps and does not
/// verify.
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
        })],
        0,
    );
    let target = tempfile::tempdir().unwrap();
    let error = sync(&fx, target.path()).unwrap_err().to_string();
    assert!(
        error.contains("genesis key"),
        "the Snapshot is refused rather than resumed without the key: {error}"
    );
}

/// WIST-3 §7: a Snapshot's `aggregator_key` tuples carry removed keys, so
/// a resuming Consumer evaluates key acts and lower Checkpoints against
/// them exactly as a replaying one does.
#[test]
fn a_snapshot_resume_keeps_a_retired_keys_tuple() {
    use wist_core::objects::{AggregatorKeyEntry, StateEntry};
    let retired = common::Signer::new([32u8; 32]);
    let fx = common::build_fixture_with_state(
        vec![
            StateEntry::AggregatorKey(AggregatorKeyEntry {
                key_id: "log1".into(),
                public_key: common::Signer::new([9u8; 32]).public_b64u(),
                added_height: 0,
                removed_height: None,
            }),
            StateEntry::AggregatorKey(AggregatorKeyEntry {
                key_id: "retired".into(),
                public_key: retired.public_b64u(),
                added_height: 0,
                removed_height: Some(0),
            }),
        ],
        0,
    );
    let at = common::next_instant(&fx);
    common::seal_next(
        &fx,
        &at,
        &[common::parameter_act(
            "retired",
            &retired,
            "record_seal_epochs",
            48,
            "2026-08-20T00:00:00Z",
        )],
    );

    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync(&fx, target.path()).unwrap().head, 2);
    assert_eq!(
        registry_rows(target.path()),
        vec![
            ("log1".to_string(), 0, None),
            ("retired".to_string(), 0, Some(0)),
        ],
        "the resumed registry keeps the retired key's tuple"
    );
    assert_eq!(
        accepted_parameter(target.path(), "record_seal_epochs"),
        0,
        "an act the retired key signed changes nothing"
    );
}
