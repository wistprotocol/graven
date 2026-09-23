//! WIST-3 §5 and §8.
use e2e::{
    graven_bin, grid_instant, resolve_sibling_bin, run, s, spawn_witness, start_aggregator,
    Aggregator,
};
use std::path::Path;

fn start_log(clave: &Path, tmp: &Path, name: &str) -> Aggregator {
    start_aggregator(clave, tmp.join(name), None, None)
}

fn seal(clave: &Path, log: &Aggregator, at: &str) {
    run(clave, &["seal", "--data", s(&log.data), "--at", at]);
}

fn seal_reaching_witnesses(clave: &Path, log: &Aggregator, at: &str) {
    run(
        clave,
        &["seal", "--data", s(&log.data), "--at", at, "--allow-http"],
    );
}

fn sync(graven: &Path, dir: &Path, log: &Aggregator, witnesses: &[&str]) -> (u64, u64, bool) {
    let anchor = log.data.join("anchor.json");
    let mut args: Vec<String> = vec![
        "sync".into(),
        "--anchor".into(),
        s(&anchor).into(),
        "--log".into(),
        log.base_url.clone(),
        "--dir".into(),
        s(dir).into(),
        "--allow-http".into(),
    ];
    for witness in witnesses {
        args.push("--witness".into());
        args.push((*witness).into());
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(graven, &borrowed);
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.contains("head epoch"))
        .unwrap_or_else(|| {
            panic!(
                "no sync report in {}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
        .to_string();
    let head = line
        .split("head epoch ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no head epoch in {line:?}"));
    let tree_size = line
        .split("tree size ")
        .nth(1)
        .and_then(|rest| rest.split([',', ' ']).next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no tree size in {line:?}"));
    (head, tree_size, line.contains("unwitnessed"))
}

/// WIST-3 §8.
#[test]
fn a_consumer_cold_starts_at_a_snapshot_and_continues_from_its_persisted_head() {
    let clave = resolve_sibling_bin("CLAVE_BIN", "clave");
    let graven = graven_bin();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let log = start_log(&clave, tmp.path(), "clave-data");
    let dir = tmp.path().join("graven-store");

    seal(&clave, &log, &grid_instant(0));
    let (head, tree_size, unwitnessed) = sync(&graven, &dir, &log, &[]);
    assert_eq!(head, 0, "the cold start adopts the Snapshot's Epoch");
    assert!(
        unwitnessed,
        "with an empty roster and a quorum of 0 the head is adopted unwitnessed"
    );

    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            dir.join("logs")
                .join(log.log_id.replace(':', "-"))
                .join("sync.json"),
        )
        .expect("the Consumer persisted its sync state"),
    )
    .expect("sync.json is JSON");
    assert_eq!(state["epoch_number"], head);
    assert_eq!(state["tree_size"], tree_size);
    assert_eq!(state["unwitnessed"], true);

    seal(&clave, &log, &grid_instant(1));
    seal(&clave, &log, &grid_instant(2));
    let (head, _, _) = sync(&graven, &dir, &log, &[]);
    assert_eq!(head, 2, "a later run continues from the persisted head");
}

/// WIST-3 §5: a source serving an older head has shown only that it is behind.
#[test]
fn a_source_serving_an_old_head_does_not_regress_the_consumer() {
    let clave = resolve_sibling_bin("CLAVE_BIN", "clave");
    let graven = graven_bin();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let log = start_log(&clave, tmp.path(), "clave-data");
    let dir = tmp.path().join("graven-store");

    seal(&clave, &log, &grid_instant(0));
    sync(&graven, &dir, &log, &[]);
    seal(&clave, &log, &grid_instant(1));
    let (head, _, _) = sync(&graven, &dir, &log, &[]);
    assert_eq!(head, 1);

    let current = std::fs::read(log.data.join("checkpoint")).expect("read the head Checkpoint");
    let stale = std::fs::read(log.data.join("log/checkpoints/000000000")).expect("read Epoch 0");
    std::fs::write(log.data.join("checkpoint"), &stale).expect("serve the old head");
    let (head, _, _) = sync(&graven, &dir, &log, &[]);
    assert_eq!(head, 1, "the stale head adopts nothing and is no error");

    std::fs::write(log.data.join("checkpoint"), &current).expect("restore the head");
    seal(&clave, &log, &grid_instant(2));
    let (head, _, _) = sync(&graven, &dir, &log, &[]);
    assert_eq!(head, 2);
}

/// WIST-3 §5 and WIST-4 §5.
#[test]
fn a_checkpoint_is_adopted_only_once_a_trusted_witness_has_cosigned_it() {
    let clave = resolve_sibling_bin("CLAVE_BIN", "clave");
    let graven = graven_bin();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let log = start_log(&clave, tmp.path(), "clave-data");
    let dir = tmp.path().join("graven-store");
    let witness = spawn_witness("witness-a.localhost", [31u8; 32]);

    seal(&clave, &log, &grid_instant(0));
    // WIST-4 §5: an amendment takes effect only after its grace period.
    let effective_at = grid_instant(24 * 7 + 2);
    run(
        &clave,
        &[
            "param-change",
            "--data",
            s(&log.data),
            "--parameter",
            "checkpoint_witness_quorum",
            "--value",
            "1",
            "--effective-at",
            &effective_at,
        ],
    );
    seal(&clave, &log, &grid_instant(1));

    let (head, _, unwitnessed) = sync(&graven, &dir, &log, &[&witness.verifier_key]);
    assert_eq!(head, 1);
    assert!(
        unwitnessed,
        "no Witness has cosigned yet and the quorum is 0"
    );

    seal(&clave, &log, &effective_at);
    let (head, _, _) = sync(&graven, &dir, &log, &[&witness.verifier_key]);
    assert_eq!(
        head, 1,
        "a Checkpoint short of the quorum leaves the verified head where it is"
    );

    run(
        &clave,
        &[
            "witness",
            "--data",
            s(&log.data),
            "--add",
            &witness.verifier_key,
            "--url",
            &witness.base_url,
        ],
    );
    seal_reaching_witnesses(&clave, &log, &grid_instant(24 * 7 + 3));
    let cosigned = std::fs::read_to_string(log.data.join("checkpoint")).expect("read the head");
    assert!(
        cosigned.contains(&witness.name),
        "the Aggregator republished its head with the Cosignature it obtained: {cosigned}"
    );

    let (head, _, unwitnessed) = sync(&graven, &dir, &log, &[&witness.verifier_key]);
    assert_eq!(head, 3, "the cosigned Checkpoint carries the quorum");
    assert!(
        !unwitnessed,
        "a Witness in the Consumer's roster cosigned the adopted Checkpoint"
    );
}
