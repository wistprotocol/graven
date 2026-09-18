mod common;

use graven::store::{load_subscriptions, save_subscriptions, MultiStore, Store};
use serde_json::{json, Value};
use wist_core::envelope::sign_envelope;
use wist_core::objects::{DisputeEntry, LabelEntry, StateEntry};

const SUBJECT: &str = "https://other.example/x";

fn append_block(fx: &common::Fixture, entries: &[Value]) -> u64 {
    let sealed_at = common::next_instant(fx);
    common::seal_next(fx, &sealed_at, entries)
}

fn label_entry(signer: &common::Signer, inner: Value) -> (String, Value) {
    let id = wist_core::label::label_id(&inner).unwrap();
    let body = sign_envelope(&inner, "label", &signer.kid(), &signer.sk).unwrap();
    (id, json!({"type": "label", "body": body}))
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

#[test]
fn walked_labels_and_disputes_reach_the_index() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path());
    let labeler = common::Signer::new([1u8; 32]);
    let (label_id, entry) = label_entry(
        &labeler,
        json!({"wist_version": "1.0.0", "labeler": "records.example", "subject": SUBJECT, "name": "wist:spam", "value": 250000, "asserted_at": "2026-08-09T12:30:00Z", "expires_at": "2027-01-01T00:00:00Z"}),
    );
    let (_, self_label) = label_entry(
        &labeler,
        json!({"wist_version": "1.0.0", "labeler": "records.example", "subject": "https://records.example/alpha", "name": "wist:spam", "asserted_at": "2026-08-09T12:30:00Z"}),
    );
    let height = append_block(&fx, &[entry, self_label]);
    sync(&fx, target.path());
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    let labels = store.labels_for(SUBJECT, None).unwrap();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].labeler, "records.example");
    assert_eq!(labels[0].value, Some(250_000));
    assert_eq!(labels[0].height, height);
    assert_eq!(
        store.label_id_of(&labels[0]).unwrap().as_deref(),
        Some(label_id.as_str())
    );
    assert!(store
        .labels_for("https://records.example/alpha", None)
        .unwrap()
        .is_empty());
    assert!(store
        .labels_for(SUBJECT, Some("2027-01-01T00:00:00Z"))
        .unwrap()
        .is_empty());
    let labelers = store.labelers().unwrap();
    assert_eq!(labelers.len(), 1);
    assert_eq!(
        (
            labelers[0].label_count,
            labelers[0].retraction_count,
            labelers[0].distinct_subjects
        ),
        (1, 0, 1)
    );

    let disputant = common::Signer::new([4u8; 32]);
    let declaration = common::build_declaration(&disputant, "other.example");
    let dispute_inner = json!({"wist_version": "1.0.0", "disputant": "other.example", "label": label_id, "log": "log.example", "height": height, "reason": "https://other.example/why", "asserted_at": "2026-08-09T13:00:00Z"});
    let dispute_id = wist_core::label::dispute_id(&dispute_inner).unwrap();
    let dispute = json!({"type": "dispute", "body": sign_envelope(&dispute_inner, "dispute", &disputant.kid(), &disputant.sk).unwrap()});
    let unknown = json!({"wist_version": "1.0.0", "disputant": "other.example", "label": format!("sha256:{}", "f".repeat(64)), "log": "log.example", "height": height, "asserted_at": "2026-08-09T13:00:00Z"});
    let unknown_dispute = json!({"type": "dispute", "body": sign_envelope(&unknown, "dispute", &disputant.kid(), &disputant.sk).unwrap()});
    append_block(
        &fx,
        &[
            json!({"type": "publisher_declaration", "body": declaration}),
            dispute,
            unknown_dispute,
        ],
    );
    sync(&fx, target.path());
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    let disputes = store.disputes_for(&label_id).unwrap();
    assert_eq!(disputes.len(), 1);
    assert_eq!(disputes[0].disputant, "other.example");
    assert_eq!(
        disputes[0].reason.as_deref(),
        Some("https://other.example/why")
    );
    let multi = MultiStore::open_read_only(target.path()).unwrap();
    assert!(multi.labels(SUBJECT, false).unwrap().is_empty());
    let views = multi.labels(SUBJECT, true).unwrap();
    assert_eq!(views.len(), 1);
    assert!(!views[0].subscribed);
    assert_eq!(views[0].treatment, "inform");
    assert_eq!(views[0].disputes.len(), 1);
    assert_eq!(views[0].label_id.as_deref(), Some(label_id.as_str()));
    let _ = dispute_id;
    let mut subscriptions = load_subscriptions(target.path()).unwrap();
    subscriptions.insert("records.example".into());
    save_subscriptions(target.path(), &subscriptions).unwrap();
    let multi = MultiStore::open_read_only(target.path()).unwrap();
    let views = multi.labels(SUBJECT, false).unwrap();
    assert_eq!(views.len(), 1);
    assert!(views[0].subscribed);
    assert!(multi.labelers().unwrap()[0].subscribed);

    let (_, retraction) = label_entry(
        &labeler,
        json!({"wist_version": "1.0.0", "labeler": "records.example", "subject": SUBJECT, "name": "wist:spam", "asserted_at": "2026-08-09T14:00:00Z", "retracted": true}),
    );
    let (_, stale) = label_entry(
        &labeler,
        json!({"wist_version": "1.0.0", "labeler": "records.example", "subject": SUBJECT, "name": "wist:spam", "asserted_at": "2026-08-09T11:00:00Z"}),
    );
    append_block(&fx, &[retraction, stale]);
    sync(&fx, target.path());
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(store.labels_for(SUBJECT, None).unwrap().is_empty());
    let labelers = store.labelers().unwrap();
    assert_eq!(
        (labelers[0].label_count, labelers[0].retraction_count),
        (3, 1)
    );
}

#[test]
fn snapshot_label_and_dispute_tuples_are_adopted() {
    let adopted_id = format!("sha256:{}", "b".repeat(64));
    let label = StateEntry::Label(LabelEntry {
        labeler: "labels.sample.net".into(),
        subject: SUBJECT.into(),
        name: "wist:copied".into(),
        value: None,
        asserted_at: "2026-08-01T00:00:00Z".into(),
        expires_at: None,
        delta: None,
        label_id: adopted_id.clone(),
        sealing_height: 0,
    });
    let dispute = StateEntry::Dispute(DisputeEntry {
        label_id: format!("sha256:{}", "a".repeat(64)),
        disputant: "other.example".into(),
        reason: None,
        asserted_at: "2026-08-01T01:00:00Z".into(),
        sealing_height: 0,
    });
    let fx = common::build_fixture_with_state(vec![label, dispute], 0);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path());
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    let labels = store.labels_for(SUBJECT, None).unwrap();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].labeler, "labels.sample.net");
    assert_eq!(
        store.label_id_of(&labels[0]).unwrap().as_deref(),
        Some(adopted_id.as_str())
    );
    let disputes = store
        .disputes_for(&format!("sha256:{}", "a".repeat(64)))
        .unwrap();
    assert_eq!(disputes.len(), 1);
    // WIST-3 §7: adopting the Label tuple records the figures a resumed
    // index can honestly hold — none of them a real count — but the
    // dispute tuple's disputant gets no such row (only adopt_label_tuple
    // seeds one).
    let labelers = store.labelers().unwrap();
    assert_eq!(labelers.len(), 1);
    assert_eq!(labelers[0].labeler, "labels.sample.net");
    assert_eq!(
        (
            labelers[0].label_count,
            labelers[0].retraction_count,
            labelers[0].first_seen_height,
            labelers[0].last_sealed_height,
        ),
        (0, 0, 0, 0)
    );
    assert!(labelers[0].counts_from_resume);
}

/// The served tool list and a call reach the label tools through the
/// combined router, not only the tools of the first router.
#[test]
fn served_tool_list_includes_the_label_tools() {
    use std::io::{BufRead, BufReader, Write};
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path());
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_graven"))
        .args(["serve", "--dir", target.path().to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut send = |v: Value| {
        stdin.write_all(format!("{v}\n").as_bytes()).unwrap();
        stdin.flush().unwrap();
    };
    send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}}}),
    );
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}));
    line.clear();
    reader.read_line(&mut line).unwrap();
    let doc: Value = serde_json::from_str(line.trim()).unwrap();
    let names: Vec<&str> = doc["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    send(
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "get_labels", "arguments": {"subject": "https://x.example/"}}}),
    );
    line.clear();
    reader.read_line(&mut line).unwrap();
    let call: Value = serde_json::from_str(line.trim()).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        names.contains(&"get_labels") && names.contains(&"list_labelers"),
        "{names:?}"
    );
    assert!(call.get("error").is_none(), "{call}");
    assert_eq!(call["result"]["structuredContent"], json!([]), "{call}");
}
