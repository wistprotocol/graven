mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use graven::fetch::Client;
use graven::sync::checkpoints;
use graven::sync::source::Sources;
use graven::sync::tree;
use rusqlite::Connection;
use serde_json::Value;
use std::path::{Path, PathBuf};
use wist_core::checkpoint::{
    witness_key_id, Adoption, AggregatorKey, Checkpoint, Progression, WitnessKey, WITNESS_KEY_TYPE,
};
use wist_core::crypto::{hex_encode, PublicKey};

fn spec_dir() -> PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
}

fn read_json(rel: &str) -> Value {
    let path = spec_dir().join(rel);
    serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn vectors() -> Value {
    read_json("vectors/wist3/checkpoints.json")
}

/// The Log the spec's Checkpoint vectors are signed by, as the key
/// registry a Consumer replaying it holds.
fn example_registry() -> (String, wist_core::aggregator_keys::Registry) {
    let anchor = read_json("examples/log-anchor.json");
    let anchor = &anchor["anchor"];
    let log_id = anchor["log_id"].as_str().unwrap().to_string();
    let genesis: wist_core::objects::GenesisKey =
        serde_json::from_value(anchor["genesis_key"].clone()).unwrap();
    let registry = wist_core::aggregator_keys::Registry::from_genesis(&log_id, &genesis).unwrap();
    (log_id, registry)
}

/// The Log the spec's Checkpoint vectors are signed by.
fn example_log() -> (String, AggregatorKey) {
    let anchor = read_json("examples/log-anchor.json");
    let anchor = &anchor["anchor"];
    (
        anchor["log_id"].as_str().unwrap().to_string(),
        AggregatorKey {
            key_id: anchor["genesis_key"]["key_id"]
                .as_str()
                .unwrap()
                .to_string(),
            public_key: PublicKey::from_b64u(anchor["genesis_key"]["public_key"].as_str().unwrap())
                .unwrap(),
        },
    )
}

/// The roster the vectors name, in the verifier-key form a Consumer is
/// configured with, so the roster parser is exercised beside the quorum.
fn roster(vector: &Value) -> Vec<WitnessKey> {
    let encoded: Vec<String> = vector["witness_roster"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, key)| {
            let public_key = PublicKey::from_b64u(key.as_str().unwrap()).unwrap();
            let mut raw = vec![WITNESS_KEY_TYPE];
            raw.extend_from_slice(&public_key.to_bytes());
            format!(
                "{name}+{}+{}",
                hex_encode(&witness_key_id(name, &public_key)),
                STANDARD.encode(&raw)
            )
        })
        .collect();
    graven::sync::parse_roster(&encoded).unwrap()
}

fn in_memory() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(graven::sync::CREATE_CHECKPOINTS)
        .unwrap();
    conn
}

#[test]
fn the_rollback_vector_keeps_the_head_and_preserves_an_equivocating_pair() {
    let vector = vectors();
    let (log_id, registry) = example_registry();
    for case in vector["rollback_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let log_dir = tempfile::tempdir().unwrap();
        let conn = in_memory();
        if let Some(note) = case["verified_checkpoint"].as_str() {
            checkpoints::save_checkpoint(&conn, &Checkpoint::parse(note).unwrap(), Some(true))
                .unwrap();
        }
        let offered = Checkpoint::parse(case["offered_checkpoint"].as_str().unwrap()).unwrap();
        let head = case["verified_head_epoch_number"].as_u64().unwrap();
        let outcome =
            checkpoints::progression(log_dir.path(), &conn, &offered, head, &log_id, &registry);
        match case["expected"].as_str().unwrap() {
            "not_adopted" => {
                assert_eq!(
                    outcome.map_err(|e| e.to_string()),
                    Ok(Progression::NotAdopted),
                    "{name}"
                );
                assert!(
                    !log_dir.path().join("evidence").exists(),
                    "{name}: a stale source leaves no evidence bundle"
                );
            }
            "WIST3-E02" => {
                let error = outcome.unwrap_err().to_string();
                assert!(error.contains("WIST3-E02"), "{name}: {error}");
                let bundle = log_dir
                    .path()
                    .join("evidence")
                    .join(format!("equivocation-epoch-{:09}", offered.epoch_number()));
                let retained = std::fs::read_to_string(bundle.join("retained.checkpoint")).unwrap();
                let kept = std::fs::read_to_string(bundle.join("offered.checkpoint")).unwrap();
                assert_eq!(
                    retained,
                    case["verified_checkpoint"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(kept, case["offered_checkpoint"].as_str().unwrap(), "{name}");
            }
            other => panic!("{name}: unknown expectation {other}"),
        }
    }
}

#[test]
fn the_quorum_vector_decides_adoption_and_the_unwitnessed_record() {
    let vector = vectors();
    let (log_id, key) = example_log();
    let roster = roster(&vector);
    for case in vector["quorum_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let checkpoint = Checkpoint::parse(case["checkpoint"].as_str().unwrap()).unwrap();
        let quorum = case["quorum"].as_u64().unwrap();
        let outcome = checkpoints::decide(
            &checkpoint,
            &log_id,
            std::slice::from_ref(&key),
            &roster,
            quorum,
        );
        match case["expected"].as_str().unwrap() {
            "valid" => {
                let unwitnessed = case["unwitnessed"].as_bool().unwrap();
                assert_eq!(
                    outcome.map_err(|e| e.to_string()),
                    Ok(Adoption::Adopted { unwitnessed }),
                    "{name}"
                );
            }
            "not_adopted" => assert_eq!(
                outcome.map_err(|e| e.to_string()),
                Ok(Adoption::NotAdopted),
                "{name}"
            ),
            "WIST3-E03" => {
                let error = outcome.unwrap_err().to_string();
                assert!(error.contains("WIST3-E03"), "{name}: {error}");
            }
            other => panic!("{name}: unknown expectation {other}"),
        }
    }
}

#[test]
fn the_note_form_vector_rejects_every_octet_level_departure() {
    let vector = vectors();
    let (log_id, key) = example_log();
    let roster = roster(&vector);
    for case in vector["note_form_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let outcome = Checkpoint::parse(case["checkpoint"].as_str().unwrap())
            .map_err(graven::Error::from)
            .and_then(|checkpoint| {
                checkpoints::decide(&checkpoint, &log_id, std::slice::from_ref(&key), &roster, 0)
            });
        match case["expected"].as_str().unwrap() {
            "valid" => assert!(outcome.is_ok(), "{name}: {outcome:?}"),
            "WIST3-E03" => {
                let error = outcome.err().map(|e| e.to_string()).unwrap_or_default();
                assert!(error.contains("WIST3-E03"), "{name}: {error}");
            }
            other => panic!("{name}: unknown expectation {other}"),
        }
    }
}

#[test]
fn the_archive_vector_rejects_a_checkpoint_filed_under_another_epochs_path() {
    let vector = vectors();
    let client = Client::new(true);
    for case in vector["archive_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = case["path"].as_str().unwrap();
        let file = dir.path().join(path.trim_start_matches('/'));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, case["checkpoint"].as_str().unwrap()).unwrap();
        let (addr, _) = common::serve_recording(dir.path().to_path_buf());
        let sources = Sources::new(
            &client,
            vec![graven::fetch::parse_base(&format!("http://{addr}")).unwrap()],
        );
        let epoch_number = Checkpoint::parse(case["checkpoint"].as_str().unwrap())
            .unwrap()
            .epoch_number();
        let requested = path.rsplit('/').next().unwrap().parse::<u64>().unwrap();
        let outcome = checkpoints::archived(&sources, requested);
        match case["expected"].as_str().unwrap() {
            "valid" => {
                assert_eq!(outcome.unwrap().epoch_number(), epoch_number, "{name}");
            }
            "WIST3-E03" => {
                let error = outcome.err().map(|e| e.to_string()).unwrap_or_default();
                assert!(error.contains("WIST3-E03"), "{name}: {error}");
            }
            other => panic!("{name}: unknown expectation {other}"),
        }
    }
}

#[test]
fn the_cold_start_vector_matches_a_manifest_to_the_checkpoint_at_its_epoch() {
    let vector = vectors();
    for case in vector["cold_start_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let manifest: wist_core::objects::SnapshotManifest =
            serde_json::from_value(serde_json::json!({
                "wist_version": "1.0.0",
                "snapshot_date": "2026-08-02",
                "epoch_number": case["manifest"]["epoch_number"],
                "tree_size": case["manifest"]["tree_size"],
                "root_hash": case["manifest"]["root_hash"],
                "content_digest": format!("sha256:{}", "0".repeat(64)),
                "state": {
                    "path": "state.json",
                    "sha256": "0".repeat(64),
                    "bytes": 0,
                    "state_digest": format!("sha256:{}", "0".repeat(64)),
                },
                "files": [],
            }))
            .unwrap();
        let checkpoint = Checkpoint::parse(case["checkpoint"].as_str().unwrap()).unwrap();
        let outcome = wist_core::snapshot::check_manifest_anchor(&manifest, &checkpoint);
        match case["expected"].as_str().unwrap() {
            "valid" => outcome.unwrap_or_else(|e| panic!("{name}: {e}")),
            "WIST3-E02" => {
                let error = outcome.unwrap_err().to_string();
                assert!(error.contains("WIST3-E02"), "{name}: {error}");
            }
            other => panic!("{name}: unknown expectation {other}"),
        }
    }
}

#[test]
fn a_tile_or_entry_bundle_one_octet_over_its_bound_is_refused_while_it_streams() {
    let vector: Value = read_json("vectors/wist3/tile-bounds.json");
    let dir = tempfile::tempdir().unwrap();
    let bound = vector["tile"]["bound_bytes"].as_u64().unwrap();
    let at_bound =
        wist_core::crypto::hex_decode(vector["tile"]["at_bound_hex"].as_str().unwrap()).unwrap();
    let over_bound =
        wist_core::crypto::hex_decode(vector["tile"]["over_bound_hex"].as_str().unwrap()).unwrap();
    assert_eq!(at_bound.len() as u64, bound);
    std::fs::write(dir.path().join("at-bound"), &at_bound).unwrap();
    std::fs::write(dir.path().join("over-bound"), &over_bound).unwrap();
    let bundle_bound = vector["entry_bundle"]["bound_bytes"].as_u64().unwrap();
    std::fs::write(dir.path().join("bundle-at-bound"), vec![0u8; 64]).unwrap();

    let (addr, _) = common::serve_recording(dir.path().to_path_buf());
    let client = Client::new(true);
    let url = |name: &str| reqwest::Url::parse(&format!("http://{addr}/{name}")).unwrap();

    assert_eq!(
        client.get_bounded(&url("at-bound"), bound).unwrap().len() as u64,
        bound,
        "equality with the bound is permitted"
    );
    let error = client
        .get_bounded(&url("over-bound"), bound)
        .unwrap_err()
        .to_string();
    assert!(error.contains("WIST3-E03"), "{error}");
    client
        .get_bounded(&url("bundle-at-bound"), bundle_bound)
        .unwrap();
    let error = client
        .get_bounded(&url("bundle-at-bound"), 32)
        .unwrap_err()
        .to_string();
    assert!(error.contains("WIST3-E03"), "{error}");
}

/// WIST-3 §3.3: an Entry's JCS serialization must not exceed 65 535
/// octets, the largest length an entry bundle's prefix can carry.
#[test]
fn an_entry_over_its_leaf_bound_is_refused() {
    let vector: Value = read_json("vectors/wist3/tile-bounds.json");
    let bound = vector["entry_jcs"]["bound_bytes"].as_u64().unwrap();
    for (key, expected) in [("at_bound_entry", true), ("over_bound_entry", false)] {
        let entry = &vector["entry_jcs"][key];
        let octets = wist_core::jcs::canonicalize(entry).unwrap().len() as u64;
        assert_eq!(octets <= bound, expected, "{key} is {octets} octets");
        assert_eq!(
            wist_core::tiles::check_entry_bytes(octets).is_ok(),
            expected,
            "{key}"
        );
    }
}

fn tree_dir(leaves: &[Vec<u8>], tree_size: u64) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let hashes: Vec<[u8; 32]> = leaves[..tree_size as usize]
        .iter()
        .map(|leaf| wist_core::merkle::leaf_hash(leaf))
        .collect();
    let tiles = wist_core::tiles::TileSet::build(&hashes);
    for (path, bytes) in tiles.serve(tree_size) {
        let file = dir.path().join(path.trim_start_matches('/'));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, bytes).unwrap();
    }
    for bundle in wist_core::tiles::required_entry_bundles(tree_size) {
        let (start, end) = bundle.leaf_range();
        let bytes =
            wist_core::tiles::encode_entry_bundle(&leaves[start as usize..end as usize]).unwrap();
        let file = dir.path().join(bundle.path().trim_start_matches('/'));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, bytes).unwrap();
    }
    dir
}

fn leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
}

fn root_at(leaves: &[Vec<u8>], size: usize) -> [u8; 32] {
    let hashes: Vec<[u8; 32]> = leaves[..size]
        .iter()
        .map(|leaf| wist_core::merkle::leaf_hash(leaf))
        .collect();
    wist_core::merkle::merkle_root(&hashes)
}

/// WIST-3 §6: a partial tile is fetched only at the width a verified
/// Checkpoint's size requires, and the full tile is the fallback once the
/// Aggregator has deleted the partial one.
#[test]
fn a_partial_tile_is_fetched_at_the_width_the_tree_requires_and_falls_back_to_the_full_one() {
    let all = leaves(512);
    let served = tree_dir(&all, 300);
    let client = Client::new(true);
    let (addr, requested) = common::serve_recording(served.path().to_path_buf());
    let sources = Sources::new(
        &client,
        vec![graven::fetch::parse_base(&format!("http://{addr}")).unwrap()],
    );
    let mut held = graven::sync::Tree::new();
    tree::seed(&sources, &mut held, 300, &root_at(&all, 300)).unwrap();
    let paths = requested.lock().unwrap().clone();
    assert!(
        paths.contains(&"/tile/0/001.p/44".to_string()),
        "the partial tile the size requires is the one fetched: {paths:?}"
    );
    assert!(
        !paths.contains(&"/tile/0/001".to_string()),
        "the full tile is not fetched while the partial one is served: {paths:?}"
    );

    // The Aggregator's tree has grown and the partial tile is gone.
    let grown = tree_dir(&all, 512);
    std::fs::remove_file(served.path().join("tile/0/001.p/44")).unwrap();
    std::fs::copy(
        grown.path().join("tile/0/001"),
        served.path().join("tile/0/001"),
    )
    .unwrap();
    let (addr, requested) = common::serve_recording(served.path().to_path_buf());
    let sources = Sources::new(
        &client,
        vec![graven::fetch::parse_base(&format!("http://{addr}")).unwrap()],
    );
    let mut held = graven::sync::Tree::new();
    tree::seed(&sources, &mut held, 300, &root_at(&all, 300)).unwrap();
    let paths = requested.lock().unwrap().clone();
    assert!(
        paths.contains(&"/tile/0/001".to_string()),
        "the full tile is the fallback: {paths:?}"
    );
}

/// WIST-3 §9: a tile a source does not hold is `WIST3-E01`, and one whose
/// octets do not reproduce the Checkpoint's tree is `WIST3-E03`; both are
/// answered by the next source, since integrity never depends on where
/// the octets came from.
#[test]
fn a_missing_or_tampered_tile_at_one_source_is_fetched_from_another() {
    let all = leaves(300);
    let root = root_at(&all, 300);
    let client = Client::new(true);

    for break_it in ["remove", "tamper"] {
        let broken = tree_dir(&all, 300);
        let good = tree_dir(&all, 300);
        let target = broken.path().join("tile/0/001.p/44");
        match break_it {
            "remove" => std::fs::remove_file(&target).unwrap(),
            _ => {
                let mut bytes = std::fs::read(&target).unwrap();
                bytes[0] ^= 0xFF;
                std::fs::write(&target, bytes).unwrap();
            }
        }
        let (broken_addr, _) = common::serve_recording(broken.path().to_path_buf());
        let (good_addr, good_requests) = common::serve_recording(good.path().to_path_buf());

        let only_broken = Sources::new(
            &client,
            vec![graven::fetch::parse_base(&format!("http://{broken_addr}")).unwrap()],
        );
        let mut held = graven::sync::Tree::new();
        let error = tree::seed(&only_broken, &mut held, 300, &root)
            .unwrap_err()
            .to_string();
        let expected = if break_it == "remove" {
            "WIST3-E01"
        } else {
            "WIST3-E03"
        };
        assert!(error.contains(expected), "{break_it}: {error}");

        let both = Sources::new(
            &client,
            vec![
                graven::fetch::parse_base(&format!("http://{broken_addr}")).unwrap(),
                graven::fetch::parse_base(&format!("http://{good_addr}")).unwrap(),
            ],
        );
        let mut held = graven::sync::Tree::new();
        tree::seed(&both, &mut held, 300, &root)
            .unwrap_or_else(|e| panic!("{break_it}: the second source serves the tree: {e}"));
        assert!(
            !good_requests.lock().unwrap().is_empty(),
            "{break_it}: the second source was asked"
        );
    }
}

/// WIST-3 §6: an entry bundle whose Entries do not hash to their leaves
/// is `WIST3-E03`, and the next source is asked for the same octets.
#[test]
fn a_tampered_entry_bundle_at_one_source_is_fetched_from_another() {
    let entries: Vec<Vec<u8>> = (0..4u8)
        .map(|i| wist_core::jcs::canonicalize(&serde_json::json!({"n": i})).unwrap())
        .collect();
    let root = root_at(&entries, entries.len());
    let broken = tree_dir(&entries, entries.len() as u64);
    let good = tree_dir(&entries, entries.len() as u64);
    let bundle = broken.path().join("tile/entries/000.p/4");
    let mut bytes = std::fs::read(&bundle).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&bundle, bytes).unwrap();

    let client = Client::new(true);
    let (broken_addr, _) = common::serve_recording(broken.path().to_path_buf());
    let (good_addr, _) = common::serve_recording(good.path().to_path_buf());
    let base = |addr: &str| graven::fetch::parse_base(&format!("http://{addr}")).unwrap();

    let only_broken = Sources::new(&client, vec![base(&broken_addr)]);
    let mut held = graven::sync::Tree::new();
    tree::seed(&only_broken, &mut held, 4, &root).unwrap();
    let error = tree::epoch_entries(&only_broken, &held, 0, 4, 1 << 20)
        .unwrap_err()
        .to_string();
    assert!(error.contains("WIST3-E03"), "{error}");

    let both = Sources::new(&client, vec![base(&broken_addr), base(&good_addr)]);
    let mut held = graven::sync::Tree::new();
    tree::seed(&both, &mut held, 4, &root).unwrap();
    let read = tree::epoch_entries(&both, &held, 0, 4, 1 << 20).unwrap();
    assert_eq!(
        read.len(),
        4,
        "the second source serves the Epoch's Entries"
    );
}

fn sync_with(
    fx: &common::Fixture,
    dir: &Path,
    witnesses: &[String],
) -> Result<graven::sync::SyncReport, graven::Error> {
    sync_from(fx, dir, &[], witnesses)
}

fn sync_from(
    fx: &common::Fixture,
    dir: &Path,
    mirrors: &[String],
    witnesses: &[String],
) -> Result<graven::sync::SyncReport, graven::Error> {
    graven::sync::follow(
        &graven::sync::Follow {
            anchor: fx.anchor_path().to_str().unwrap(),
            log_base: &fx.base_url,
            mirrors,
            witnesses,
            tier1: false,
            allow_http: true,
        },
        dir,
    )
}

/// WIST-3 §5: Equivocation is two Checkpoints *each validly signed* under
/// a key valid at the height its `epoch_number` line states, so a note
/// no such key authenticates is `WIST3-E03` against the source that
/// served it — never evidence, and never a reason to stop applying the
/// Log while another source serves it honestly.
#[test]
fn a_forged_note_at_the_verified_head_is_e03_against_its_source_and_leaves_no_evidence() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    let report = sync_with(&fx, target.path(), &[]).unwrap();
    assert_eq!(report.head, 1);

    let mirror_dir = tempfile::tempdir().unwrap();
    common::copy_dir(fx.dir.path(), mirror_dir.path());
    let mirror = format!(
        "http://{}",
        common::serve_static(mirror_dir.path().to_path_buf())
    );
    common::forge_head_note(&fx, [0xab; 32], &fx.other);

    let report = sync_from(&fx, target.path(), std::slice::from_ref(&mirror), &[])
        .expect("a note no valid key signs is no reason to stop applying the Log");
    assert_eq!(report.head, 1, "the verified head stands");
    assert!(
        !common::synced_log_dir(target.path())
            .join("evidence")
            .exists(),
        "an unverifiable note is preserved as nothing"
    );

    // The same Epoch, this time under the key valid at its height: the
    // two Checkpoints equivocate and the bundle is kept.
    common::forge_head_note(&fx, [0xcd; 32], &fx.log);
    let error = sync_from(&fx, target.path(), std::slice::from_ref(&mirror), &[])
        .unwrap_err()
        .to_string();
    assert!(error.contains("WIST3-E02"), "{error}");
    assert!(common::synced_log_dir(target.path())
        .join("evidence/equivocation-epoch-000000001")
        .join("offered.checkpoint")
        .exists());
}

/// WIST-3 §5: a Checkpoint at or below the verified head is judged under
/// the key set valid at its own height, never at the head's, so a key
/// valid then and retired since still speaks for the Epoch it signed —
/// and a key not yet admitted at that height does not.
#[test]
fn a_checkpoint_below_the_head_is_judged_under_the_keys_valid_at_its_own_height() {
    for (offered_epoch, expected, evidence) in
        [(5u64, "WIST3-E02", true), (2u64, "WIST3-E03", false)]
    {
        let fx = common::build_fixture(true, false);
        let second = common::Signer::new([41u8; 32]);
        // k2 is admitted at Epoch 3 and retired at Epoch 8; the head is
        // Epoch 10.
        for epoch in 2..=10u64 {
            let at = common::next_instant(&fx);
            let entries = match epoch {
                3 => vec![common::key_act(
                    &fx,
                    "aggregator_key_add",
                    "log1",
                    &fx.log,
                    "log2",
                    Some(&second),
                    "2026-08-09T15:00:00Z",
                )],
                8 => vec![common::key_act(
                    &fx,
                    "aggregator_key_remove",
                    "log1",
                    &fx.log,
                    "log2",
                    None,
                    "2026-08-09T15:00:00Z",
                )],
                _ => Vec::new(),
            };
            common::seal_next(&fx, &at, &entries);
        }
        let target = tempfile::tempdir().unwrap();
        assert_eq!(sync_with(&fx, target.path(), &[]).unwrap().head, 10);

        // A source offers a differing Checkpoint of an Epoch the Consumer
        // retains, signed by k2.
        let retained = fx.log_state().checkpoints[offered_epoch as usize].clone();
        let mut forged = Checkpoint::new(
            retained.origin(),
            retained.tree_size(),
            [0x5a; 32],
            retained.epoch_number(),
            retained.sealed_at(),
        )
        .unwrap();
        forged.sign(&second.sk);
        fx.log_state().write_head_note(&forged.encode());

        let error = sync_with(&fx, target.path(), &[]).unwrap_err().to_string();
        assert!(error.contains(expected), "epoch {offered_epoch}: {error}");
        assert_eq!(
            common::synced_log_dir(target.path())
                .join(format!("evidence/equivocation-epoch-{offered_epoch:09}"))
                .exists(),
            evidence,
            "epoch {offered_epoch}: evidence is kept only for an authenticated Checkpoint"
        );
    }
}

/// WIST-3 §5, the first Equivocation form: two Checkpoints of one Log
/// stating one tree size and different root hashes. The two notes are the
/// whole evidence, and no tile decides it.
#[test]
fn two_checkpoints_stating_one_tree_size_and_different_roots_are_divergence() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync_with(&fx, target.path(), &[]).unwrap().head, 1);

    let head = fx.log_state().head().clone();
    let mut forged = Checkpoint::new(
        head.origin(),
        head.tree_size(),
        [0x77; 32],
        head.epoch_number() + 1,
        "2026-08-09T14:00:00Z",
    )
    .unwrap();
    forged.sign(&fx.log.sk);
    fx.log_state().write_head_note(&forged.encode());

    let error = sync_with(&fx, target.path(), &[]).unwrap_err().to_string();
    assert!(error.contains("WIST3-E02"), "{error}");
    let bundle = common::synced_log_dir(target.path()).join("evidence/divergence-epoch-000000002");
    assert!(bundle.join("previous.checkpoint").exists());
    assert!(bundle.join("offered.checkpoint").exists());
    assert!(
        !bundle.join("tiles").exists(),
        "the two notes are the whole evidence for this form"
    );
}

/// WIST-3 §5, the third Equivocation form inside tiles the Consumer
/// already holds: the offered tree does not extend the verified head's,
/// and the tiles that reproduce the larger root are the evidence.
#[test]
fn a_fork_below_the_verified_head_is_divergence_with_the_forks_tiles_preserved() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync_with(&fx, target.path(), &[]).unwrap().head, 1);
    let honest_size = fx.head_tree_size();

    // A second history under the same key and origin: its Epoch 1 seals
    // other Entries, so the tree the Consumer holds at the head's size is
    // not the prefix of the tree Epoch 2 states.
    let publisher = common::Signer::new([1u8; 32]);
    let fork_entries: Vec<Value> = (0..honest_size + 2)
        .map(|i| {
            let (_, env, _) = common::build_delta(
                &publisher,
                &format!("https://records.example/fork-{i}"),
                "Fork",
                None,
                "fork body",
                None,
            );
            serde_json::json!({"type": "publisher_delta", "body": env})
        })
        .collect();
    let mut forked = common::Log::new(
        fx.dir.path(),
        common::Signer::new([9u8; 32]),
        "graven-test-log",
    );
    forked.seal("2026-08-09T12:00:00Z", &fork_entries);
    forked.seal("2026-08-09T13:00:00Z", &[]);
    forked.seal("2026-08-09T14:00:00Z", &[]);

    let error = sync_with(&fx, target.path(), &[]).unwrap_err().to_string();
    assert!(error.contains("WIST3-E02"), "{error}");
    let bundle = common::synced_log_dir(target.path()).join("evidence/divergence-epoch-000000002");
    assert!(bundle.join("offered.checkpoint").exists());
    assert!(
        std::fs::read_dir(bundle.join("tiles"))
            .unwrap()
            .next()
            .is_some(),
        "the tiles that reproduce the larger root are preserved"
    );
}

/// WIST-3 §4 and §9: a Checkpoint stating tree size 0 with any root but
/// `SHA-256("")` fails the Consistency Proof from the empty tree, and
/// that one Checkpoint is the whole evidence.
#[test]
fn a_size_zero_checkpoint_stating_another_root_is_divergence() {
    let dir = tempfile::tempdir().unwrap();
    let signer = common::Signer::new([44u8; 32]);
    let log = common::Log::new(dir.path(), common::Signer::new([44u8; 32]), "empty.example");
    drop(log);
    let mut forged =
        Checkpoint::new("empty.example", 0, [0x11; 32], 0, "2026-08-09T12:00:00Z").unwrap();
    forged.sign(&signer.sk);
    let genesis: wist_core::objects::GenesisKey = serde_json::from_value(serde_json::json!({
        "key_id": "log1",
        "alg": "Ed25519",
        "public_key": signer.public_b64u(),
    }))
    .unwrap();
    let registry =
        wist_core::aggregator_keys::Registry::from_genesis("empty.example", &genesis).unwrap();
    let error = checkpoints::divergence(
        dir.path(),
        "empty.example",
        &registry,
        0,
        None,
        &forged,
        None,
        "a Checkpoint states tree size 0 with another root than the empty tree's",
    )
    .to_string();
    assert!(error.contains("WIST3-E02"), "{error}");
    let bundle = dir.path().join("evidence/divergence-epoch-000000000");
    assert!(bundle.join("offered.checkpoint").exists());
    assert!(!bundle.join("previous.checkpoint").exists());

    let client = Client::new(true);
    let (addr, _) = common::serve_recording(dir.path().to_path_buf());
    let sources = Sources::new(
        &client,
        vec![graven::fetch::parse_base(&format!("http://{addr}")).unwrap()],
    );
    let mut held = graven::sync::Tree::new();
    let error = tree::seed(&sources, &mut held, 0, &[0x11; 32])
        .unwrap_err()
        .to_string();
    assert!(error.contains("WIST3-E02"), "{error}");
    tree::seed(&sources, &mut held, 0, &wist_core::merkle::EMPTY_ROOT).unwrap();
}

/// WIST-3 §5: "consumers verifying it MUST stop applying new data from
/// that Aggregator" — the halt outlives the run that established it.
#[test]
fn a_verified_divergence_halts_every_later_sync_of_that_log() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync_with(&fx, target.path(), &[]).unwrap().head, 1);

    common::forge_head_note(&fx, [0xcd; 32], &fx.log);
    let error = sync_with(&fx, target.path(), &[]).unwrap_err().to_string();
    assert!(error.contains("WIST3-E02"), "{error}");

    // The source goes back to serving its honest history.
    fx.log_state().publish();
    common::extend_fixture(&fx);
    let error = sync_with(&fx, target.path(), &[]).unwrap_err().to_string();
    assert!(
        error.contains("WIST3-E02") && error.contains("evidence"),
        "{error}"
    );
    assert_eq!(
        graven::store::synced_state(&common::synced_log_dir(target.path()))
            .unwrap()
            .epoch_number,
        1,
        "nothing more is applied from this Aggregator"
    );
    // Queries over what was already applied keep working.
    let store = graven::store::Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(store
        .get("https://records.example/alpha")
        .unwrap()
        .is_some());
}

/// WIST-3 §5: staleness is judged on the newest Checkpoint the Consumer
/// can ACCEPT — the verified head while everything above it is short of
/// the quorum — not on whatever a source last offered.
#[test]
fn a_head_kept_short_of_the_quorum_is_reported_stale() {
    let fx = common::build_fixture(true, false);
    let witness = common::Witness::new("witness-a.example", [79u8; 32]);
    let roster = vec![witness.verifier_key()];
    let target = tempfile::tempdir().unwrap();

    let raise = common::parameter_act(
        "log1",
        &fx.log,
        "checkpoint_witness_quorum",
        1,
        "2026-08-16T14:00:00Z",
    );
    common::seal_next(&fx, "2026-08-09T14:00:00Z", &[raise]);
    let report = sync_with(&fx, target.path(), &roster).unwrap();
    assert_eq!(report.head, 2);
    assert!(
        report.stale,
        "the fixture's Epochs are sealed far in the past"
    );

    // A fresh Checkpoint arrives, but no Witness of the roster cosigned
    // it: the head stays where it is and stays stale.
    common::seal_next(&fx, "2026-08-16T14:00:00Z", &[]);
    let report = sync_with(&fx, target.path(), &roster).unwrap();
    assert_eq!(report.head, 2, "the Checkpoint is short of the quorum");
    assert!(report.stale, "the head it kept is the newest it can accept");
}

/// A head sealed within three cadences of now is not stale, whatever a
/// source offers above it.
#[test]
fn a_recent_head_is_not_reported_stale() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    let now = jiff::Timestamp::now().as_second();
    let at = wist_core::timestamp::instant(now.div_euclid(3600) * 3600).unwrap();
    common::seal_next(&fx, &at, &[]);
    let report = sync_with(&fx, target.path(), &[]).unwrap();
    assert_eq!(report.head, 2);
    assert!(!report.stale);
}

/// With no source serving a head, the verified head is the newest
/// Checkpoint the Consumer can accept, and its staleness is reported with
/// the failure.
#[test]
fn a_head_no_source_serves_reports_the_verified_heads_staleness() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync_with(&fx, target.path(), &[]).unwrap().head, 1);

    std::fs::remove_file(fx.dir.path().join("checkpoint")).unwrap();
    let error = sync_with(&fx, target.path(), &[]).unwrap_err().to_string();
    assert!(error.contains("WIST3-E01"), "{error}");
    assert!(error.contains("stale"), "{error}");
    assert_eq!(
        graven::store::synced_state(&common::synced_log_dir(target.path()))
            .unwrap()
            .epoch_number,
        1
    );
}

/// WIST-3 §5: the unwitnessed record belongs to the Checkpoint the
/// Consumer retains, so a later witnessed adoption does not rewrite it.
#[test]
fn the_unwitnessed_record_stays_with_the_checkpoint_it_belongs_to() {
    let fx = common::build_fixture(true, false);
    let witness = common::Witness::new("witness-a.example", [78u8; 32]);
    let roster = vec![witness.verifier_key()];
    let target = tempfile::tempdir().unwrap();
    assert_eq!(sync_with(&fx, target.path(), &roster).unwrap().head, 1);

    let at = common::next_instant(&fx);
    common::seal_next(&fx, &at, &[]);
    fx.log_state().cosign_head(&[&witness], 1_775_000_000);
    let report = sync_with(&fx, target.path(), &roster).unwrap();
    assert_eq!(report.head, 2);
    assert!(!report.unwitnessed);

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let recorded = |epoch: u64| -> Option<bool> {
        conn.query_row(
            "SELECT unwitnessed FROM checkpoints WHERE epoch_number = ?1",
            [epoch as i64],
            |row| row.get::<_, Option<bool>>(0),
        )
        .unwrap()
    };
    assert_eq!(recorded(1), Some(true), "Epoch 1 was adopted unwitnessed");
    assert_eq!(recorded(2), Some(false), "Epoch 2 carries a Cosignature");
}

/// WIST-3 §6: an Epoch whose leaves cross a tile boundary is read from
/// every entry bundle and tile its leaf range meets, the right-edge ones
/// at the partial widths the Checkpoint's size requires.
#[test]
fn an_epoch_whose_leaves_cross_a_tile_boundary_is_verified_and_applied() {
    let fx = common::build_fixture(true, false);
    let publisher = common::Signer::new([1u8; 32]);
    let entries: Vec<Value> = (0..300)
        .map(|i| {
            let url = format!("https://records.example/wide-{i}");
            let (id, env, payload) = common::build_delta(
                &publisher,
                &url,
                &format!("Wide {i}"),
                None,
                "wide body",
                None,
            );
            common::write_payload(fx.dir.path(), id.strip_prefix("sha256:").unwrap(), &payload);
            serde_json::json!({"type": "publisher_delta", "body": env})
        })
        .collect();
    common::seal_next(&fx, "2026-08-09T14:00:00Z", &entries);
    assert!(
        fx.head_tree_size() > 256,
        "the Epoch's leaves must cross the first tile"
    );

    let target = tempfile::tempdir().unwrap();
    let report = sync_with(&fx, target.path(), &[]).unwrap();
    assert_eq!(report.tree_size, fx.head_tree_size());
    let store = graven::store::Store::open(&common::synced_log_dir(target.path())).unwrap();
    assert!(store
        .get("https://records.example/wide-299")
        .unwrap()
        .is_some());
}

/// With an empty roster and the quorum this edition starts at, the head
/// is adopted and the acceptance is recorded as unwitnessed (WIST-3 §5).
#[test]
fn an_empty_roster_at_quorum_zero_adopts_the_head_and_records_it_unwitnessed() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    let report = sync_with(&fx, target.path(), &[]).unwrap();
    assert!(report.unwitnessed);
    let state = graven::store::synced_state(&common::synced_log_dir(target.path())).unwrap();
    assert!(state.unwitnessed);
    assert_eq!(state.epoch_number, report.head);
}

/// A store written before the Log became one growing tree names a Block
/// hash where a tree size and root now stand; it is refused rather than
/// reinterpreted.
#[test]
fn a_sync_state_in_the_superseded_format_is_refused_with_an_instruction_to_resync() {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    sync_with(&fx, target.path(), &[]).unwrap();
    let log_dir = common::synced_log_dir(target.path());
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    conn.execute(
        "UPDATE sync_state SET state = ?1 WHERE id = 1",
        [r#"{"log_position":0,"head_number":1,"head_hash":"sha256:deadbeef"}"#],
    )
    .unwrap();
    drop(conn);
    let error = sync_with(&fx, target.path(), &[]).unwrap_err().to_string();
    assert!(
        error.contains("superseded format") && error.contains("sync again"),
        "{error}"
    );
}
