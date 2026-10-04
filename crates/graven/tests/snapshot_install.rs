mod common;

use common::{Content, Log, RecordFixture, Signer, SnapshotParts};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use wist_core::objects::{AggregatorKeyEntry, DeclarationEntry, StateEntry};

fn spec_dir() -> PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
}

fn read_json(rel: &str) -> Value {
    serde_json::from_slice(&std::fs::read(spec_dir().join(rel)).unwrap()).unwrap()
}

fn log_key_tuple(log: &Signer) -> StateEntry {
    StateEntry::AggregatorKey(AggregatorKeyEntry {
        key_id: "log1".into(),
        public_key: log.public_b64u(),
        added_height: 0,
        removed_height: None,
        adding_act: None,
        removing_act: None,
    })
}

fn declaration_tuple(declaration: &Value) -> StateEntry {
    StateEntry::Declaration(DeclarationEntry {
        domain: declaration["publisher"]["domain"].as_str().unwrap().into(),
        declaration: declaration.clone(),
        sealing_height: 0,
        highest_accepted_seq: declaration["publisher"]["seq"].as_u64().unwrap(),
    })
}

struct Served {
    dir: tempfile::TempDir,
    base_url: String,
    log_id: String,
}

impl Served {
    fn cold_start(&self, tier1: bool) -> (tempfile::TempDir, PathBuf) {
        let (target, log_dir) = self.cold_start_unchecked(tier1);
        common::assert_records_materialized(&log_dir);
        (target, log_dir)
    }

    fn cold_start_unchecked(&self, tier1: bool) -> (tempfile::TempDir, PathBuf) {
        let target = tempfile::tempdir().unwrap();
        graven::sync::run(
            self.dir.path().join("log/anchor.json").to_str().unwrap(),
            &self.base_url,
            target.path(),
            true,
            tier1,
        )
        .unwrap();
        let log_dir = graven::registry::log_dir(target.path(), &self.log_id);
        common::assert_rows_are_the_replays(&log_dir);
        (target, log_dir)
    }
}

fn rows(log_dir: &Path, query: &str) -> Vec<Value> {
    let conn = Connection::open(log_dir.join("index.sqlite")).unwrap();
    let mut stmt = conn.prepare(query).unwrap();
    let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
    stmt.query_map([], |row| {
        let mut object = serde_json::Map::new();
        for (index, column) in columns.iter().enumerate() {
            let value = match row.get_ref(index)? {
                rusqlite::types::ValueRef::Integer(n) => json!(n),
                rusqlite::types::ValueRef::Text(text) => json!(std::str::from_utf8(text).unwrap()),
                _ => Value::Null,
            };
            object.insert(column.clone(), value);
        }
        Ok(Value::Object(object))
    })
    .unwrap()
    .collect::<rusqlite::Result<_>>()
    .unwrap()
}

fn serve_snapshot_records(shards: Option<u64>) -> (Served, wist_core::objects::SnapshotManifest) {
    let vector = read_json("vectors/wist3/snapshot-records.json");
    let dir = tempfile::tempdir().unwrap();
    let log_id = "snapshot-records-log";
    let log_signer = Signer::new([70u8; 32]);
    let mut log = Log::new(dir.path(), Signer::new([70u8; 32]), log_id);
    let checkpoint = log.seal("2026-08-02T13:00:00Z", &[]);

    let mut entries: Vec<StateEntry> = vector["tuples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tuple| serde_json::from_value(tuple.clone()).unwrap())
        .collect();
    entries.push(declaration_tuple(&read_json("examples/publisher.json")));
    for declaration in vector["declarations"].as_object().unwrap().values() {
        entries.push(declaration_tuple(declaration));
    }
    entries.push(log_key_tuple(&log_signer));

    let item_of = |url: &str| -> Value {
        vector["tuples"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tuple| tuple[0] == "record" && tuple[2] == url)
            .unwrap()[3]
            .clone()
    };
    let mut records = Vec::new();
    let mut extracts = Vec::new();
    let mut links = Vec::new();
    for record in vector["records"].as_array().unwrap() {
        let url = record["url"].as_str().unwrap();
        let item_id = record["item_id"].as_str().unwrap();
        let item = item_of(url);
        let content = &vector["payloads"][item_id]["content"];
        records.push(RecordFixture {
            url: url.into(),
            publisher: record["publisher"].as_str().unwrap().into(),
            item: item.clone(),
            item_id: item_id.into(),
            observed_at: record["observed_at"].as_str().unwrap().into(),
            attested_at: record["attested_at"].as_str().unwrap().into(),
            title: content["summary"]["title"].as_str().unwrap().into(),
            abstract_text: content["summary"]["abstract"].as_str().map(str::to_owned),
            lang: item["meta"]["lang"].as_str().unwrap().into(),
        });
        extracts.push((
            url.to_owned(),
            record["publisher"].as_str().unwrap().to_owned(),
            item_id.to_owned(),
            content["extract"].as_str().unwrap().to_owned(),
        ));
        for (position, target) in content["links"]["urls"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            links.push((
                url.to_owned(),
                target.as_str().unwrap().to_owned(),
                position as i64,
            ));
        }
    }
    let manifest = common::write_snapshot(
        dir.path(),
        &SnapshotParts {
            signer: &log_signer,
            key_id: "log1",
            snapshot_date: vector["snapshot_date"].as_str().unwrap(),
            checkpoint: &checkpoint,
            entries,
            records: &records,
            extracts,
            links,
            tier1: true,
            shards,
        },
    );
    let base_url = format!("http://{}", common::serve_static(dir.path().to_path_buf()));
    (
        Served {
            dir,
            base_url,
            log_id: log_id.into(),
        },
        manifest,
    )
}

fn assert_holds_the_vectors_records(log_dir: &Path) {
    let vector = read_json("vectors/wist3/snapshot-records.json");
    assert_eq!(
        json!(rows(
            log_dir,
            "SELECT url, publisher, item_id, observed_at, attested_at FROM records ORDER BY publisher, url"
        )),
        vector["records"]
    );
    assert_eq!(
        common::records_content_digest(log_dir),
        vector["content_digest"].as_str().unwrap()
    );
    assert_eq!(
        json!(rows(
            log_dir,
            "SELECT l.source_url, l.target_url, l.position FROM links l JOIN records r ON r.url = l.source_url ORDER BY r.publisher, r.url, l.position"
        )),
        vector["links"]
    );
    for record in rows(
        log_dir,
        "SELECT item_id, title, abstract, collection FROM records",
    ) {
        let summary =
            &vector["payloads"][record["item_id"].as_str().unwrap()]["content"]["summary"];
        assert_eq!(record["title"], summary["title"]);
        assert_eq!(record["abstract"], summary["abstract"]);
        assert_eq!(record["collection"], "default");
    }
    for extract in rows(log_dir, "SELECT collection FROM extracts") {
        assert_eq!(extract["collection"], "default");
    }
}

/// WIST-3 §7 and §8 cold start steps 3 and 4.
#[test]
fn snapshot_records_vector_installs_the_content_tuples_and_link_rows_it_names() {
    let (served, _) = serve_snapshot_records(None);
    let (_target, log_dir) = served.cold_start(true);
    assert_holds_the_vectors_records(&log_dir);
}

/// WIST-3 §7 "Sharding".
#[test]
fn snapshot_records_vector_sharded_files_digests_and_records_install_by_publisher() {
    let vector = read_json("vectors/wist3/snapshot-records.json");
    let sharded = &vector["sharded"];
    let count = sharded["count"].as_u64().unwrap();
    for (domain, shard) in sharded["shard_of"].as_object().unwrap() {
        assert_eq!(
            wist_core::snapshot::shard_of(domain, std::num::NonZeroU64::new(count).unwrap()),
            shard.as_u64().unwrap(),
            "{domain}"
        );
    }
    let (served, manifest) = serve_snapshot_records(Some(count));
    assert_eq!(
        json!(manifest.shards.as_ref().unwrap().digests),
        sharded["digests"]
    );
    let files: Vec<Value> = manifest
        .files
        .iter()
        .map(|f| json!({"path": f.path, "tier": f.tier, "shard": f.shard}))
        .collect();
    assert_eq!(json!(files), sharded["files"]);

    let (_target, log_dir) = served.cold_start(true);
    assert_holds_the_vectors_records(&log_dir);
}

/// WIST-3 §8 cold start steps 4 and 9: the tuples decide the records; a tier-0 row supplies the
/// content of the record whose Item it names, and a record no row covers has its Payload fetched.
#[test]
fn a_cold_start_installs_the_records_its_tuples_materialize_and_takes_only_their_content_from_tier0(
) {
    let dir = tempfile::tempdir().unwrap();
    let log_id = "snapshot-tuples-log";
    let log_signer = Signer::new([71u8; 32]);
    let mut log = Log::new(dir.path(), Signer::new([71u8; 32]), log_id);
    let checkpoint = log.seal("2026-08-09T13:00:00Z", &[]);
    let publisher = Signer::new([1u8; 32]);

    let page = |path: &str, title: &'static str| {
        let url = format!("https://{}/{path}", common::RECORDS);
        let (item, payload) = common::page(
            common::RECORDS,
            &url,
            common::OBSERVED,
            &Content {
                title,
                r#abstract: None,
                extract: title,
                links: &[],
            },
        );
        common::serve_payload(dir.path(), &item, &payload);
        RecordFixture {
            item_id: wist_core::item::item_id(&item).unwrap(),
            item,
            title: format!("{title} from tier 0"),
            ..RecordFixture::new(&url, common::RECORDS, title)
        }
    };
    let covered = page("covered", "Covered");
    let replaced = page("replaced", "Replaced");
    let uncovered = page("uncovered", "Uncovered");
    let stray = page("stray", "Stray");
    let stale = RecordFixture {
        item: page("replaced", "Replaced earlier").item,
        item_id: page("replaced", "Replaced earlier").item_id,
        ..replaced.clone()
    };

    let mut entries = common::record_tuples(
        &[covered.clone(), replaced.clone(), uncovered.clone()],
        |_| Signer::new([1u8; 32]),
    );
    entries.push(declaration_tuple(&common::build_declaration(
        &publisher,
        common::RECORDS,
    )));
    entries.push(log_key_tuple(&log_signer));
    common::write_snapshot(
        dir.path(),
        &SnapshotParts {
            signer: &log_signer,
            key_id: "log1",
            snapshot_date: "2026-08-09",
            checkpoint: &checkpoint,
            entries,
            records: &[covered.clone(), stale, stray.clone()],
            extracts: Vec::new(),
            links: Vec::new(),
            tier1: false,
            shards: None,
        },
    );
    let served = Served {
        base_url: format!("http://{}", common::serve_static(dir.path().to_path_buf())),
        dir,
        log_id: log_id.into(),
    };

    let (_target, log_dir) = served.cold_start_unchecked(false);

    assert_eq!(
        json!(rows(&log_dir, "SELECT url, item_id, title FROM records ORDER BY url")),
        json!([
            {"url": covered.url, "item_id": covered.item_id, "title": "Covered from tier 0"},
            {"url": replaced.url, "item_id": replaced.item_id, "title": "Replaced"},
            {"url": uncovered.url, "item_id": uncovered.item_id, "title": "Uncovered"},
        ]),
        "the stray row leaves, the stale row takes its tuple's Item and that Item's Payload, and the uncovered record is fetched"
    );
    assert!(common::record_row(&log_dir, &stray.url).is_none());
}

/// WIST-4 §5.1: a Consumer resumed from a Snapshot holds the IDs of its `registry_update` tuples
/// as accepted, so a `parameter_change` sealed again above it is idempotent.
#[test]
fn a_consumer_resumed_from_a_snapshot_reads_a_parameter_change_sealed_again_as_idempotent() {
    let vector = read_json("vectors/wist4/parameter-in-force.json");
    let cases = vector["resume_cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let parameter = case["parameter"].as_str().unwrap();
        let snapshot_epoch = case["snapshot_epoch"].as_u64().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log_id = "parameter-resume-log";
        let log_signer = Signer::new([72u8; 32]);
        let mut log = Log::new(dir.path(), Signer::new([72u8; 32]), log_id);
        let act_key = &case["log_key"];
        let addition = wist_core::envelope::sign_envelope(
            &json!({
                "wist_version": "1.0.0",
                "action": "aggregator_key_add",
                "subject": act_key["key_id"],
                "details": {"alg": "Ed25519", "key_id": act_key["key_id"], "public_key": act_key["public_key"]},
                "effective_at": "2026-08-01T00:00:00Z"
            }),
            "update",
            "log1",
            &log_signer.sk,
        )
        .unwrap();
        let mut snapshot = None;
        for epoch in case["epochs"].as_array().unwrap() {
            let height = epoch["epoch_number"].as_u64().unwrap();
            let mut entries: Vec<Value> = epoch["acts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|act| json!({"type": "registry_update", "body": act}))
                .collect();
            if height == 0 {
                entries.push(json!({"type": "registry_update", "body": addition}));
            }
            let checkpoint = log.seal(epoch["sealed_at"].as_str().unwrap(), &entries);
            if height == snapshot_epoch {
                snapshot = Some(checkpoint);
            }
        }
        let snapshot = snapshot.unwrap();
        let mut entries: Vec<StateEntry> =
            serde_json::from_value(case["snapshot_tuples"].clone()).unwrap();
        entries.push(log_key_tuple(&log_signer));
        entries.push(StateEntry::AggregatorKey(AggregatorKeyEntry {
            key_id: act_key["key_id"].as_str().unwrap().into(),
            public_key: act_key["public_key"].as_str().unwrap().into(),
            added_height: 0,
            removed_height: None,
            adding_act: Some(addition.clone()),
            removing_act: None,
        }));
        entries.push(StateEntry::RegistryUpdate(
            wist_core::objects::RegistryUpdateEntry {
                update_id: wist_core::registry_updates::update_id(&addition).unwrap(),
                sealing_height: 0,
            },
        ));
        common::write_snapshot(
            dir.path(),
            &SnapshotParts {
                signer: &log_signer,
                key_id: "log1",
                snapshot_date: "2026-08-04",
                checkpoint: &snapshot,
                entries,
                records: &[],
                extracts: Vec::new(),
                links: Vec::new(),
                tier1: false,
                shards: None,
            },
        );
        let served = Served {
            base_url: format!("http://{}", common::serve_static(dir.path().to_path_buf())),
            dir,
            log_id: log_id.into(),
        };
        let (_target, log_dir) = served.cold_start_unchecked(false);

        let accepted = rows(
            &log_dir,
            &format!(
                "SELECT value, epoch_number FROM parameters WHERE parameter = '{parameter}' ORDER BY epoch_number, entry_index"
            ),
        );
        assert_eq!(
            accepted.last().map(|row| row["value"].clone()),
            Some(case["resumed_value"].clone()),
            "{label}"
        );
        assert!(
            accepted
                .iter()
                .all(|row| row["epoch_number"].as_u64().unwrap() <= snapshot_epoch),
            "{label}: the act sealed again above the Snapshot applies nothing: {accepted:?}"
        );
        let held: Vec<Value> = common::state_tuples(&log_dir)
            .into_iter()
            .filter(|tuple| tuple[0] == "registry_update")
            .collect();
        for tuple in case["snapshot_tuples"].as_array().unwrap() {
            if tuple[0] == "registry_update" {
                assert!(held.contains(tuple), "{label}: {tuple} keeps its height");
            }
        }
    }
}
