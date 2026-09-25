mod common;

use common::{build_sharded_fixture, rewrite_manifest, ShardedFixture};
use graven::store::Store;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use wist_core::crypto::hex_encode;

fn cold_start(sharded: &ShardedFixture, target: &std::path::Path) -> graven::error::Result<()> {
    graven::sync::run(
        sharded.fx.anchor_path().to_str().unwrap(),
        &sharded.fx.base_url,
        target,
        true,
        true,
    )
    .map(|_| ())
}

fn refused(sharded: &ShardedFixture) -> String {
    let target = tempfile::tempdir().unwrap();
    let error = cold_start(sharded, target.path())
        .expect_err("the Snapshot does not verify")
        .to_string();
    assert!(
        !common::synced_log_dir(target.path())
            .join("sync.json")
            .exists(),
        "a refused Snapshot commits nothing"
    );
    error
}

fn assert_serves_every_record(sharded: &ShardedFixture, target: &std::path::Path) {
    let store = Store::open(&common::synced_log_dir(target)).unwrap();
    for record in &sharded.records {
        let held = store
            .get(&record.url)
            .unwrap()
            .unwrap_or_else(|| panic!("{} is served", record.url));
        assert_eq!(held.publisher, record.publisher);
        assert_eq!(held.title, record.title);
    }
}

fn files_mut(manifest: &mut Value) -> &mut Vec<Value> {
    manifest["files"].as_array_mut().unwrap()
}

/// WIST-3 §7 "Sharding" and §8 steps 3–4.
#[test]
fn a_sharded_snapshot_cold_start_serves_the_records_of_every_shard() {
    let sharded = build_sharded_fixture(3, false, None);
    let target = tempfile::tempdir().unwrap();

    cold_start(&sharded, target.path()).unwrap();

    assert_serves_every_record(&sharded, target.path());
    let store = Store::open(&common::synced_log_dir(target.path())).unwrap();
    for record in &sharded.records {
        let hits = store.search(&record.title, 10).unwrap();
        assert!(
            hits.iter().any(|hit| hit.url == record.url),
            "{} is found by its title",
            record.url
        );
    }
    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let extracts: i64 = conn
        .query_row("SELECT COUNT(*) FROM extracts", [], |row| row.get(0))
        .unwrap();
    let links: i64 = conn
        .query_row("SELECT COUNT(*) FROM links", [], |row| row.get(0))
        .unwrap();
    assert_eq!(extracts as usize, sharded.records.len());
    assert_eq!(links as usize, sharded.records.len());
    assert!(!common::synced_log_dir(target.path())
        .join("index.sqlite.shard-1.verifying")
        .exists());
}

/// WIST-3 §6.
#[test]
fn a_snapshot_resolves_its_files_against_a_manifest_in_any_directory() {
    let sharded = build_sharded_fixture(2, false, Some("mirrored/elsewhere/"));
    let target = tempfile::tempdir().unwrap();

    cold_start(&sharded, target.path()).unwrap();

    assert_serves_every_record(&sharded, target.path());
}

/// WIST-3 §7 "Sharding".
#[test]
fn a_record_filed_in_the_wrong_shard_fails_its_shard_digest() {
    let sharded = build_sharded_fixture(2, true, None);

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(
        error.contains("shard") && error.contains("digest"),
        "{error}"
    );
    assert!(
        error.contains("is not the one its manifest names"),
        "{error}"
    );
}

/// WIST-3 §7 "Sharding".
#[test]
fn a_shard_index_disagreeing_with_its_path_prefix_is_wist3_e04() {
    let sharded = build_sharded_fixture(2, false, None);
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        let file = files_mut(manifest)
            .iter_mut()
            .find(|f| f["path"] == "shard-1/tier1/links.parquet")
            .unwrap();
        file["shard"] = 0.into();
    });

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(error.contains("shard-1/tier1/links.parquet"), "{error}");
}

/// WIST-3 §7 "Sharding".
#[test]
fn a_sharded_manifest_listing_a_tier_file_outside_a_shard_directory_is_wist3_e04() {
    let sharded = build_sharded_fixture(2, false, None);
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        let file = files_mut(manifest)
            .iter_mut()
            .find(|f| f["path"] == "shard-0/tier1/links.parquet")
            .unwrap();
        file["path"] = "tier1/links.parquet".into();
    });

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(error.contains("tier1/links.parquet"), "{error}");
}

/// WIST-3 §7 "Sharding".
#[test]
fn a_zero_padded_shard_directory_is_wist3_e04() {
    let sharded = build_sharded_fixture(2, false, None);
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        let file = files_mut(manifest)
            .iter_mut()
            .find(|f| f["path"] == "shard-1/tier1/links.parquet")
            .unwrap();
        file["path"] = "shard-01/tier1/links.parquet".into();
    });

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(error.contains("shard-01/tier1/links.parquet"), "{error}");
}

/// WIST-3 §7 "Sharding".
#[test]
fn a_sharded_manifest_listing_a_shard_without_its_tier0_index_is_wist3_e04() {
    let sharded = build_sharded_fixture(2, false, None);
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        files_mut(manifest).retain(|f| f["path"] != "shard-1/tier0/index.sqlite");
    });

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(
        error.contains("shard 1 without its tier0/index.sqlite"),
        "{error}"
    );
}

/// WIST-3 §7 "Sharding".
#[test]
fn a_shard_digest_count_differing_from_the_shard_count_is_wist3_e04() {
    let sharded = build_sharded_fixture(2, false, None);
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        manifest["shards"]["digests"].as_array_mut().unwrap().pop();
    });

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(error.contains("2 shards but carries 1"), "{error}");
}

/// WIST-3 §7 "Sharding".
#[test]
fn a_sharded_manifest_file_without_a_shard_index_is_wist3_e04() {
    let sharded = build_sharded_fixture(2, false, None);
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        let file = files_mut(manifest)
            .iter_mut()
            .find(|f| f["path"] == "shard-0/tier1/extracts.parquet")
            .unwrap();
        file.as_object_mut().unwrap().remove("shard");
    });

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(error.contains("without a shard index"), "{error}");
}

/// WIST-3 §7 "Sharding".
#[test]
fn a_shard_index_at_or_above_the_shard_count_is_wist3_e04() {
    let sharded = build_sharded_fixture(2, false, None);
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        let file = files_mut(manifest)
            .iter_mut()
            .find(|f| f["path"] == "shard-1/tier1/extracts.parquet")
            .unwrap();
        file["shard"] = 2.into();
        file["path"] = "shard-2/tier1/extracts.parquet".into();
    });

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(error.contains("under shard 2 of 2"), "{error}");
}

/// WIST-3 §7 "Tier layout is normative": a Consumer ignores columns it does not know.
#[test]
fn a_sharded_cold_start_ignores_a_constrained_extra_column_in_a_shards_records() {
    let sharded = build_sharded_fixture(2, false, None);
    let path = sharded
        .manifest_path
        .parent()
        .unwrap()
        .join("shard-0/tier0/index.sqlite");
    std::fs::remove_file(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE records(url TEXT, publisher TEXT, delta_id TEXT, observed_at TEXT, title TEXT, abstract TEXT, lang TEXT, rank INTEGER NOT NULL);
         CREATE VIRTUAL TABLE records_fts USING fts5(title, abstract, content=records, content_rowid=rowid);",
    )
    .unwrap();
    for (rank, r) in sharded
        .records
        .iter()
        .filter(|r| common::shard_of(&r.publisher, 2) == 0)
        .enumerate()
    {
        conn.execute(
            "INSERT INTO records VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                &r.url,
                &r.publisher,
                &r.delta_id,
                &r.observed_at,
                &r.title,
                &r.abstract_text,
                &r.lang,
                rank as i64,
            ),
        )
        .unwrap();
    }
    conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])
        .unwrap();
    drop(conn);
    let bytes = std::fs::read(&path).unwrap();
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        let file = files_mut(manifest)
            .iter_mut()
            .find(|f| f["path"] == "shard-0/tier0/index.sqlite")
            .unwrap();
        file["sha256"] = hex_encode(&Sha256::digest(&bytes)).into();
        file["bytes"] = (bytes.len() as u64).into();
    });
    let target = tempfile::tempdir().unwrap();

    cold_start(&sharded, target.path()).unwrap();

    assert_serves_every_record(&sharded, target.path());
}

/// WIST-3 §6.
#[test]
fn a_listed_path_with_a_dot_dot_segment_is_wist3_e04() {
    let sharded = build_sharded_fixture(2, false, None);
    rewrite_manifest(&sharded.manifest_path, &sharded.fx.log, |manifest| {
        let file = files_mut(manifest)
            .iter_mut()
            .find(|f| f["path"] == "shard-0/tier1/links.parquet")
            .unwrap();
        file["path"] = "shard-0/../../../log/anchor.json".into();
    });

    let error = refused(&sharded);

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(
        error.contains("shard-0/../../../log/anchor.json"),
        "{error}"
    );
}

/// WIST-3 §6.
#[test]
fn a_listed_state_path_with_a_leading_slash_is_wist3_e04() {
    let fx = common::build_fixture(true, false);
    let path = common::snapshot_dir(fx.dir.path(), &fx.snapshot_date, 0).join("manifest.json");
    rewrite_manifest(&path, &fx.log, |manifest| {
        manifest["state"]["path"] = "/log/anchor.json".into();
    });
    let target = tempfile::tempdir().unwrap();

    let error = graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .expect_err("the state path leaves the Snapshot directory")
    .to_string();

    assert!(error.contains("WIST3-E04"), "{error}");
    assert!(error.contains("/log/anchor.json"), "{error}");
}
