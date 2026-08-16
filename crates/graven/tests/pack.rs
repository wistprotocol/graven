mod common;

use rusqlite::Connection;

fn read_sync_state(target: &std::path::Path) -> (String, u64) {
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::synced_log_dir(target).join("sync.json")).unwrap(),
    )
    .unwrap();
    (
        value["content_digest"].as_str().unwrap().to_string(),
        value["log_position"].as_u64().unwrap(),
    )
}

fn embeddings_count(target: &std::path::Path) -> i64 {
    let conn = Connection::open(common::synced_log_dir(target).join("index.sqlite")).unwrap();
    conn.query_row("SELECT COUNT(*) FROM embeddings", [], |r| r.get(0))
        .unwrap()
}

fn alpha_beta_ids() -> (String, String) {
    let publisher = common::Signer::new([1u8; 32]);
    let (alpha_id, _, _) = common::build_delta(
        &publisher,
        "pk1",
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    let (beta_id, _, _) = common::build_delta(
        &publisher,
        "pk1",
        "https://records.example/beta",
        "Beta Title",
        Some("Beta abstract"),
        "beta body",
        None,
    );
    (alpha_id, beta_id)
}

fn sync_fixture() -> (common::Fixture, tempfile::TempDir) {
    let fx = common::build_fixture(true, false);
    let target = tempfile::tempdir().unwrap();
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();
    (fx, target)
}

#[test]
fn happy_import_over_synced_fixture() {
    let (fx, target) = sync_fixture();
    let (alpha_id, beta_id) = alpha_beta_ids();
    let (content_digest, log_position) = read_sync_state(target.path());

    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[
            (
                alpha_id.as_str(),
                "https://records.example/alpha",
                fx.domain.as_str(),
                vec![0.1, 0.2, 0.3],
            ),
            (
                beta_id.as_str(),
                "https://records.example/beta",
                fx.domain.as_str(),
                vec![0.4, 0.5, 0.6],
            ),
        ],
        3,
        "cosine",
    );

    let report = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.log.public_b64u(),
    )
    .unwrap();

    assert_eq!(report.imported, 2);
    assert_eq!(report.skipped, 0);
    assert_eq!(embeddings_count(target.path()), 2);
}

#[test]
fn wrong_key_rejects_and_writes_nothing() {
    let (fx, target) = sync_fixture();
    let (alpha_id, _) = alpha_beta_ids();
    let (content_digest, log_position) = read_sync_state(target.path());

    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[(
            alpha_id.as_str(),
            "https://records.example/alpha",
            fx.domain.as_str(),
            vec![0.1, 0.2, 0.3],
        )],
        3,
        "cosine",
    );

    let result = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.other.public_b64u(),
    );
    assert!(result.is_err());

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    assert!(conn
        .query_row("SELECT COUNT(*) FROM embeddings", [], |r| r
            .get::<_, i64>(0))
        .is_err());
}

#[test]
fn digest_mismatch_rejects() {
    let (fx, target) = sync_fixture();
    let (alpha_id, _) = alpha_beta_ids();
    let (_, log_position) = read_sync_state(target.path());

    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        &format!("sha256:{}", "0".repeat(64)),
        log_position,
        &[(
            alpha_id.as_str(),
            "https://records.example/alpha",
            fx.domain.as_str(),
            vec![0.1, 0.2, 0.3],
        )],
        3,
        "cosine",
    );

    let result = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.log.public_b64u(),
    );
    assert!(result.is_err());
}

#[test]
fn tampered_vectors_file_rejects() {
    let (fx, target) = sync_fixture();
    let (alpha_id, _) = alpha_beta_ids();
    let (content_digest, log_position) = read_sync_state(target.path());

    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[(
            alpha_id.as_str(),
            "https://records.example/alpha",
            fx.domain.as_str(),
            vec![0.1, 0.2, 0.3],
        )],
        3,
        "cosine",
    );

    let vectors_path = pack_dir.path().join("vectors.jsonl.zst");
    let mut bytes = std::fs::read(&vectors_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&vectors_path, bytes).unwrap();

    let result = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.log.public_b64u(),
    );
    assert!(result.is_err());
}

#[test]
fn dim_mismatch_row_rejects() {
    let (fx, target) = sync_fixture();
    let (alpha_id, _) = alpha_beta_ids();
    let (content_digest, log_position) = read_sync_state(target.path());

    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[(
            alpha_id.as_str(),
            "https://records.example/alpha",
            fx.domain.as_str(),
            vec![0.1, 0.2],
        )],
        3,
        "cosine",
    );

    let result = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.log.public_b64u(),
    );
    assert!(result.is_err());
}

#[test]
fn unknown_delta_id_is_skipped_others_import() {
    let (fx, target) = sync_fixture();
    let (alpha_id, _) = alpha_beta_ids();
    let (content_digest, log_position) = read_sync_state(target.path());
    let unknown_id = format!("sha256:{}", "f".repeat(64));

    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[
            (
                alpha_id.as_str(),
                "https://records.example/alpha",
                fx.domain.as_str(),
                vec![0.1, 0.2, 0.3],
            ),
            (
                unknown_id.as_str(),
                "https://records.example/unknown",
                fx.domain.as_str(),
                vec![0.7, 0.8, 0.9],
            ),
        ],
        3,
        "cosine",
    );

    let report = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.log.public_b64u(),
    )
    .unwrap();

    assert_eq!(report.imported, 1);
    assert_eq!(report.skipped, 1);
}

#[test]
fn all_unknown_delta_ids_rejects() {
    let (fx, target) = sync_fixture();
    let (content_digest, log_position) = read_sync_state(target.path());
    let unknown1 = format!("sha256:{}", "e".repeat(64));
    let unknown2 = format!("sha256:{}", "f".repeat(64));

    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[
            (
                unknown1.as_str(),
                "https://records.example/u1",
                fx.domain.as_str(),
                vec![0.1, 0.2, 0.3],
            ),
            (
                unknown2.as_str(),
                "https://records.example/u2",
                fx.domain.as_str(),
                vec![0.4, 0.5, 0.6],
            ),
        ],
        3,
        "cosine",
    );

    let err = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.log.public_b64u(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("pack matches no local record"),
        "error was: {err}"
    );
}

#[test]
fn re_import_replaces_prior_embeddings() {
    let (fx, target) = sync_fixture();
    let (alpha_id, beta_id) = alpha_beta_ids();
    let (content_digest, log_position) = read_sync_state(target.path());

    let pack_dir1 = tempfile::tempdir().unwrap();
    let pack_path1 = common::build_pack(
        pack_dir1.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[
            (
                alpha_id.as_str(),
                "https://records.example/alpha",
                fx.domain.as_str(),
                vec![0.1, 0.2, 0.3],
            ),
            (
                beta_id.as_str(),
                "https://records.example/beta",
                fx.domain.as_str(),
                vec![0.4, 0.5, 0.6],
            ),
        ],
        3,
        "cosine",
    );
    let report1 = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path1,
        &fx.log.public_b64u(),
    )
    .unwrap();
    assert_eq!(report1.imported, 2);
    assert_eq!(embeddings_count(target.path()), 2);

    let pack_dir2 = tempfile::tempdir().unwrap();
    let pack_path2 = common::build_pack(
        pack_dir2.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[(
            alpha_id.as_str(),
            "https://records.example/alpha",
            fx.domain.as_str(),
            vec![0.9, 0.9, 0.9],
        )],
        3,
        "cosine",
    );
    let report2 = graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path2,
        &fx.log.public_b64u(),
    )
    .unwrap();
    assert_eq!(report2.imported, 1);
    assert_eq!(embeddings_count(target.path()), 1);
}

#[test]
fn withdrawal_purges_embedding_row() {
    let (fx, target) = sync_fixture();
    let (alpha_id, beta_id) = alpha_beta_ids();
    let (content_digest, log_position) = read_sync_state(target.path());

    let pack_dir = tempfile::tempdir().unwrap();
    let pack_path = common::build_pack(
        pack_dir.path(),
        &fx.log,
        &content_digest,
        log_position,
        &[
            (
                alpha_id.as_str(),
                "https://records.example/alpha",
                fx.domain.as_str(),
                vec![0.1, 0.2, 0.3],
            ),
            (
                beta_id.as_str(),
                "https://records.example/beta",
                fx.domain.as_str(),
                vec![0.4, 0.5, 0.6],
            ),
        ],
        3,
        "cosine",
    );
    graven::pack::import(
        target.path(),
        "graven-test-log",
        &pack_path,
        &fx.log.public_b64u(),
    )
    .unwrap();
    assert_eq!(embeddings_count(target.path()), 2);

    common::extend_fixture_with_withdrawal(&fx, &alpha_id);
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target.path(),
        true,
        false,
    )
    .unwrap();

    let conn =
        Connection::open(common::synced_log_dir(target.path()).join("index.sqlite")).unwrap();
    let alpha_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM embeddings WHERE delta_id = ?1",
            [&alpha_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(alpha_rows, 0);
    assert_eq!(embeddings_count(target.path()), 1);
}
