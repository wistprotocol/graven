use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use wist_core::crypto::{b64u_encode, hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::objects::{
    AggregatorKeyEntry, Anchor, Checkpoint, DeclarationEntry, GenesisKey, ParameterEntry,
    RecordEntry, SnapshotFile, SnapshotIndex, SnapshotIndexEntry, SnapshotManifest, SnapshotState,
    SnapshotStateFile, StateEntry,
};
use wist_core::{jcs, merkle};

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

pub struct Signer {
    pub seed: [u8; 32],
    pub sk: SigningKey,
}

impl Signer {
    pub fn new(seed: [u8; 32]) -> Self {
        Signer {
            seed,
            sk: SigningKey::from_seed(&seed),
        }
    }

    pub fn public_b64u(&self) -> String {
        b64u_encode(
            &ed25519_dalek::SigningKey::from_bytes(&self.seed)
                .verifying_key()
                .to_bytes(),
        )
    }
}

#[derive(Clone)]
pub struct RecordFixture {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub observed_at: String,
    pub weight: String,
    pub title: String,
    pub abstract_text: Option<String>,
    pub lang: String,
}

fn record_projection(r: &RecordFixture) -> Value {
    serde_json::json!({
        "url": r.url,
        "publisher": r.publisher,
        "delta_id": r.delta_id,
        "observed_at": r.observed_at,
        "weight": r.weight,
    })
}

pub fn write_anchor(path: &Path, log: &Signer, log_id: &str) {
    let anchor = Anchor {
        wist_version: "1.0.0".into(),
        log_id: log_id.into(),
        genesis_key: GenesisKey {
            key_id: "log1".into(),
            alg: "Ed25519".into(),
            public_key: log.public_b64u(),
        },
        created_at: "2026-08-09T00:00:00Z".into(),
        predecessor: None,
    };
    let value = serde_json::to_value(&anchor).unwrap();
    let env = sign_envelope(&value, "anchor", "log1", &log.sk).unwrap();
    std::fs::write(path, serde_json::to_vec(&env).unwrap()).unwrap();
}

pub fn build_declaration_full(
    signing: &Signer,
    signing_key_id: &str,
    domain: &str,
    seq: u64,
    prev: Option<&str>,
    keys: &[(&str, &Signer, &str)],
) -> Value {
    let key_entries: Vec<Value> = keys
        .iter()
        .map(|(key_id, signer, valid_from)| {
            serde_json::json!({
                "key_id": key_id,
                "alg": "Ed25519",
                "public_key": signer.public_b64u(),
                "valid_from": valid_from,
            })
        })
        .collect();
    let mut doc = serde_json::json!({
        "wist_version": "1.0.0",
        "domain": domain,
        "keys": key_entries,
        "seq": seq,
    });
    if let Some(p) = prev {
        doc["prev_declaration"] = p.into();
    }
    sign_envelope(&doc, "publisher", signing_key_id, &signing.sk).unwrap()
}

pub fn build_declaration(publisher: &Signer, key_id: &str, domain: &str) -> Value {
    build_declaration_full(
        publisher,
        key_id,
        domain,
        0,
        None,
        &[(key_id, publisher, "2026-08-09T00:00:00Z")],
    )
}

pub fn declaration_hash(envelope: &Value) -> String {
    let canon = jcs::canonicalize(&envelope["publisher"]).unwrap();
    format!("sha256:{}", hex_encode(&Sha256::digest(&canon)))
}

pub fn build_delta(
    publisher: &Signer,
    key_id: &str,
    url: &str,
    title: &str,
    abstract_text: Option<&str>,
    extract: &str,
    prev: Option<&str>,
) -> (String, Value, Value) {
    let salt = b64u_encode(&[5u8; 16]);
    let mut summary = serde_json::json!({"title": title});
    if let Some(a) = abstract_text {
        summary["abstract"] = a.into();
    }
    let content = serde_json::json!({
        "extract": extract,
        "links": {"total": 0, "urls": []},
        "summary": summary,
    });
    let payload = serde_json::json!({
        "wist_version": "1.0.0",
        "salt": salt,
        "content": content,
    });
    let commitment = wist_core::delta::make_commitment(&salt, &content).unwrap();
    let bytes = wist_core::delta::content_bytes(&content).unwrap();
    let mut delta = serde_json::json!({
        "wist_version": "1.0.0",
        "url": url,
        "change_type": if prev.is_some() { "update" } else { "new" },
        "observed_at": "2026-08-09T12:00:00Z",
        "payload": {"commitment": commitment, "alg": "HMAC-SHA256", "bytes": bytes},
        "meta": {"lang": "en"},
    });
    if let Some(p) = prev {
        delta["prev"] = p.into();
    }
    let id = wist_core::delta::delta_id(&delta).unwrap();
    let env = sign_envelope(&delta, "delta", key_id, &publisher.sk).unwrap();
    (id, env, payload)
}

pub fn write_payload(dir: &Path, hex: &str, payload: &Value) {
    let payloads_dir = dir.join("payloads");
    std::fs::create_dir_all(&payloads_dir).unwrap();
    std::fs::write(
        payloads_dir.join(format!("{hex}.json")),
        serde_json::to_vec(payload).unwrap(),
    )
    .unwrap();
}

pub fn build_block(
    log: &Signer,
    block_number: u64,
    prev_block_hash: &str,
    sealed_at: &str,
    wrapped_entries: &[Value],
) -> (Value, String) {
    let leaves: Vec<[u8; 32]> = wrapped_entries
        .iter()
        .map(|e| merkle::leaf_hash(&jcs::canonicalize(e).unwrap()))
        .collect();
    let root = if leaves.is_empty() {
        merkle::leaf_hash(&[])
    } else {
        merkle::merkle_root(&leaves).unwrap()
    };
    let header = serde_json::json!({
        "wist_version": "1.0.0",
        "block_number": block_number,
        "prev_block_hash": prev_block_hash,
        "sealed_at": sealed_at,
        "merkle_root": format!("sha256:{}", hex_encode(&root)),
        "entry_count": wrapped_entries.len() as u64,
    });
    let sig_value = log.sk.sign(&jcs::canonicalize(&header).unwrap());
    let block_hash = wist_core::block::block_hash(&header).unwrap();
    let block = serde_json::json!({
        "header": header,
        "entries": wrapped_entries,
        "sig": {"key_id": "log1", "alg": "Ed25519", "value": sig_value},
    });
    (block, block_hash)
}

pub fn write_block(dir: &Path, block_number: u64, block: &Value) {
    let blocks_dir = dir.join("log/blocks");
    std::fs::create_dir_all(&blocks_dir).unwrap();
    let bytes = serde_json::to_vec(block).unwrap();
    let compressed = zstd::encode_all(bytes.as_slice(), 0).unwrap();
    std::fs::write(
        blocks_dir.join(format!("{block_number:09}.json.zst")),
        compressed,
    )
    .unwrap();
}

pub fn write_checkpoint(
    dir: &Path,
    log: &Signer,
    block_number: u64,
    block_hash: &str,
    sealed_at: &str,
) {
    let checkpoint = Checkpoint {
        wist_version: "1.0.0".into(),
        block_number,
        block_hash: block_hash.into(),
        sealed_at: sealed_at.into(),
    };
    let value = serde_json::to_value(&checkpoint).unwrap();
    let env = sign_envelope(&value, "checkpoint", "log1", &log.sk).unwrap();
    let path = dir.join("log/checkpoint.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(&env).unwrap()).unwrap();
}

pub fn write_tier0(path: &Path, records: &[RecordFixture]) -> Vec<u8> {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE records(url TEXT, publisher TEXT, delta_id TEXT, observed_at TEXT, weight TEXT, title TEXT, abstract TEXT, lang TEXT);
         CREATE VIRTUAL TABLE records_fts USING fts5(title, abstract, content=records, content_rowid=rowid);",
    )
    .unwrap();
    for r in records {
        conn.execute(
            "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (&r.url, &r.publisher, &r.delta_id, &r.observed_at, &r.weight, &r.title, &r.abstract_text, &r.lang),
        )
        .unwrap();
    }
    conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])
        .unwrap();
    drop(conn);
    std::fs::read(path).unwrap()
}

fn write_parquet(
    message_type: &str,
    byte_columns: &[Vec<Vec<u8>>],
    int_column: Option<&[i64]>,
) -> Vec<u8> {
    let schema = Arc::new(parse_message_type(message_type).unwrap());
    let mut writer = SerializedFileWriter::new(
        Vec::new(),
        schema,
        Arc::new(WriterProperties::builder().build()),
    )
    .unwrap();
    let mut rg = writer.next_row_group().unwrap();
    for column in byte_columns {
        let mut col = rg.next_column().unwrap().unwrap();
        let values: Vec<ByteArray> = column.iter().map(|v| ByteArray::from(v.clone())).collect();
        col.typed::<ByteArrayType>()
            .write_batch(&values, None, None)
            .unwrap();
        col.close().unwrap();
    }
    if let Some(ints) = int_column {
        let mut col = rg.next_column().unwrap().unwrap();
        col.typed::<Int64Type>()
            .write_batch(ints, None, None)
            .unwrap();
        col.close().unwrap();
    }
    rg.close().unwrap();
    writer.into_inner().unwrap()
}

pub fn write_extracts_parquet(rows: &[(&str, &str, &str, &str)]) -> Vec<u8> {
    write_parquet(
        "message extracts { required binary url (UTF8); required binary publisher (UTF8); required binary delta_id (UTF8); required binary extract (UTF8); }",
        &[
            rows.iter().map(|r| r.0.as_bytes().to_vec()).collect(),
            rows.iter().map(|r| r.1.as_bytes().to_vec()).collect(),
            rows.iter().map(|r| r.2.as_bytes().to_vec()).collect(),
            rows.iter().map(|r| r.3.as_bytes().to_vec()).collect(),
        ],
        None,
    )
}

pub fn write_links_parquet(rows: &[(&str, &str, i64)]) -> Vec<u8> {
    write_parquet(
        "message links { required binary source_url (UTF8); required binary target_url (UTF8); required int64 position; }",
        &[
            rows.iter().map(|r| r.0.as_bytes().to_vec()).collect(),
            rows.iter().map(|r| r.1.as_bytes().to_vec()).collect(),
        ],
        Some(&rows.iter().map(|r| r.2).collect::<Vec<_>>()),
    )
}

pub fn write_state(
    path: &Path,
    log: &Signer,
    cadence: i64,
    declarations: &[(String, Value)],
    records: &[RecordFixture],
    log_position: u64,
) -> (Vec<u8>, String) {
    let mut entries = Vec::new();
    entries.push(StateEntry::AggregatorKey(AggregatorKeyEntry {
        key_id: "log1".into(),
        public_key: log.public_b64u(),
        added_height: 0,
        removed_height: None,
    }));
    entries.push(StateEntry::Parameter(ParameterEntry {
        name: "block_cadence_seconds".into(),
        value: cadence,
        effective_height: 0,
    }));
    for (domain, declaration) in declarations {
        entries.push(StateEntry::Declaration(DeclarationEntry {
            domain: domain.clone(),
            declaration: declaration.clone(),
            sealing_height: 0,
        }));
    }
    for r in records {
        entries.push(StateEntry::Record(RecordEntry {
            publisher: r.publisher.clone(),
            url: r.url.clone(),
            delta_id: r.delta_id.clone(),
        }));
    }
    let state = SnapshotState {
        wist_version: "1.0.0".into(),
        log_position,
        entries,
    };
    let entry_values: Vec<Value> = state
        .entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    let state_digest = wist_core::snapshot::state_digest(&entry_values).unwrap();

    let state_value = serde_json::to_value(&state).unwrap();
    let env = sign_envelope(&state_value, "state", "log1", &log.sk).unwrap();
    let bytes = serde_json::to_vec(&env).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, &bytes).unwrap();
    (bytes, state_digest)
}

#[allow(clippy::too_many_arguments)]
fn write_manifest_with_files(
    path: &Path,
    log: &Signer,
    snapshot_date: &str,
    log_position: u64,
    anchor_block_hash: &str,
    content_digest_value: &str,
    state_bytes: &[u8],
    state_digest_value: &str,
    sqlite_bytes: &[u8],
    extra_files: &[(String, Vec<u8>, u8)],
) {
    let mut files = vec![SnapshotFile {
        path: "tier0/index.sqlite".into(),
        sha256: sha256_hex(sqlite_bytes),
        bytes: sqlite_bytes.len() as u64,
        tier: 0,
        shard: None,
    }];
    for (file_path, bytes, tier) in extra_files {
        files.push(SnapshotFile {
            path: file_path.clone(),
            sha256: sha256_hex(bytes),
            bytes: bytes.len() as u64,
            tier: *tier,
            shard: None,
        });
    }
    let manifest = SnapshotManifest {
        wist_version: "1.0.0".into(),
        snapshot_date: snapshot_date.into(),
        log_position,
        anchor_block_hash: anchor_block_hash.into(),
        content_digest: content_digest_value.into(),
        state: SnapshotStateFile {
            path: "state.json".into(),
            sha256: sha256_hex(state_bytes),
            bytes: state_bytes.len() as u64,
            state_digest: state_digest_value.into(),
        },
        shards: None,
        files,
    };
    let value = serde_json::to_value(&manifest).unwrap();
    let env = sign_envelope(&value, "manifest", "log1", &log.sk).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(&env).unwrap()).unwrap();
}

#[allow(clippy::too_many_arguments)]
pub fn write_manifest(
    path: &Path,
    log: &Signer,
    snapshot_date: &str,
    log_position: u64,
    anchor_block_hash: &str,
    content_digest_value: &str,
    state_bytes: &[u8],
    state_digest_value: &str,
    sqlite_bytes: &[u8],
) {
    write_manifest_with_files(
        path,
        log,
        snapshot_date,
        log_position,
        anchor_block_hash,
        content_digest_value,
        state_bytes,
        state_digest_value,
        sqlite_bytes,
        &[],
    );
}

#[allow(clippy::too_many_arguments)]
pub fn write_manifest_with_tier1(
    path: &Path,
    log: &Signer,
    snapshot_date: &str,
    log_position: u64,
    anchor_block_hash: &str,
    content_digest_value: &str,
    state_bytes: &[u8],
    state_digest_value: &str,
    sqlite_bytes: &[u8],
    tier1_files: &[(String, Vec<u8>, u8)],
) {
    write_manifest_with_files(
        path,
        log,
        snapshot_date,
        log_position,
        anchor_block_hash,
        content_digest_value,
        state_bytes,
        state_digest_value,
        sqlite_bytes,
        tier1_files,
    );
}

pub fn write_index(
    path: &Path,
    log: &Signer,
    snapshot_date: &str,
    log_position: u64,
    manifest_url: &str,
    content_digest_value: &str,
) {
    let index = SnapshotIndex {
        wist_version: "1.0.0".into(),
        updated_at: "2026-08-09T12:05:00Z".into(),
        snapshots: vec![SnapshotIndexEntry {
            snapshot_date: snapshot_date.into(),
            log_position,
            manifest_url: manifest_url.into(),
            content_digest: content_digest_value.into(),
        }],
    };
    let value = serde_json::to_value(&index).unwrap();
    let env = sign_envelope(&value, "index", "log1", &log.sk).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(&env).unwrap()).unwrap();
}

pub fn corrupt_manifest_content_digest(dir: &Path, log: &Signer, snapshot_date: &str) {
    let path = dir
        .join("snapshots")
        .join(snapshot_date)
        .join("manifest.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut manifest = doc["manifest"].clone();
    manifest["content_digest"] = serde_json::json!(format!("sha256:{}", "0".repeat(64)));
    let env = sign_envelope(&manifest, "manifest", "log1", &log.sk).unwrap();
    std::fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();
}

pub fn corrupt_state_digest(dir: &Path, log: &Signer, snapshot_date: &str) {
    let path = dir
        .join("snapshots")
        .join(snapshot_date)
        .join("manifest.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut manifest = doc["manifest"].clone();
    manifest["state"]["state_digest"] = serde_json::json!(format!("sha256:{}", "0".repeat(64)));
    let env = sign_envelope(&manifest, "manifest", "log1", &log.sk).unwrap();
    std::fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();
}

pub fn resign_state_with_wrong_key(dir: &Path, log: &Signer, other: &Signer, snapshot_date: &str) {
    let snapdir = dir.join("snapshots").join(snapshot_date);

    let state_path = snapdir.join("state.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    let state = doc["state"].clone();
    let env = sign_envelope(&state, "state", "log1", &other.sk).unwrap();
    let new_state_bytes = serde_json::to_vec(&env).unwrap();
    std::fs::write(&state_path, &new_state_bytes).unwrap();

    let manifest_path = snapdir.join("manifest.json");
    let mdoc: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let mut manifest = mdoc["manifest"].clone();
    manifest["state"]["sha256"] = serde_json::json!(sha256_hex(&new_state_bytes));
    manifest["state"]["bytes"] = serde_json::json!(new_state_bytes.len() as u64);
    let menv = sign_envelope(&manifest, "manifest", "log1", &log.sk).unwrap();
    std::fs::write(&manifest_path, serde_json::to_vec(&menv).unwrap()).unwrap();
}

pub fn resign_checkpoint_with_wrong_key(dir: &Path, other: &Signer) {
    let path = dir.join("log/checkpoint.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let checkpoint = doc["checkpoint"].clone();
    let env = sign_envelope(&checkpoint, "checkpoint", "log1", &other.sk).unwrap();
    std::fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();
}

pub fn extend_fixture(fx: &Fixture) -> String {
    let publisher = Signer::new([1u8; 32]);
    let checkpoint_path = fx.dir.path().join("log/checkpoint.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    let prev_number = doc["checkpoint"]["block_number"].as_u64().unwrap();
    let prev_hash = doc["checkpoint"]["block_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let next_number = prev_number + 1;

    let url = format!("https://records.example/extra-{next_number}");
    let (id, delta_env, payload) = build_delta(
        &publisher,
        "pk1",
        &url,
        "Extra Title",
        Some("Extra abstract"),
        "extra body",
        None,
    );
    let hex = id.strip_prefix("sha256:").unwrap();
    write_payload(fx.dir.path(), hex, &payload);
    let wrapped_delta = serde_json::json!({"type": "publisher_delta", "body": delta_env});

    let sealed_at = format!("2026-08-09T{:02}:00:00Z", 14 + next_number);
    let (block, new_hash) = build_block(
        &fx.log,
        next_number,
        &prev_hash,
        &sealed_at,
        &[wrapped_delta],
    );
    write_block(fx.dir.path(), next_number, &block);
    write_checkpoint(fx.dir.path(), &fx.log, next_number, &new_hash, &sealed_at);

    url
}

pub fn build_delete_delta(
    publisher: &Signer,
    key_id: &str,
    url: &str,
    prev: &str,
) -> (String, Value) {
    let delta = serde_json::json!({
        "wist_version": "1.0.0",
        "url": url,
        "change_type": "delete",
        "observed_at": "2026-08-09T15:00:00Z",
        "prev": prev,
        "meta": {"lang": "en"},
    });
    let id = wist_core::delta::delta_id(&delta).unwrap();
    (
        id,
        sign_envelope(&delta, "delta", key_id, &publisher.sk).unwrap(),
    )
}

pub fn extend_fixture_with_withdrawal(fx: &Fixture, delta_id: &str) {
    let checkpoint_path = fx.dir.path().join("log/checkpoint.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    let prev_number = doc["checkpoint"]["block_number"].as_u64().unwrap();
    let prev_hash = doc["checkpoint"]["block_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let next_number = prev_number + 1;

    let update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "payload_withdrawal",
        "subject": fx.domain,
        "details": {"delta_id": delta_id, "legal_basis": "court order", "jurisdiction": "EU"},
        "effective_at": "2026-08-09T15:00:00Z",
    });
    let body = sign_envelope(&update, "update", "log1", &fx.log.sk).unwrap();
    let wrapped = serde_json::json!({"type": "registry_update", "body": body});

    let sealed_at = format!("2026-08-09T{:02}:00:00Z", 14 + next_number);
    let (block, new_hash) = build_block(&fx.log, next_number, &prev_hash, &sealed_at, &[wrapped]);
    write_block(fx.dir.path(), next_number, &block);
    write_checkpoint(fx.dir.path(), &fx.log, next_number, &new_hash, &sealed_at);
}

pub fn extend_fixture_with_delete(fx: &Fixture, url: &str, prev: &str) {
    let publisher = Signer::new([1u8; 32]);
    let checkpoint_path = fx.dir.path().join("log/checkpoint.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    let prev_number = doc["checkpoint"]["block_number"].as_u64().unwrap();
    let prev_hash = doc["checkpoint"]["block_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let next_number = prev_number + 1;

    let (_id, delta_env) = build_delete_delta(&publisher, "pk1", url, prev);
    let wrapped_delta = serde_json::json!({"type": "publisher_delta", "body": delta_env});

    let sealed_at = format!("2026-08-09T{:02}:00:00Z", 14 + next_number);
    let (block, new_hash) = build_block(
        &fx.log,
        next_number,
        &prev_hash,
        &sealed_at,
        &[wrapped_delta],
    );
    write_block(fx.dir.path(), next_number, &block);
    write_checkpoint(fx.dir.path(), &fx.log, next_number, &new_hash, &sealed_at);
}

pub fn extend_fixture_with_forged_delta(fx: &Fixture) {
    let attacker = Signer::new([7u8; 32]);
    let checkpoint_path = fx.dir.path().join("log/checkpoint.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    let prev_number = doc["checkpoint"]["block_number"].as_u64().unwrap();
    let prev_hash = doc["checkpoint"]["block_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let next_number = prev_number + 1;

    let url = format!("https://records.example/extra-{next_number}");
    let (_id, delta_env, _payload) = build_delta(
        &attacker,
        "pk1",
        &url,
        "Extra Title",
        Some("Extra abstract"),
        "extra body",
        None,
    );
    let wrapped_delta = serde_json::json!({"type": "publisher_delta", "body": delta_env});

    let sealed_at = format!("2026-08-09T{:02}:00:00Z", 14 + next_number);
    let (block, new_hash) = build_block(
        &fx.log,
        next_number,
        &prev_hash,
        &sealed_at,
        &[wrapped_delta],
    );
    write_block(fx.dir.path(), next_number, &block);
    write_checkpoint(fx.dir.path(), &fx.log, next_number, &new_hash, &sealed_at);
}

pub fn extend_fixture_with_rotation(fx: &Fixture, new_key: &Signer) -> String {
    let old = Signer::new([1u8; 32]);
    let checkpoint_path = fx.dir.path().join("log/checkpoint.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    let prev_number = doc["checkpoint"]["block_number"].as_u64().unwrap();
    let prev_hash = doc["checkpoint"]["block_hash"]
        .as_str()
        .unwrap()
        .to_string();

    let decl0 = build_declaration(&old, "pk1", &fx.domain);
    let hash0 = declaration_hash(&decl0);

    let rotation_number = prev_number + 1;
    let rotation_decl = build_declaration_full(
        &old,
        "pk1",
        &fx.domain,
        1,
        Some(&hash0),
        &[("pk2", new_key, "2026-08-09T00:00:00Z")],
    );
    let wrapped_decl = serde_json::json!({"type": "publisher_declaration", "body": rotation_decl});
    let sealed_at1 = format!("2026-08-09T{:02}:00:00Z", 14 + rotation_number);
    let (block1, hash1) = build_block(
        &fx.log,
        rotation_number,
        &prev_hash,
        &sealed_at1,
        &[wrapped_decl],
    );
    write_block(fx.dir.path(), rotation_number, &block1);
    write_checkpoint(fx.dir.path(), &fx.log, rotation_number, &hash1, &sealed_at1);

    let delta_number = rotation_number + 1;
    let url = format!("https://records.example/extra-{delta_number}");
    let (id, delta_env, payload) = build_delta(
        new_key,
        "pk2",
        &url,
        "Rotated Title",
        Some("Rotated abstract"),
        "rotated body",
        None,
    );
    let hex = id.strip_prefix("sha256:").unwrap();
    write_payload(fx.dir.path(), hex, &payload);
    let wrapped_delta = serde_json::json!({"type": "publisher_delta", "body": delta_env});
    let sealed_at2 = format!("2026-08-09T{:02}:00:00Z", 14 + delta_number);
    let (block2, hash2) = build_block(&fx.log, delta_number, &hash1, &sealed_at2, &[wrapped_delta]);
    write_block(fx.dir.path(), delta_number, &block2);
    write_checkpoint(fx.dir.path(), &fx.log, delta_number, &hash2, &sealed_at2);

    url
}

pub fn serve_static(dir: PathBuf) -> String {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            addr_tx.send(addr.to_string()).unwrap();
            let app =
                axum::Router::new().fallback_service(tower_http::services::ServeDir::new(dir));
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                .await
                .unwrap();
        });
    });
    addr_rx.recv().unwrap()
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub log: Signer,
    pub other: Signer,
    pub domain: String,
    pub snapshot_date: String,
    pub base_url: String,
}

impl Fixture {
    pub fn anchor_path(&self) -> PathBuf {
        self.dir.path().join("anchor.json")
    }
}

pub fn synced_log_dir(dir: &Path) -> PathBuf {
    dir.join("logs/graven-test-log")
}

pub fn build_fixture(write_second_payload: bool, duplicate_tier0_record: bool) -> Fixture {
    build_fixture_full(
        "graven-test-log",
        9,
        write_second_payload,
        duplicate_tier0_record,
        false,
    )
}

pub fn build_fixture_with_log_id(log_id: &str, seed: u8) -> Fixture {
    build_fixture_full(log_id, seed, true, false, false)
}

pub fn build_fixture_with_tier1() -> Fixture {
    build_fixture_full("graven-test-log", 9, true, false, true)
}

fn build_fixture_full(
    log_id: &str,
    seed: u8,
    write_second_payload: bool,
    duplicate_tier0_record: bool,
    include_tier1: bool,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let log = Signer::new([seed; 32]);
    let other = Signer::new([3u8; 32]);
    let publisher = Signer::new([1u8; 32]);
    let domain = "records.example".to_string();
    let snapshot_date = "2026-08-09".to_string();

    write_anchor(&dir.path().join("anchor.json"), &log, log_id);

    let declaration_env = build_declaration(&publisher, "pk1", &domain);
    let wrapped_declaration =
        serde_json::json!({"type": "publisher_declaration", "body": declaration_env});

    let (id1, delta1_env, payload1) = build_delta(
        &publisher,
        "pk1",
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    let hex1 = id1.strip_prefix("sha256:").unwrap();
    write_payload(dir.path(), hex1, &payload1);
    let wrapped_delta1 = serde_json::json!({"type": "publisher_delta", "body": delta1_env});

    let (block0, block0_hash) = build_block(
        &log,
        0,
        "sha256:genesis",
        "2026-08-09T12:00:00Z",
        &[wrapped_declaration, wrapped_delta1],
    );
    write_block(dir.path(), 0, &block0);

    let record1 = RecordFixture {
        url: "https://records.example/alpha".into(),
        publisher: domain.clone(),
        delta_id: id1.clone(),
        observed_at: "2026-08-09T12:00:00Z".into(),
        weight: "full".into(),
        title: "Alpha Title".into(),
        abstract_text: Some("Alpha abstract".into()),
        lang: "en".into(),
    };

    let snapdir = dir.path().join("snapshots").join(&snapshot_date);
    let tier0_records: Vec<RecordFixture> = if duplicate_tier0_record {
        vec![record1.clone(), record1.clone()]
    } else {
        vec![record1.clone()]
    };
    let sqlite_bytes = write_tier0(&snapdir.join("tier0/index.sqlite"), &tier0_records);
    let content_digest_projections: Vec<Value> =
        tier0_records.iter().map(record_projection).collect();
    let content_digest_value =
        wist_core::snapshot::content_digest(&content_digest_projections).unwrap();

    let (state_bytes, state_digest_value) = write_state(
        &snapdir.join("state.json"),
        &log,
        3600,
        &[(domain.clone(), declaration_env.clone())],
        std::slice::from_ref(&record1),
        0,
    );

    if include_tier1 {
        let extracts_bytes = write_extracts_parquet(&[(
            record1.url.as_str(),
            record1.publisher.as_str(),
            record1.delta_id.as_str(),
            "alpha body",
        )]);
        let links_bytes =
            write_links_parquet(&[(record1.url.as_str(), "https://records.example/other", 0i64)]);
        std::fs::create_dir_all(snapdir.join("tier1")).unwrap();
        std::fs::write(snapdir.join("tier1/extracts.parquet"), &extracts_bytes).unwrap();
        std::fs::write(snapdir.join("tier1/links.parquet"), &links_bytes).unwrap();
        write_manifest_with_tier1(
            &snapdir.join("manifest.json"),
            &log,
            &snapshot_date,
            0,
            &block0_hash,
            &content_digest_value,
            &state_bytes,
            &state_digest_value,
            &sqlite_bytes,
            &[
                ("tier1/extracts.parquet".to_string(), extracts_bytes, 1u8),
                ("tier1/links.parquet".to_string(), links_bytes, 1u8),
            ],
        );
    } else {
        write_manifest(
            &snapdir.join("manifest.json"),
            &log,
            &snapshot_date,
            0,
            &block0_hash,
            &content_digest_value,
            &state_bytes,
            &state_digest_value,
            &sqlite_bytes,
        );
    }

    write_index(
        &dir.path().join("snapshots/index.json"),
        &log,
        &snapshot_date,
        0,
        &format!("/snapshots/{snapshot_date}/manifest.json"),
        &content_digest_value,
    );

    let (id2, delta2_env, payload2) = build_delta(
        &publisher,
        "pk1",
        "https://records.example/beta",
        "Beta Title",
        Some("Beta abstract"),
        "beta body",
        None,
    );
    let hex2 = id2.strip_prefix("sha256:").unwrap();
    if write_second_payload {
        write_payload(dir.path(), hex2, &payload2);
    }
    let wrapped_delta2 = serde_json::json!({"type": "publisher_delta", "body": delta2_env});

    let (block1, block1_hash) = build_block(
        &log,
        1,
        &block0_hash,
        "2026-08-09T13:00:00Z",
        &[wrapped_delta2],
    );
    write_block(dir.path(), 1, &block1);

    write_checkpoint(dir.path(), &log, 1, &block1_hash, "2026-08-09T13:00:00Z");

    let base_url = format!("http://{}", serve_static(dir.path().to_path_buf()));

    Fixture {
        dir,
        log,
        other,
        domain,
        snapshot_date,
        base_url,
    }
}
