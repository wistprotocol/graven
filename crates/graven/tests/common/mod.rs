#![allow(dead_code)]

use base64::Engine;
use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::{RefCell, RefMut};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use wist_core::checkpoint::Checkpoint as WistCheckpoint;
use wist_core::crypto::{b64u_encode, hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::objects::{
    AggregatorKeyEntry, Anchor, DeclarationEntry, GenesisKey, ParameterEntry, RecordEntry,
    SnapshotFile, SnapshotIndex, SnapshotIndexEntry, SnapshotManifest, SnapshotState,
    SnapshotStateFile, StateEntry,
};
use wist_core::tiles::TileSet;
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

    pub fn kid(&self) -> String {
        wist_core::objects::publisher::thumbprint(&self.public_b64u())
    }
}

pub fn key_entry(signer: &Signer, not_before: &str) -> Value {
    serde_json::to_value(wist_core::objects::PublisherKey::new(
        &signer.public_b64u(),
        wist_core::timestamp::log_seconds(not_before).unwrap() as u64,
        None,
    ))
    .unwrap()
}

#[derive(Clone)]
pub struct RecordFixture {
    pub url: String,
    pub publisher: String,
    pub delta_id: String,
    pub observed_at: String,
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
    })
}

/// WIST-3 §6 serves the Log's Anchor at `/log/anchor.json`, for
/// convenience only: it is a trust root because of how it was obtained,
/// never because of where it sits.
pub fn write_anchor(path: &Path, log: &Signer, log_id: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
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
    domain: &str,
    seq: u64,
    prev: Option<&str>,
    keys: &[(&Signer, &str)],
) -> Value {
    let key_entries: Vec<Value> = keys
        .iter()
        .map(|(signer, not_before)| key_entry(signer, not_before))
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
    sign_envelope(&doc, "publisher", &signing.kid(), &signing.sk).unwrap()
}

pub fn build_declaration(publisher: &Signer, domain: &str) -> Value {
    build_declaration_full(
        publisher,
        domain,
        0,
        None,
        &[(publisher, "2026-08-09T00:00:00Z")],
    )
}

pub fn declaration_hash(envelope: &Value) -> String {
    let canon = jcs::canonicalize(&envelope["publisher"]).unwrap();
    format!("sha256:{}", hex_encode(&Sha256::digest(&canon)))
}

pub fn build_delta(
    publisher: &Signer,
    url: &str,
    title: &str,
    abstract_text: Option<&str>,
    extract: &str,
    prev: Option<&str>,
) -> (String, Value, Value) {
    build_delta_with_links(publisher, url, title, abstract_text, extract, &[], prev)
}

#[allow(clippy::too_many_arguments)]
pub fn build_delta_with_links(
    publisher: &Signer,
    url: &str,
    title: &str,
    abstract_text: Option<&str>,
    extract: &str,
    links: &[&str],
    prev: Option<&str>,
) -> (String, Value, Value) {
    let salt = b64u_encode(&[5u8; 16]);
    let mut summary = serde_json::json!({"title": title});
    if let Some(a) = abstract_text {
        summary["abstract"] = a.into();
    }
    let content = serde_json::json!({
        "extract": extract,
        "links": {"total": links.len() as u64, "urls": links},
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
        "publisher": reqwest::Url::parse(url).unwrap().host_str().unwrap(),
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
    let env = sign_envelope(&delta, "delta", &publisher.kid(), &publisher.sk).unwrap();
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

/// A test Log: one growing RFC 6962 tree published as WIST-3 §6's static
/// surface — the head Checkpoint at `/checkpoint`, every Checkpoint under
/// `/log/checkpoints/`, the tree's hashes as tiles and its Entries as
/// entry bundles.
pub struct Log {
    pub dir: PathBuf,
    pub log: Signer,
    pub log_id: String,
    leaves: Vec<Vec<u8>>,
    hashes: Vec<[u8; 32]>,
    pub checkpoints: Vec<WistCheckpoint>,
}

pub struct Witness {
    pub name: String,
    pub key: SigningKey,
}

impl Witness {
    pub fn new(name: &str, seed: [u8; 32]) -> Self {
        Witness {
            name: name.to_string(),
            key: SigningKey::from_seed(&seed),
        }
    }

    pub fn verifier_key(&self) -> String {
        let mut encoded = vec![wist_core::checkpoint::WITNESS_KEY_TYPE];
        encoded.extend_from_slice(&self.key.public().to_bytes());
        format!(
            "{}+{}+{}",
            self.name,
            hex_encode(&wist_core::checkpoint::witness_key_id(
                &self.name,
                &self.key.public()
            )),
            base64::engine::general_purpose::STANDARD.encode(&encoded)
        )
    }
}

impl Log {
    pub fn new(dir: &Path, log: Signer, log_id: &str) -> Log {
        write_anchor(&dir.join("log/anchor.json"), &log, log_id);
        Log::empty(dir, log, log_id)
    }

    /// A Log whose Anchor another party wrote, as a spec vector's does.
    pub fn empty(dir: &Path, log: Signer, log_id: &str) -> Log {
        Log {
            dir: dir.to_path_buf(),
            log,
            log_id: log_id.to_string(),
            leaves: Vec::new(),
            hashes: Vec::new(),
            checkpoints: Vec::new(),
        }
    }

    /// Publishes an Epoch whose Checkpoint another party signed, keeping
    /// the note verbatim.
    pub fn adopt(&mut self, note: &str, entries: &[Value]) {
        for entry in entries {
            let bytes = jcs::canonicalize(entry).expect("entry canonicalizes");
            self.hashes.push(merkle::leaf_hash(&bytes));
            self.leaves.push(bytes);
        }
        self.checkpoints
            .push(WistCheckpoint::parse(note).expect("the note parses"));
        self.publish();
    }

    /// Seals an Epoch under a `sealed_at` this suite's profile or cadence
    /// grid rejects, which only a misbehaving Aggregator publishes.
    pub fn seal_off_profile(&mut self, sealed_at: &str, entries: &[Value]) {
        let mut ordered = entries.to_vec();
        wist_core::epoch::sort_entries(&mut ordered).expect("entries are well formed");
        for entry in &ordered {
            let bytes = jcs::canonicalize(entry).expect("entry canonicalizes");
            self.hashes.push(merkle::leaf_hash(&bytes));
            self.leaves.push(bytes);
        }
        let number = self.checkpoints.len() as u64;
        let note_text = format!(
            "{}\n{}\n{}\nepoch_number {number}\nsealed_at {sealed_at}\n",
            self.log_id,
            self.hashes.len(),
            base64::engine::general_purpose::STANDARD.encode(merkle::merkle_root(&self.hashes)),
        );
        let line = wist_core::checkpoint::aggregator_signature_line(
            &self.log_id,
            &self.log.sk,
            &note_text,
        );
        let note = format!("{note_text}\n{}\n", line.encode());
        std::fs::write(self.dir.join("checkpoint"), &note).expect("write /checkpoint");
        let path = self.dir.join(format!("log/checkpoints/{number:09}"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, &note).expect("write an archived Checkpoint");
        self.publish_tree();
    }

    /// Seals an Epoch from leaf data supplied verbatim, so that a test can
    /// publish an Entry whose octets are not the JCS of anything.
    pub fn seal_leaf_bytes(&mut self, sealed_at: &str, leaves: &[Vec<u8>]) -> WistCheckpoint {
        for bytes in leaves {
            self.hashes.push(merkle::leaf_hash(bytes));
            self.leaves.push(bytes.clone());
        }
        let number = self.checkpoints.len() as u64;
        let mut checkpoint = WistCheckpoint::new(
            &self.log_id,
            self.hashes.len() as u64,
            merkle::merkle_root(&self.hashes),
            number,
            sealed_at,
        )
        .expect("checkpoint fields are well formed");
        checkpoint.sign(&self.log.sk);
        self.checkpoints.push(checkpoint.clone());
        self.publish();
        checkpoint
    }

    pub fn head(&self) -> &WistCheckpoint {
        self.checkpoints
            .last()
            .expect("the Log has sealed an Epoch")
    }

    pub fn head_number(&self) -> u64 {
        self.head().epoch_number()
    }

    pub fn tree_size(&self) -> u64 {
        self.hashes.len() as u64
    }

    pub fn root_token(&self) -> String {
        self.head().root_token()
    }

    pub fn seal(&mut self, sealed_at: &str, entries: &[Value]) -> WistCheckpoint {
        let signer = Signer::new(self.log.seed);
        self.seal_signed_by(&signer, sealed_at, entries)
    }

    /// Seals the next Epoch under a named Aggregator key, which is how a
    /// Log that rotated its key signs the Checkpoints after the rotation.
    pub fn seal_signed_by(
        &mut self,
        signer: &Signer,
        sealed_at: &str,
        entries: &[Value],
    ) -> WistCheckpoint {
        let mut ordered = entries.to_vec();
        wist_core::epoch::sort_entries(&mut ordered).expect("entries are well formed");
        for entry in &ordered {
            let bytes = jcs::canonicalize(entry).expect("entry canonicalizes");
            self.hashes.push(merkle::leaf_hash(&bytes));
            self.leaves.push(bytes);
        }
        let number = self.checkpoints.len() as u64;
        let mut checkpoint = WistCheckpoint::new(
            &self.log_id,
            self.hashes.len() as u64,
            merkle::merkle_root(&self.hashes),
            number,
            sealed_at,
        )
        .expect("checkpoint fields are well formed");
        checkpoint.sign(&signer.sk);
        self.checkpoints.push(checkpoint.clone());
        self.publish();
        checkpoint
    }

    /// Appends each Witness's Cosignature to the head Checkpoint, as the
    /// Aggregator republishes it after `add-checkpoint` (WIST-3 §5).
    pub fn cosign_head(&mut self, witnesses: &[&Witness], timestamp_s: u64) {
        let head = self.checkpoints.last_mut().expect("a sealed Epoch");
        let note_text = head.note_text();
        for witness in witnesses {
            head.add_signature(wist_core::checkpoint::cosignature_line(
                &witness.name,
                &witness.key,
                &note_text,
                timestamp_s,
            ));
        }
        self.publish();
    }

    /// Writes the head Checkpoint note verbatim, for a source offering
    /// something other than what this Log sealed.
    pub fn write_head_note(&self, note: &str) {
        std::fs::write(self.dir.join("checkpoint"), note).expect("write /checkpoint");
    }

    pub fn publish(&self) {
        let head = self.head().encode();
        std::fs::write(self.dir.join("checkpoint"), &head).expect("write /checkpoint");
        for checkpoint in &self.checkpoints {
            let path = self
                .dir
                .join(format!("log/checkpoints/{:09}", checkpoint.epoch_number()));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, checkpoint.encode()).expect("write an archived Checkpoint");
        }
        self.publish_tree();
    }

    fn publish_tree(&self) {
        let tree_size = self.hashes.len() as u64;
        let tiles = TileSet::build(&self.hashes);
        for (path, bytes) in tiles.serve(tree_size) {
            let file = self.dir.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, bytes).expect("write a tile");
        }
        for bundle in wist_core::tiles::required_entry_bundles(tree_size) {
            let (start, end) = bundle.leaf_range();
            let bytes =
                wist_core::tiles::encode_entry_bundle(&self.leaves[start as usize..end as usize])
                    .expect("encode an entry bundle");
            let file = self.dir.join(bundle.path().trim_start_matches('/'));
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, bytes).expect("write an entry bundle");
        }
    }
}

pub fn write_tier0(path: &Path, records: &[RecordFixture]) -> Vec<u8> {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE records(url TEXT, publisher TEXT, delta_id TEXT, observed_at TEXT, title TEXT, abstract TEXT, lang TEXT);
         CREATE VIRTUAL TABLE records_fts USING fts5(title, abstract, content=records, content_rowid=rowid);",
    )
    .unwrap();
    for r in records {
        conn.execute(
            "INSERT INTO records(url, publisher, delta_id, observed_at, title, abstract, lang) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (&r.url, &r.publisher, &r.delta_id, &r.observed_at, &r.title, &r.abstract_text, &r.lang),
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
    tree_size: u64,
) -> (Vec<u8>, String) {
    write_state_with(
        path,
        log,
        cadence,
        declarations,
        records,
        tree_size,
        Vec::new(),
        0,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_state_with(
    path: &Path,
    log: &Signer,
    cadence: i64,
    declarations: &[(String, Value)],
    records: &[RecordFixture],
    tree_size: u64,
    extra: Vec<StateEntry>,
    floor: u64,
) -> (Vec<u8>, String) {
    let mut entries = extra;
    // WIST-3 §7: the state carries an `aggregator_key` tuple for every
    // key admitted at or below `tree_size`, removed ones included; a
    // caller supplying its own set replaces the genesis-only default.
    if !entries
        .iter()
        .any(|entry| matches!(entry, StateEntry::AggregatorKey(_)))
    {
        entries.push(StateEntry::AggregatorKey(AggregatorKeyEntry {
            key_id: "log1".into(),
            public_key: log.public_b64u(),
            added_height: 0,
            removed_height: None,
        }));
    }
    entries.push(StateEntry::Parameter(ParameterEntry {
        name: "epoch_cadence_seconds".into(),
        effective_at: "2026-08-09T13:00:00Z".into(),
        value: cadence,
    }));
    for (domain, declaration) in declarations {
        entries.push(StateEntry::Declaration(DeclarationEntry {
            domain: domain.clone(),
            declaration: declaration.clone(),
            sealing_height: 0,
            highest_accepted_seq: declaration["publisher"]["seq"]
                .as_u64()
                .unwrap_or(0)
                .max(floor),
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
        tree_size,
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
    epoch_number: u64,
    tree_size: u64,
    root_hash: &str,
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
        epoch_number,
        tree_size,
        root_hash: root_hash.into(),
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
    epoch_number: u64,
    tree_size: u64,
    root_hash: &str,
    content_digest_value: &str,
    state_bytes: &[u8],
    state_digest_value: &str,
    sqlite_bytes: &[u8],
) {
    write_manifest_with_files(
        path,
        log,
        snapshot_date,
        epoch_number,
        tree_size,
        root_hash,
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
    epoch_number: u64,
    tree_size: u64,
    root_hash: &str,
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
        epoch_number,
        tree_size,
        root_hash,
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
    tree_size: u64,
    manifest_url: &str,
    content_digest_value: &str,
) {
    let index = SnapshotIndex {
        wist_version: "1.0.0".into(),
        updated_at: "2026-08-09T12:05:00Z".into(),
        snapshots: vec![SnapshotIndexEntry {
            snapshot_date: snapshot_date.into(),
            tree_size,
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

pub fn resign_checkpoint_with_wrong_key(fx: &Fixture, other: &Signer) {
    let head = fx.log_state().head().clone();
    let mut forged = WistCheckpoint::new(
        head.origin(),
        head.tree_size(),
        *head.root(),
        head.epoch_number(),
        head.sealed_at(),
    )
    .expect("checkpoint fields are well formed");
    forged.sign(&other.sk);
    fx.log_state().write_head_note(&forged.encode());
}

/// Seals one more Epoch, publishing the tree and its Checkpoint.
pub fn seal_next(fx: &Fixture, sealed_at: &str, entries: &[Value]) -> u64 {
    fx.log_state().seal(sealed_at, entries).epoch_number()
}

/// The `sealed_at` one cadence above the Log's head, on the hourly grid
/// the fixtures seal on.
pub fn next_instant(fx: &Fixture) -> String {
    let at = fx.log_state().head().sealed_at_s().expect("a sealed head") + 3600;
    jiff::Timestamp::from_second(at)
        .expect("grid instant is in range")
        .to_string()
}

/// A signed `aggregator_key_add` or `aggregator_key_remove` Entry, as
/// WIST-4 §5.1 shapes it, under the Log key `signing_key_id` names.
pub fn key_act(
    fx: &Fixture,
    action: &str,
    signing_key_id: &str,
    signer: &Signer,
    key_id: &str,
    public_key: Option<&Signer>,
    effective_at: &str,
) -> Value {
    let mut details = serde_json::json!({ "key_id": key_id });
    if let Some(key) = public_key {
        details["alg"] = "Ed25519".into();
        details["public_key"] = key.public_b64u().into();
    }
    let update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": action,
        "subject": key_id,
        "details": details,
        "effective_at": effective_at,
    });
    let _ = fx;
    let body = sign_envelope(&update, "update", signing_key_id, &signer.sk).unwrap();
    serde_json::json!({"type": "registry_update", "body": body})
}

/// A signed `parameter_change` Entry under the Log key
/// `signing_key_id` names.
pub fn parameter_act(
    signing_key_id: &str,
    signer: &Signer,
    parameter: &str,
    value: i64,
    effective_at: &str,
) -> Value {
    let update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "parameter_change",
        "subject": parameter,
        "details": {"parameter": parameter, "value": value},
        "effective_at": effective_at,
    });
    let body = sign_envelope(&update, "update", signing_key_id, &signer.sk).unwrap();
    serde_json::json!({"type": "registry_update", "body": body})
}

/// The canonical Entry order WIST-3 §3.3 fixes for an Epoch's Entries.
pub fn canonical_order(entries: &[Value]) -> Vec<Value> {
    let mut ordered = entries.to_vec();
    wist_core::epoch::sort_entries(&mut ordered).unwrap();
    ordered
}

pub fn extend_fixture(fx: &Fixture) -> String {
    let publisher = Signer::new([1u8; 32]);
    let next_number = fx.log_state().head_number() + 1;
    let url = format!("https://records.example/extra-{next_number}");
    let (id, delta_env, payload) = build_delta(
        &publisher,
        &url,
        "Extra Title",
        Some("Extra abstract"),
        "extra body",
        None,
    );
    write_payload(fx.dir.path(), id.strip_prefix("sha256:").unwrap(), &payload);
    let at = next_instant(fx);
    seal_next(
        fx,
        &at,
        &[serde_json::json!({"type": "publisher_delta", "body": delta_env})],
    );
    url
}

pub fn build_delete_delta(publisher: &Signer, url: &str, prev: &str) -> (String, Value) {
    let delta = serde_json::json!({
        "wist_version": "1.0.0",
        "publisher": reqwest::Url::parse(url).unwrap().host_str().unwrap(),
        "url": url,
        "change_type": "delete",
        "observed_at": "2026-08-09T12:00:00Z",
        "prev": prev,
        "meta": {"lang": "en"},
    });
    let id = wist_core::delta::delta_id(&delta).unwrap();
    (
        id,
        sign_envelope(&delta, "delta", &publisher.kid(), &publisher.sk).unwrap(),
    )
}

pub fn extend_fixture_with_withdrawal(fx: &Fixture, delta_id: &str) {
    let update = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "payload_withdrawal",
        "subject": fx.domain,
        "details": {"delta_id": delta_id, "legal_basis": "court order", "jurisdiction": "EU"},
        "effective_at": "2026-08-09T15:00:00Z",
    });
    let body = sign_envelope(&update, "update", "log1", &fx.log.sk).unwrap();
    let at = next_instant(fx);
    seal_next(
        fx,
        &at,
        &[serde_json::json!({"type": "registry_update", "body": body})],
    );
}

pub fn extend_fixture_with_delete(fx: &Fixture, url: &str, prev: &str) {
    let publisher = Signer::new([1u8; 32]);
    let (_id, delta_env) = build_delete_delta(&publisher, url, prev);
    let at = next_instant(fx);
    seal_next(
        fx,
        &at,
        &[serde_json::json!({"type": "publisher_delta", "body": delta_env})],
    );
}

pub fn extend_fixture_with_forged_delta(fx: &Fixture) {
    let attacker = Signer::new([7u8; 32]);
    let next_number = fx.log_state().head_number() + 1;
    let url = format!("https://records.example/extra-{next_number}");
    let (_id, delta_env, _payload) = build_delta(
        &attacker,
        &url,
        "Extra Title",
        Some("Extra abstract"),
        "extra body",
        None,
    );
    let at = next_instant(fx);
    seal_next(
        fx,
        &at,
        &[serde_json::json!({"type": "publisher_delta", "body": delta_env})],
    );
}

pub fn extend_fixture_with_rotation(fx: &Fixture, new_key: &Signer) -> String {
    let old = Signer::new([1u8; 32]);
    let decl0 = build_declaration(&old, &fx.domain);
    let hash0 = declaration_hash(&decl0);
    let rotation_decl = build_declaration_full(
        &old,
        &fx.domain,
        1,
        Some(&hash0),
        &[(new_key, "2026-08-09T00:00:00Z")],
    );
    let at = next_instant(fx);
    seal_next(
        fx,
        &at,
        &[serde_json::json!({"type": "publisher_declaration", "body": rotation_decl})],
    );

    let delta_number = fx.log_state().head_number() + 1;
    let url = format!("https://records.example/extra-{delta_number}");
    let (id, delta_env, payload) = build_delta(
        new_key,
        &url,
        "Rotated Title",
        Some("Rotated abstract"),
        "rotated body",
        None,
    );
    write_payload(fx.dir.path(), id.strip_prefix("sha256:").unwrap(), &payload);
    let at = next_instant(fx);
    seal_next(
        fx,
        &at,
        &[serde_json::json!({"type": "publisher_delta", "body": delta_env})],
    );
    url
}

#[allow(clippy::too_many_arguments)]
pub fn build_pack(
    dir: &Path,
    signer: &Signer,
    content_digest: &str,
    tree_size: u64,
    rows: &[(&str, &str, &str, Vec<f32>)],
    dim: u32,
    metric: &str,
) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();

    let mut jsonl = String::new();
    for (delta_id, url, publisher, vector) in rows {
        let row = serde_json::json!({
            "delta_id": delta_id,
            "url": url,
            "publisher": publisher,
            "vector": vector,
        });
        jsonl.push_str(&serde_json::to_string(&row).unwrap());
        jsonl.push('\n');
    }
    let compressed = zstd::encode_all(jsonl.as_bytes(), 0).unwrap();
    let vectors_path = dir.join("vectors.jsonl.zst");
    std::fs::write(&vectors_path, &compressed).unwrap();

    let pack = serde_json::json!({
        "wist_version": "1.0.0",
        "content_digest": content_digest,
        "tree_size": tree_size,
        "model": {
            "name": "test-model",
            "version": "1.0.0",
            "weights_hash": format!("sha256:{}", "a".repeat(64)),
            "dim": dim,
            "quantization": "f32",
            "metric": metric,
            "source": "summary",
        },
        "vectors": {
            "path": "vectors.jsonl.zst",
            "sha256": sha256_hex(&compressed),
            "bytes": compressed.len() as u64,
            "count": rows.len() as u64,
        },
    });
    let env = sign_envelope(&pack, "pack", "log1", &signer.sk).unwrap();
    let pack_path = dir.join("pack.json");
    std::fs::write(&pack_path, serde_json::to_vec(&env).unwrap()).unwrap();
    pack_path
}

/// Serves a directory over loopback and records the paths it was asked
/// for, so a test can tell which tile a Consumer fetched.
pub fn serve_recording(dir: PathBuf) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(clone) = stream.try_clone() else {
                continue;
            };
            let mut reader = BufReader::new(clone);
            let mut request = String::new();
            if reader.read_line(&mut request).unwrap_or(0) == 0 {
                continue;
            }
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                    break;
                }
            }
            let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
            recorded
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(path.clone());
            match std::fs::read(dir.join(path.trim_start_matches('/'))) {
                Ok(bytes) => {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(&bytes);
                }
                Err(_) => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
        }
    });
    (addr, seen)
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
    state: RefCell<Log>,
}

impl Fixture {
    pub fn anchor_path(&self) -> PathBuf {
        self.dir.path().join("log/anchor.json")
    }

    pub fn log_state(&self) -> RefMut<'_, Log> {
        self.state.borrow_mut()
    }

    pub fn head_number(&self) -> u64 {
        self.state.borrow().head_number()
    }

    pub fn head_tree_size(&self) -> u64 {
        self.state.borrow().tree_size()
    }
}

/// Serves, at `/checkpoint`, a Checkpoint of the head's Epoch stating
/// another root: what a Log equivocating about an Epoch it already
/// published would serve. `signer` is the key that signs it, so a test
/// can offer a note no key valid at that height authenticates.
pub fn forge_head_note(fx: &Fixture, root: [u8; 32], signer: &Signer) {
    let head = fx.log_state().head().clone();
    let mut forged = WistCheckpoint::new(
        head.origin(),
        head.tree_size(),
        root,
        head.epoch_number(),
        head.sealed_at(),
    )
    .expect("checkpoint fields are well formed");
    forged.sign(&signer.sk);
    fx.log_state().write_head_note(&forged.encode());
}

/// Copies a served Log directory, so a second source can serve what the
/// first served before it was tampered with.
pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
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

pub fn build_fixture_with_state(extra: Vec<StateEntry>, floor: u64) -> Fixture {
    build_fixture_state("graven-test-log", 9, true, false, false, extra, floor)
}

fn build_fixture_full(
    log_id: &str,
    seed: u8,
    write_second_payload: bool,
    duplicate_tier0_record: bool,
    include_tier1: bool,
) -> Fixture {
    build_fixture_state(
        log_id,
        seed,
        write_second_payload,
        duplicate_tier0_record,
        include_tier1,
        Vec::new(),
        0,
    )
}

fn build_fixture_state(
    log_id: &str,
    seed: u8,
    write_second_payload: bool,
    duplicate_tier0_record: bool,
    include_tier1: bool,
    extra_state: Vec<StateEntry>,
    floor: u64,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let log = Signer::new([seed; 32]);
    let other = Signer::new([3u8; 32]);
    let publisher = Signer::new([1u8; 32]);
    let domain = "records.example".to_string();
    let snapshot_date = "2026-08-09".to_string();

    let mut state = Log::new(dir.path(), Signer::new([seed; 32]), log_id);

    let declaration_env = build_declaration(&publisher, &domain);
    let wrapped_declaration =
        serde_json::json!({"type": "publisher_declaration", "body": declaration_env});

    let (id1, delta1_env, payload1) = build_delta(
        &publisher,
        "https://records.example/alpha",
        "Alpha Title",
        Some("Alpha abstract"),
        "alpha body",
        None,
    );
    let hex1 = id1.strip_prefix("sha256:").unwrap();
    write_payload(dir.path(), hex1, &payload1);
    let wrapped_delta1 = serde_json::json!({"type": "publisher_delta", "body": delta1_env});

    let epoch0 = state.seal(
        "2026-08-09T12:00:00Z",
        &[wrapped_declaration, wrapped_delta1],
    );
    let epoch0_root = epoch0.root_token();
    let epoch0_size = epoch0.tree_size();

    let record1 = RecordFixture {
        url: "https://records.example/alpha".into(),
        publisher: domain.clone(),
        delta_id: id1.clone(),
        observed_at: "2026-08-09T12:00:00Z".into(),
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

    let (state_bytes, state_digest_value) = write_state_with(
        &snapdir.join("state.json"),
        &log,
        3600,
        &[(domain.clone(), declaration_env.clone())],
        std::slice::from_ref(&record1),
        epoch0_size,
        extra_state,
        floor,
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
            epoch0_size,
            &epoch0_root,
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
            epoch0_size,
            &epoch0_root,
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
        epoch0_size,
        &format!("/snapshots/{snapshot_date}/manifest.json"),
        &content_digest_value,
    );

    let (id2, delta2_env, payload2) = build_delta(
        &publisher,
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

    state.seal("2026-08-09T13:00:00Z", &[wrapped_delta2]);

    let base_url = format!("http://{}", serve_static(dir.path().to_path_buf()));

    Fixture {
        dir,
        log,
        other,
        domain,
        snapshot_date,
        base_url,
        state: RefCell::new(state),
    }
}
