use super::history::{default_recovery_window_days, persist_declaration, ChainState};
use super::persist::{record_withdrawal, save_aggregator_keys, save_chain_tips};
use super::source::Sources;
use crate::error::{Error, Result};
use crate::fetch::Client;
use crate::keyset::KeyHistory;
use crate::registry::{self};
use crate::store::{CREATE_DECLARATIONS, CREATE_RECORDS, CREATE_TIER1, CREATE_UNIQUE_INDEX};
use crate::tier1;
use reqwest::Url;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::path::PathBuf;
use wist_core::aggregator_keys::Registry;
use wist_core::chain::ChainTips;
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::envelope::verify_envelope;
use wist_core::objects::Anchor;
use wist_core::objects::LogAnchorEnvelope;
use wist_core::objects::{
    AggregatorKeyEntry, SnapshotIndexEntry, SnapshotIndexEnvelope, SnapshotManifest,
    SnapshotManifestEnvelope, SnapshotState, SnapshotStateEnvelope, StateEntry,
};
use wist_core::snapshot::content_digest;
use wist_core::snapshot::state_digest;
use wist_core::unsealed::{self, Document};

pub(super) struct TempFileGuard {
    path: PathBuf,
    armed: bool,
}

impl TempFileGuard {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(super) fn verify_file_integrity(
    bytes: &[u8],
    expected_sha256_hex: &str,
    expected_bytes: u64,
) -> Result<()> {
    if bytes.len() as u64 != expected_bytes {
        return Err(Error::Verify(format!(
            "byte length mismatch: expected {expected_bytes}, got {}",
            bytes.len()
        )));
    }
    if hex_encode(&Sha256::digest(bytes)) != expected_sha256_hex {
        return Err(Error::Verify("sha256 mismatch".into()));
    }
    Ok(())
}

pub(super) fn load_anchor_bytes(spec: &str, client: &Client) -> Result<Vec<u8>> {
    if let Ok(url) = Url::parse(spec) {
        if url.scheme() == "http" || url.scheme() == "https" {
            return client.get_bytes(&url);
        }
    }
    Ok(std::fs::read(spec)?)
}

struct ShardRecord {
    record: Value,
    publisher: String,
    filed_in: usize,
}

fn read_records(sqlite_path: &Path, filed_in: usize) -> Result<Vec<ShardRecord>> {
    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare("SELECT url, publisher, delta_id, observed_at FROM records")?;
    let records = stmt
        .query_map([], |row| {
            let publisher = row.get::<_, String>(1)?;
            Ok(ShardRecord {
                record: serde_json::json!({
                    "url": row.get::<_, String>(0)?,
                    "publisher": publisher,
                    "delta_id": row.get::<_, String>(2)?,
                    "observed_at": row.get::<_, String>(3)?,
                }),
                publisher,
                filed_in,
            })
        })?
        .collect::<rusqlite::Result<Vec<ShardRecord>>>()?;
    Ok(records)
}

/// WIST-3 §7 "Sharding".
fn shard_of(publisher: &str, count: usize) -> usize {
    let digest = Sha256::digest(publisher.as_bytes());
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(prefix) % count as u64) as usize
}

const TIER0_PATH: &str = "tier0/index.sqlite";

/// WIST-3 §6.
fn manifest_directory(manifest_url: &str) -> &str {
    manifest_url
        .rfind('/')
        .map_or("", |end| &manifest_url[..=end])
}

struct Layout<'m> {
    shards: Option<&'m [String]>,
    files: Vec<(usize, &'m str)>,
}

fn is_dot_segment(segment: &str) -> bool {
    let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
    decoded == "." || decoded == ".."
}

/// WIST-3 §6: a listed path names a file inside the manifest's directory.
fn stays_in_directory(path: &str) -> bool {
    let first_separator = path.find(['/', '\\']).unwrap_or(path.len());
    !path.is_empty()
        && !path.starts_with(['/', '\\'])
        && !path[..first_separator].contains(':')
        && !path.split(['/', '\\']).any(is_dot_segment)
}

/// WIST-3 §7 "Sharding" (`WIST3-E04`).
fn shard_layout<'m>(manifest: &'m SnapshotManifest, manifest_url: &Url) -> Result<Layout<'m>> {
    let refuse = |reason: String| {
        Error::Verify(format!(
            "WIST3-E04 the manifest served at {manifest_url} {reason}"
        ))
    };
    if let Some(path) = std::iter::once(&manifest.state.path)
        .chain(manifest.files.iter().map(|f| &f.path))
        .find(|path| !stays_in_directory(path))
    {
        return Err(refuse(format!(
            "lists {path:?}, which does not name a file inside the manifest's directory"
        )));
    }
    let Some(shards) = &manifest.shards else {
        return Ok(Layout {
            shards: None,
            files: manifest
                .files
                .iter()
                .map(|f| (0, f.path.as_str()))
                .collect(),
        });
    };
    if shards.count == 0 {
        return Err(refuse("declares a shard count of 0".into()));
    }
    if shards.digests.len() as u64 != shards.count {
        return Err(refuse(format!(
            "declares {} shards but carries {} shard digests",
            shards.count,
            shards.digests.len()
        )));
    }
    let count = shards.digests.len();
    let mut has_tier0 = vec![false; count];
    let mut files = Vec::with_capacity(manifest.files.len());
    for f in &manifest.files {
        let shard = f
            .shard
            .ok_or_else(|| refuse(format!("lists {} without a shard index", f.path)))?;
        if shard >= shards.count {
            return Err(refuse(format!(
                "lists {} under shard {shard} of {}",
                f.path, shards.count
            )));
        }
        let shard = shard as usize;
        let relative = f
            .path
            .strip_prefix(&format!("shard-{shard}/"))
            .ok_or_else(|| {
                refuse(format!(
                    "lists {} under shard {shard}, outside that shard's shard-{shard}/ directory",
                    f.path
                ))
            })?;
        if f.tier == 0 && relative == TIER0_PATH {
            has_tier0[shard] = true;
        }
        files.push((shard, relative));
    }
    if let Some(missing) = has_tier0.iter().position(|held| !held) {
        return Err(refuse(format!(
            "lists shard {missing} without its {TIER0_PATH}"
        )));
    }
    Ok(Layout {
        shards: Some(&shards.digests),
        files,
    })
}

fn install_tier0(
    dir: &Path,
    tier0: Vec<Option<Vec<u8>>>,
    manifest: &SnapshotManifest,
    shard_digests: Option<&[String]>,
    manifest_url: &Url,
    snapshot_base: &str,
) -> Result<(TempFileGuard, PathBuf)> {
    let sharded = shard_digests.is_some();
    let installed_path = dir.join("index.sqlite.verifying");
    let mut paths = Vec::with_capacity(tier0.len());
    let mut guards = Vec::with_capacity(tier0.len());
    for (shard, bytes) in tier0.into_iter().enumerate() {
        let bytes = bytes.ok_or_else(|| {
            Error::Verify(format!(
                "WIST3-E04 the manifest served at {manifest_url} lists no {TIER0_PATH} file"
            ))
        })?;
        let path = if sharded {
            dir.join(format!("index.sqlite.shard-{shard}.verifying"))
        } else {
            installed_path.clone()
        };
        std::fs::write(&path, &bytes)?;
        guards.push(TempFileGuard::new(path.clone()));
        paths.push(path);
    }

    let mut records = Vec::new();
    for (shard, path) in paths.iter().enumerate() {
        records.extend(read_records(path, shard)?);
    }
    let mismatch = |what: String| {
        Error::Verify(format!(
            "WIST3-E04 the {what} of the tier-0 index served under {snapshot_base} is not the one its manifest names"
        ))
    };
    let whole: Vec<Value> = records.iter().map(|r| r.record.clone()).collect();
    if content_digest(&whole)? != manifest.content_digest {
        return Err(mismatch("content_digest".into()));
    }
    if let Some(digests) = shard_digests {
        let mut grouped: Vec<Vec<Value>> = vec![Vec::new(); digests.len()];
        for r in &records {
            grouped[shard_of(&r.publisher, digests.len())].push(r.record.clone());
        }
        for (shard, (held, named)) in grouped.iter().zip(digests).enumerate() {
            if &content_digest(held)? != named {
                return Err(mismatch(format!("shard {shard} digest")));
            }
        }
        if let Some(misfiled) = records
            .iter()
            .find(|r| shard_of(&r.publisher, digests.len()) != r.filed_in)
        {
            return Err(Error::Verify(format!(
                "WIST3-E04 shard {}'s tier-0 index served under {snapshot_base} carries a record of {}, which WIST-3 §7 assigns to shard {}",
                misfiled.filed_in,
                misfiled.publisher,
                shard_of(&misfiled.publisher, digests.len())
            )));
        }
    }

    if !sharded {
        let mut guards = guards;
        let guard = guards.pop().ok_or_else(|| {
            Error::Verify(format!(
                "WIST3-E04 the manifest served at {manifest_url} lists no {TIER0_PATH} file"
            ))
        })?;
        return Ok((guard, installed_path));
    }

    if installed_path.exists() {
        std::fs::remove_file(&installed_path)?;
    }
    let guard = TempFileGuard::new(installed_path.clone());
    let conn = Connection::open(&installed_path)?;
    conn.execute_batch(CREATE_RECORDS)?;
    for path in &paths {
        conn.execute(
            "ATTACH DATABASE ?1 AS shard",
            [path.to_string_lossy().as_ref()],
        )?;
        conn.execute(
            "INSERT INTO main.records(url, publisher, delta_id, observed_at, title, abstract, lang) SELECT url, publisher, delta_id, observed_at, title, abstract, lang FROM shard.records",
            [],
        )?;
        conn.execute("DETACH DATABASE shard", [])?;
    }
    drop(conn);
    drop(guards);
    Ok((guard, installed_path))
}

/// WIST-3 §3.4.
pub(super) fn load_anchor(anchor: &str, client: &Client) -> Result<Anchor> {
    let anchor_bytes = load_anchor_bytes(anchor, client)?;
    let anchor_value = wist_core::json::parse(&anchor_bytes)?;
    let anchor_env: LogAnchorEnvelope = serde_json::from_value(anchor_value.clone())?;
    let trust_key = PublicKey::from_b64u(&anchor_env.anchor.genesis_key.public_key)?;
    verify_envelope(&anchor_value, "anchor", &trust_key)?;
    Ok(anchor_env.anchor)
}

/// WIST-3 §3.4: committed to by no tree; its signature is judged at the adopted height (§8 step 8).
pub(super) struct Unsealed {
    pub(super) document: Document,
    pub(super) envelope: Value,
    pub(super) url: String,
}

/// WIST-3 §8 steps 1–4; the three signatures step 8 judges are not yet checked.
pub(super) struct Installation {
    guard: TempFileGuard,
    tmp_sqlite_path: PathBuf,
    pub(super) conn: Connection,
    pub(super) manifest: SnapshotManifest,
    /// WIST-3 §8 step 4: must equal the manifest's (`WIST3-E04`).
    pub(super) state_tree_size: u64,
    pub(super) content_digest: String,
    pub(super) history: KeyHistory,
    pub(super) aggregator_keys: Registry,
    pub(super) chain: ChainState,
    pub(super) suffix_lists: super::suffix::SuffixLists,
    /// WIST-3 §8 step 8: verified at the adopted Checkpoint's height.
    pub(super) unsealed: Vec<Unsealed>,
    pub(super) source: usize,
}

impl Installation {
    pub(super) fn commit(self, dir: &Path) -> Result<()> {
        let Installation {
            mut guard,
            tmp_sqlite_path,
            conn,
            ..
        } = self;
        drop(conn);
        guard.disarm();
        std::fs::rename(&tmp_sqlite_path, dir.join("index.sqlite"))?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}

const SNAPSHOT_INDEX_PATH: &str = "/snapshots/index.json";

/// WIST-3 §9 `WIST3-E04`.
fn malformed(document: Document, detail: &impl std::fmt::Display) -> Error {
    Error::Verify(format!(
        "WIST3-E04 {document} does not validate against its schema: {detail}"
    ))
}

/// WIST-3 §8 steps 1, 2 and 4. The signature is left unchecked: §3.4 judges it at the adopted
/// Checkpoint's height.
fn parse_document<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    document: Document,
) -> Result<(T, Value)> {
    let value = wist_core::json::parse(bytes).map_err(|error| malformed(document, &error))?;
    let parsed =
        serde_json::from_value(value.clone()).map_err(|error| malformed(document, &error))?;
    Ok((parsed, value))
}

/// The guard of `tmp_sqlite_path` removes it unless the Snapshot is installed.
struct Documents {
    manifest: SnapshotManifest,
    state: SnapshotState,
    keys: Registry,
    unsealed: Vec<Unsealed>,
    guard: TempFileGuard,
    tmp_sqlite_path: PathBuf,
    tier1_extracts: Vec<Vec<u8>>,
    tier1_links: Vec<Vec<u8>>,
}

/// WIST-3 §8 step 1 and §6: the index is mutable, so it is read per source, never from the first
/// source that answers.
fn index_entry(sources: &Sources, at: usize) -> Result<(SnapshotIndexEntry, Unsealed)> {
    let ((envelope, value), url) = sources.whole_at(SNAPSHOT_INDEX_PATH, at, |bytes| {
        parse_document::<SnapshotIndexEnvelope>(bytes, Document::Index)
    })?;
    let entry = envelope
        .index
        .snapshots
        .into_iter()
        .next()
        .ok_or_else(|| Error::Verify("snapshot index is empty".into()))?;
    Ok((
        entry,
        Unsealed {
            document: Document::Index,
            envelope: value,
            url: url.to_string(),
        },
    ))
}

/// WIST-3 §8 step 2 (`WIST3-E04`).
fn check_index_agreement(entry: &SnapshotIndexEntry, manifest: &SnapshotManifest) -> Result<()> {
    for (field, from_index, from_manifest) in [
        (
            "snapshot_date",
            &entry.snapshot_date,
            &manifest.snapshot_date,
        ),
        (
            "content_digest",
            &entry.content_digest,
            &manifest.content_digest,
        ),
    ] {
        if from_index != from_manifest {
            return Err(Error::Verify(format!(
                "WIST3-E04: snapshot index names {field} {from_index}, its manifest {from_manifest}"
            )));
        }
    }
    if entry.tree_size != manifest.tree_size {
        return Err(Error::Verify(format!(
            "WIST3-E04: snapshot index names tree_size {}, its manifest {}",
            entry.tree_size, manifest.tree_size
        )));
    }
    Ok(())
}

/// WIST-3 §6: files are verified "by hash, signature, or commitment, never by source", so a refused
/// path is asked of the next source.
fn documents(
    sources: &Sources,
    anchor: &Anchor,
    dir: &Path,
    at: usize,
    tier1: bool,
) -> Result<Documents> {
    let (entry, index) = index_entry(sources, at)?;
    let ((manifest_envelope, manifest_value), manifest_url) =
        sources.whole_from(&entry.manifest_url, at, |bytes| {
            let (envelope, value) =
                parse_document::<SnapshotManifestEnvelope>(bytes, Document::Manifest)?;
            check_index_agreement(&entry, &envelope.manifest)?;
            Ok((envelope, value))
        })?;
    let manifest = manifest_envelope.manifest;
    let snapshot_base = manifest_directory(&entry.manifest_url);
    let layout = shard_layout(&manifest, &manifest_url)?;

    let state_path = format!("{snapshot_base}{}", manifest.state.path);
    let ((state_envelope, state_value), state_url) =
        sources.whole_from(&state_path, at, |bytes| {
            verify_file_integrity(bytes, &manifest.state.sha256, manifest.state.bytes)?;
            parse_document::<SnapshotStateEnvelope>(bytes, Document::StateFile)
        })?;

    let unsealed = vec![
        index,
        Unsealed {
            document: Document::Manifest,
            envelope: manifest_value,
            url: manifest_url.to_string(),
        },
        Unsealed {
            document: Document::StateFile,
            envelope: state_value,
            url: state_url.to_string(),
        },
    ];

    let state = state_envelope.state;
    let mut tier0: Vec<Option<Vec<u8>>> = vec![None; layout.shards.map_or(1, <[String]>::len)];
    let mut tier1_extracts = Vec::new();
    let mut tier1_links = Vec::new();
    for (f, &(shard, relative)) in manifest.files.iter().zip(&layout.files) {
        let path = format!("{snapshot_base}{}", f.path);
        let (bytes, _) = sources.whole(&path, |bytes| {
            verify_file_integrity(bytes, &f.sha256, f.bytes)?;
            Ok(bytes.to_vec())
        })?;
        if f.tier == 0 && relative == TIER0_PATH {
            tier0[shard] = Some(bytes);
        } else if tier1 && relative.ends_with("tier1/extracts.parquet") {
            tier1_extracts.push(bytes);
        } else if tier1 && relative.ends_with("tier1/links.parquet") {
            tier1_links.push(bytes);
        }
    }

    // WIST-3 §8 step 4 and §7: the tuples are chained to the Anchor's genesis key before any is
    // used.
    wist_core::snapshot::check_state_tree_size(&manifest, state.tree_size)?;
    let tuples: Vec<AggregatorKeyEntry> = state
        .entries
        .iter()
        .filter_map(|entry| match entry {
            StateEntry::AggregatorKey(key) => Some(key.clone()),
            _ => None,
        })
        .collect();
    let keys = Registry::from_state_tuples(anchor, manifest.epoch_number, &tuples)?;

    // WIST-3 §9 `WIST3-E04`: a disagreement among one source's documents re-fetches the Snapshot;
    // §9's no-refetch case is a digest the Consumer's own rebuild contradicts.
    let state_entry_values: Vec<Value> = state
        .entries
        .iter()
        .map(serde_json::to_value)
        .collect::<serde_json::Result<_>>()?;
    if state_digest(&state_entry_values)? != manifest.state.state_digest {
        return Err(Error::Verify(format!(
            "WIST3-E04 the state_digest of the state file served at {state_url} is not the one its manifest names"
        )));
    }
    let (guard, tmp_sqlite_path) = install_tier0(
        dir,
        tier0,
        &manifest,
        layout.shards,
        &manifest_url,
        snapshot_base,
    )?;

    // WIST-3 §8 step 8's early rejection: a signature failing under the tuple key it names verifies
    // at no height.
    for unsealed in &unsealed {
        if unsealed::verifies_at_no_height(unsealed.document, &unsealed.envelope, &keys) {
            return Err(Error::Verify(format!(
                "WIST3-E04 {}'s signature does not verify under the key its own aggregator_key tuple names, so it verifies at no height ({})",
                unsealed.document, unsealed.url
            )));
        }
    }

    Ok(Documents {
        manifest,
        state,
        keys,
        unsealed,
        guard,
        tmp_sqlite_path,
        tier1_extracts,
        tier1_links,
    })
}

/// WIST-3 §9 `WIST3-E04`: the rejection stands only where no source's index yields a Snapshot that
/// verifies.
fn snapshot_documents(
    sources: &Sources,
    anchor: &Anchor,
    dir: &Path,
    from: usize,
    tier1: bool,
) -> Result<(Documents, usize)> {
    let mut last: Option<Error> = None;
    for at in from..sources.count() {
        match documents(sources, anchor, dir, at, tier1) {
            Ok(documents) => return Ok((documents, at)),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        Error::Fetch(format!("WIST3-E01 no source holds {SNAPSHOT_INDEX_PATH}"))
    }))
}

/// The three Envelope signatures are left to WIST-3 §8 step 8.
pub(super) fn snapshot(
    sources: &Sources,
    anchor: &Anchor,
    dir: &Path,
    tier1: bool,
    from: usize,
) -> Result<Installation> {
    let client = sources.client();
    let base = sources.primary();
    let (
        Documents {
            manifest,
            state,
            keys: aggregator_keys,
            unsealed,
            guard,
            tmp_sqlite_path,
            tier1_extracts,
            tier1_links,
        },
        source,
    ) = snapshot_documents(sources, anchor, dir, from, tier1)?;

    let conn = Connection::open(&tmp_sqlite_path)?;
    conn.execute(CREATE_UNIQUE_INDEX, [])?;
    conn.execute(CREATE_DECLARATIONS, [])?;

    if tier1 {
        conn.execute_batch(CREATE_TIER1)?;
        for bytes in &tier1_extracts {
            tier1::import_extracts(&conn, bytes)?;
        }
        for bytes in &tier1_links {
            tier1::import_links(&conn, bytes)?;
        }
    }

    // WIST-3 §8 step 10: without the chain tips a continuing Delta reads as a fork; without the
    // recovery windows an in-window rotation is invisible.
    let mut history = KeyHistory::new();
    let mut suffix_lists = super::suffix::SuffixLists::load(&conn)?;
    conn.execute_batch(crate::store::CREATE_CHAIN_TIPS)?;
    let mut tips = ChainTips::new();
    let mut adopted_windows: Vec<(String, String, Value, u64)> = Vec::new();
    let mut adopted_pending: Vec<(String, Value, u64, u64)> = Vec::new();
    let mut adopted_parameters: Vec<(String, String, i64)> = Vec::new();
    for entry in &state.entries {
        match entry {
            StateEntry::Parameter(p) => {
                adopted_parameters.push((p.name.clone(), p.effective_at.clone(), p.value));
            }
            StateEntry::Declaration(d) => {
                history.adopt_domain(
                    &d.domain,
                    &d.declaration,
                    d.sealing_height,
                    d.highest_accepted_seq,
                )?;
                persist_declaration(
                    &conn,
                    d.sealing_height,
                    "",
                    true,
                    default_recovery_window_days(),
                    &d.declaration,
                )?;
            }
            StateEntry::RecoveryWindow(w) => {
                adopted_windows.push((
                    w.domain.clone(),
                    w.window_end.clone(),
                    w.head.clone(),
                    w.head_height,
                ));
            }
            StateEntry::PendingDeclaration(p) => {
                adopted_pending.push((
                    p.domain.clone(),
                    p.head.clone(),
                    p.sealing_height,
                    p.activation_height,
                ));
            }
            // WIST-3 §6.2 and §7: a Consumer resuming above the withdrawal's Epoch never sees its
            // Entry.
            StateEntry::Withdrawal(w) => {
                record_withdrawal(&conn, &w.delta_id, &w.publisher, w.sealing_height)?;
                let _ = super::history::remove_by_delta_id(&conn, &w.delta_id, w.sealing_height)?;
            }
            StateEntry::Label(l) => super::persist::adopt_label_tuple(&conn, l)?,
            StateEntry::Dispute(d) => super::persist::adopt_dispute_tuple(&conn, d)?,
            StateEntry::SuffixList(s) => {
                suffix_lists.adopt(client, base, &s.identifier, s.sealing_height)?;
            }
            StateEntry::Record(r) => tips.adopt(&r.publisher, &r.url, &r.delta_id),
            // WIST-3 §7: authenticated from the Anchor before any of this state was read.
            StateEntry::AggregatorKey(_) => {}
        }
    }
    for (domain, window_end, head, head_height) in &adopted_windows {
        history.adopt_window(domain, window_end, head, *head_height)?;
    }
    for (domain, head, head_height, activation_height) in &adopted_pending {
        history.adopt_pending(domain, head, *head_height, *activation_height)?;
    }
    for (head, head_height) in adopted_windows
        .iter()
        .map(|(_, _, head, height)| (head, *height))
        .chain(
            adopted_pending
                .iter()
                .map(|(_, head, height, _)| (head, *height)),
        )
    {
        persist_declaration(
            &conn,
            head_height,
            "",
            true,
            default_recovery_window_days(),
            head,
        )?;
    }
    save_chain_tips(&conn, &tips)?;
    super::persist::seed_ranking_index(&conn, manifest.epoch_number)?;

    save_aggregator_keys(&conn, &aggregator_keys)?;
    let chain = ChainState::from_tuples(&adopted_parameters)?;
    Ok(Installation {
        guard,
        tmp_sqlite_path,
        conn,
        content_digest: manifest.content_digest.clone(),
        state_tree_size: state.tree_size,
        manifest,
        history,
        aggregator_keys,
        chain,
        suffix_lists,
        unsealed,
        source,
    })
}

pub(super) fn migrate_legacy_layout(dir: &Path, log_id: &str) -> Result<bool> {
    if !registry::is_unmigrated_legacy_layout(dir) {
        return Ok(false);
    }
    let target_dir = registry::log_dir(dir, log_id);
    std::fs::create_dir_all(&target_dir)?;

    let index_src = dir.join("index.sqlite");
    let index_dst = target_dir.join("index.sqlite");
    std::fs::rename(&index_src, &index_dst)?;

    let sync_src = dir.join("sync.json");
    let sync_dst = target_dir.join("sync.json");
    if let Err(err) = std::fs::rename(&sync_src, &sync_dst) {
        if let Err(undo_err) = std::fs::rename(&index_dst, &index_src) {
            return Err(Error::Verify(format!(
                "legacy migration failed moving {} into {} ({err}); additionally, could not move {} back to {} ({undo_err}); index.sqlite is stranded at {}",
                sync_src.display(),
                sync_dst.display(),
                index_dst.display(),
                index_src.display(),
                index_dst.display()
            )));
        }
        return Err(Error::Verify(format!(
            "legacy migration failed moving {} into {}: {err}",
            sync_src.display(),
            sync_dst.display()
        )));
    }
    Ok(true)
}

pub(super) fn rollback_migration(dir: &Path, log_id: &str) -> Result<()> {
    let target_dir = registry::log_dir(dir, log_id);
    let index_src = target_dir.join("index.sqlite");
    let index_dst = dir.join("index.sqlite");
    let sync_src = target_dir.join("sync.json");
    let sync_dst = dir.join("sync.json");

    if let Err(err) = std::fs::rename(&index_src, &index_dst) {
        return Err(Error::Verify(format!(
            "rollback of legacy migration failed: could not move {} back to {}: {err}; both files remain in {}",
            index_src.display(),
            index_dst.display(),
            target_dir.display()
        )));
    }
    if let Err(err) = std::fs::rename(&sync_src, &sync_dst) {
        return Err(Error::Verify(format!(
            "rollback of legacy migration failed: index.sqlite was restored to {} but could not move {} back to {}: {err}; sync.json remains in {}",
            dir.display(),
            sync_src.display(),
            sync_dst.display(),
            target_dir.display()
        )));
    }

    std::fs::remove_dir_all(&target_dir).map_err(|err| {
        Error::Verify(format!(
            "rollback of legacy migration restored both files to {} but could not remove {}: {err}",
            dir.display(),
            target_dir.display()
        ))
    })?;
    std::fs::remove_file(dir.join("logs.json")).map_err(|err| {
        Error::Verify(format!(
            "rollback of legacy migration restored both files to {} but could not remove {}: {err}",
            dir.display(),
            dir.join("logs.json").display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod shard_tests {
    use super::*;

    #[test]
    fn shard_of_reads_the_first_eight_digest_octets_big_endian() {
        assert_eq!(shard_of("alpha.example", 1_000_003), 119_713);
        assert_eq!(shard_of("records.example", 1_000_003), 895_760);
        assert_eq!(shard_of("records.example", 3), 2);
        assert_eq!(shard_of("records.example", 1), 0);
    }

    #[test]
    fn stays_in_directory_refuses_paths_leaving_the_manifests_directory() {
        for path in [
            "",
            "/log/anchor.json",
            "\\log\\anchor.json",
            "https://other.example/x",
            "c:x",
            "shard-0/../../../log/anchor.json",
            "shard-0/./tier0/index.sqlite",
            "shard-0\\..\\x",
            "shard-0/%2E%2e/x",
            "..",
        ] {
            assert!(!stays_in_directory(path), "{path:?}");
        }
        for path in [
            "state.json",
            "tier0/index.sqlite",
            "shard-12/tier1/links.parquet",
            "a/b:c",
            "...x/y",
        ] {
            assert!(stays_in_directory(path), "{path:?}");
        }
    }

    #[test]
    fn manifest_directory_keeps_everything_through_the_last_slash() {
        assert_eq!(
            manifest_directory("/snapshots/2026-08-09/000000000/manifest.json"),
            "/snapshots/2026-08-09/000000000/"
        );
        assert_eq!(
            manifest_directory("https://mirror.example/any/where/manifest.json"),
            "https://mirror.example/any/where/"
        );
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn migrate_legacy_layout_is_noop_when_not_legacy() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!migrate_legacy_layout(dir.path(), "log-a").unwrap());
    }

    #[test]
    fn migrate_legacy_layout_moves_both_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.sqlite"), b"idx").unwrap();
        std::fs::write(dir.path().join("sync.json"), b"sync").unwrap();

        assert!(migrate_legacy_layout(dir.path(), "log-a").unwrap());

        let target = registry::log_dir(dir.path(), "log-a");
        assert_eq!(std::fs::read(target.join("index.sqlite")).unwrap(), b"idx");
        assert_eq!(std::fs::read(target.join("sync.json")).unwrap(), b"sync");
        assert!(!dir.path().join("index.sqlite").exists());
        assert!(!dir.path().join("sync.json").exists());
    }

    #[test]
    fn migrate_legacy_layout_restores_first_file_when_second_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.sqlite"), b"idx").unwrap();
        std::fs::write(dir.path().join("sync.json"), b"sync").unwrap();

        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(target.join("sync.json")).unwrap();

        let err = migrate_legacy_layout(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("sync.json"), "error was: {err}");

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite must be restored to the top level, not stranded in target_dir"
        );
        assert!(!target.join("index.sqlite").exists());
        assert_eq!(
            std::fs::read(dir.path().join("sync.json")).unwrap(),
            b"sync"
        );
    }

    #[test]
    fn rollback_migration_moves_files_back_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        rollback_migration(dir.path(), "log-a").unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx"
        );
        assert_eq!(
            std::fs::read(dir.path().join("sync.json")).unwrap(),
            b"sync"
        );
        assert!(!target.exists());
        assert!(!dir.path().join("logs.json").exists());
    }

    #[test]
    fn rollback_migration_leaves_target_dir_intact_when_first_rename_back_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        std::fs::create_dir_all(dir.path().join("index.sqlite")).unwrap();

        let err = rollback_migration(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("index.sqlite"), "error was: {err}");

        assert_eq!(
            std::fs::read(target.join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite must still be in target_dir, not deleted by a premature remove_dir_all"
        );
        assert_eq!(std::fs::read(target.join("sync.json")).unwrap(), b"sync");
        assert!(
            target.exists(),
            "target_dir must not be removed while rollback is incomplete"
        );
        assert!(dir.path().join("logs.json").exists());
    }

    #[test]
    fn rollback_migration_preserves_sync_json_when_second_rename_back_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = registry::log_dir(dir.path(), "log-a");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.sqlite"), b"idx").unwrap();
        std::fs::write(target.join("sync.json"), b"sync").unwrap();
        std::fs::write(dir.path().join("logs.json"), b"{}").unwrap();

        std::fs::create_dir_all(dir.path().join("sync.json")).unwrap();

        let err = rollback_migration(dir.path(), "log-a").unwrap_err();
        assert!(err.to_string().contains("sync.json"), "error was: {err}");

        assert_eq!(
            std::fs::read(dir.path().join("index.sqlite")).unwrap(),
            b"idx",
            "index.sqlite rename-back had already succeeded and must not be undone"
        );
        assert_eq!(
            std::fs::read(target.join("sync.json")).unwrap(),
            b"sync",
            "sync.json must still be in target_dir, not deleted by a premature remove_dir_all"
        );
        assert!(
            target.exists(),
            "target_dir must not be removed while rollback is incomplete"
        );
        assert!(dir.path().join("logs.json").exists());
    }
}
