use graven::keyset::KeyHistory;
use graven::sync::{checkpoints, tree, SyncState, Tree};
use rusqlite::Connection;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use wist_core::crypto::{hex_decode, PublicKey};
use wist_core::envelope::sign_envelope;
use wist_core::item::Kind;
use wist_core::objects::{Anchor, GenesisKey};
use wist_core::parameters::{Amendment, Schedule};
use wist_core::sealing::{carried_label_ids, Epoch, Parameters, Replay};
use wist_core::timestamp::log_seconds;

pub fn spec_dir() -> PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
}

pub fn vector(rel: &str) -> Value {
    serde_json::from_slice(&std::fs::read(spec_dir().join("vectors").join(rel)).unwrap()).unwrap()
}

pub fn signer_of(key: &Value) -> super::Signer {
    let seed: [u8; 32] = hex_decode(key["seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signer = super::Signer::new(seed);
    assert_eq!(signer.public_b64u(), key["x"].as_str().unwrap());
    signer
}

pub struct VectorEpoch {
    pub sealed_at: String,
    pub parameters: BTreeMap<String, i64>,
    pub leaves: Vec<Vec<u8>>,
}

impl VectorEpoch {
    pub fn entries(&self) -> Vec<Value> {
        self.leaves
            .iter()
            .map(|leaf| serde_json::from_slice(leaf).unwrap())
            .collect()
    }

    pub fn stored(&self) -> Vec<(usize, &[u8])> {
        self.leaves
            .iter()
            .enumerate()
            .filter(|(_, leaf)| wist_core::json::member_eligible(leaf, &[]) != Some(true))
            .map(|(index, leaf)| (index, leaf.as_slice()))
            .collect()
    }
}

pub struct ServedLog {
    pub dir: tempfile::TempDir,
    pub log: super::Log,
    pub log_id: String,
    pub log_key_id: String,
    pub base_url: String,
    pub epochs: Vec<VectorEpoch>,
}

impl ServedLog {
    pub fn new(log_key: &Value, log_id: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let signer = signer_of(log_key);
        let key_id = log_key["kid"].as_str().unwrap().to_owned();
        let anchor = Anchor {
            wist_version: "1.0.0".into(),
            log_id: log_id.into(),
            genesis_key: GenesisKey {
                key_id: key_id.clone(),
                alg: "Ed25519".into(),
                public_key: signer.public_b64u(),
            },
            created_at: "2026-08-01T00:00:00Z".into(),
            predecessor: None,
        };
        let envelope = sign_envelope(
            &serde_json::to_value(&anchor).unwrap(),
            "anchor",
            &key_id,
            &signer.sk,
        )
        .unwrap();
        let anchor_path = dir.path().join("log/anchor.json");
        std::fs::create_dir_all(anchor_path.parent().unwrap()).unwrap();
        std::fs::write(&anchor_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let log = super::Log::empty(dir.path(), signer, log_id);
        let base_url = format!("http://{}", super::serve_static(dir.path().to_path_buf()));
        ServedLog {
            dir,
            log,
            log_id: log_id.into(),
            log_key_id: key_id,
            base_url,
            epochs: Vec::new(),
        }
    }

    pub fn seal(&mut self, epoch: VectorEpoch) -> u64 {
        let height = self
            .log
            .seal_leaf_bytes(&epoch.sealed_at, &epoch.leaves)
            .epoch_number();
        self.epochs.push(epoch);
        height
    }

    pub fn log_key(&self) -> impl Fn(&str) -> Option<PublicKey> + '_ {
        let public = PublicKey::from_b64u(&self.log.log.public_b64u()).unwrap();
        move |key_id: &str| (key_id == self.log_key_id).then(|| public.clone())
    }

    pub fn log_dir(&self, target: &Path) -> PathBuf {
        graven::registry::log_dir(target, &self.log_id)
    }

    pub fn amendments(&self) -> Vec<Amendment> {
        let first = log_seconds(&self.epochs[0].sealed_at).unwrap();
        let mut schedule = Schedule::new(first);
        let mut amendments = Vec::new();
        for (height, epoch) in self.epochs.iter().enumerate() {
            let at = log_seconds(&epoch.sealed_at).unwrap();
            let mut wanted = epoch.parameters.clone();
            wanted.entry("epoch_cadence_seconds".into()).or_insert(1);
            for (index, (parameter, value)) in wanted.into_iter().enumerate() {
                if schedule.value_at(&parameter, at) == Some(value) {
                    continue;
                }
                let amendment = Amendment {
                    parameter,
                    value,
                    epoch_number: height as u64,
                    entry_index: index as u64,
                    sealed_at_s: at,
                    effective_at_s: at,
                };
                schedule.adopt(amendment.clone());
                amendments.push(amendment);
            }
        }
        amendments
    }

    pub fn genesis_replay(&self) -> Replay {
        let epoch = &self.epochs[0];
        let entries = epoch.entries();
        let parameters = Parameters::new(
            epoch
                .parameters
                .iter()
                .map(|(name, value)| (name.as_str(), *value)),
        )
        .unwrap();
        let root = self.log.checkpoints[0].root_token();
        let log_key = self.log_key();
        let mut replay = Replay::new();
        replay
            .epoch_stored(
                &Epoch {
                    height: 0,
                    root: &root,
                    sealed_at: &epoch.sealed_at,
                    parameters: &parameters,
                    suffix_list: None,
                    log_key: &log_key,
                    entries: &entries,
                },
                &epoch.stored(),
            )
            .unwrap();
        replay
    }

    pub fn install(&self, target: &Path) {
        let replay = self.genesis_replay();
        assert_eq!(replay.labels().count(), 0);
        let checkpoint = self.log.checkpoints[0].clone();
        let log_dir = self.log_dir(target);
        std::fs::create_dir_all(&log_dir).unwrap();
        let index = log_dir.join("index.sqlite");
        let conn = Connection::open(&index).unwrap();
        conn.execute_batch(graven::store::CREATE_RECORDS).unwrap();
        for tuple in replay.materialized().unwrap() {
            let record = replay
                .records()
                .record(&tuple.publisher, &tuple.url)
                .unwrap();
            conn.execute(
                "INSERT INTO records(url, publisher, item_id, observed_at, attested_at, lang, collection, generated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    &tuple.url,
                    &tuple.publisher,
                    &tuple.item_id,
                    &tuple.observed_at,
                    &tuple.attested_at,
                    record.item["meta"]["lang"].as_str(),
                    &record.collection,
                    &record.generated_at,
                ),
            )
            .unwrap();
        }
        conn.execute_batch(graven::store::CREATE_STATE_TUPLES)
            .unwrap();
        conn.execute_batch(graven::store::CREATE_PARAMETERS)
            .unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS declaration_state(id INTEGER PRIMARY KEY CHECK(id = 1), state TEXT NOT NULL)",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO declaration_state(id, state) VALUES (1, ?1)",
            [KeyHistory::from_declarations(replay.declarations().clone())
                .state()
                .unwrap()],
        )
        .unwrap();
        for (seq, tuple) in replay.state_entries().iter().enumerate() {
            conn.execute(
                "INSERT INTO state_tuples(seq, tuple) VALUES (?1, ?2)",
                (seq as i64, serde_json::to_string(tuple).unwrap()),
            )
            .unwrap();
        }
        conn.execute_batch(graven::store::CREATE_SEALED_LABEL_IDS)
            .unwrap();
        conn.execute_batch(graven::store::CREATE_SEALED_ITEMS)
            .unwrap();
        let genesis = &self.epochs[0];
        for label_id in carried_label_ids(&genesis.entries(), &genesis.stored()).unwrap() {
            conn.execute(
                "INSERT INTO sealed_label_ids(label_id, subject) VALUES (?1, NULL)",
                [label_id],
            )
            .unwrap();
        }
        for item in replay.sealed_items().sealed() {
            let kind = match item.kind {
                Kind::Page => "page",
                Kind::Removed => "removed",
            };
            conn.execute(
                "INSERT INTO sealed_items(item_id, publisher, kind, height) VALUES (?1, ?2, ?3, ?4)",
                (item.item_id, item.publisher, kind, item.height as i64),
            )
            .unwrap();
        }
        checkpoints::save_checkpoint(&conn, &checkpoint, Some(true)).unwrap();
        let at = checkpoint.sealed_at_s().unwrap();
        graven::sync::save_sync_state(
            &conn,
            &SyncState {
                format: graven::sync::SYNC_STATE_FORMAT,
                tree_size: checkpoint.tree_size(),
                epoch_number: 0,
                root: checkpoint.root_token(),
                unwitnessed: true,
                content_digest: None,
                snapshot_tree_size: None,
                schedule_first_s: Some(at),
                prior_sealed_at_s: Some(at),
                largest_epoch_bytes: 0,
                walk_floor: None,
                rejected_epochs: Vec::new(),
            },
        )
        .unwrap();
        let client = graven::fetch::Client::new(true);
        let sources = graven::sync::Sources::new(
            &client,
            vec![graven::fetch::parse_base(&self.base_url).unwrap()],
        );
        let mut held = Tree::new();
        tree::seed(
            &sources,
            &mut held,
            checkpoint.tree_size(),
            checkpoint.root(),
        )
        .unwrap();
        held.save(&conn).unwrap();
        self.amend(target);
    }

    pub fn amend(&self, target: &Path) {
        let conn = Connection::open(self.log_dir(target).join("index.sqlite")).unwrap();
        conn.execute_batch(graven::store::CREATE_PARAMETERS)
            .unwrap();
        for a in self.amendments() {
            conn.execute(
                "INSERT OR IGNORE INTO parameters(parameter, value, epoch_number, entry_index, sealed_at_s, effective_at_s) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (&a.parameter, a.value, a.epoch_number as i64, a.entry_index as i64, a.sealed_at_s, a.effective_at_s),
            )
            .unwrap();
        }
    }

    pub fn sync(&self, target: &Path) -> Result<u64, String> {
        self.sync_tiers(target, false)
    }

    pub fn sync_tiers(&self, target: &Path, tier1: bool) -> Result<u64, String> {
        let outcome = graven::sync::run(
            self.dir.path().join("log/anchor.json").to_str().unwrap(),
            &self.base_url,
            target,
            true,
            tier1,
        )
        .map(|report| report.head)
        .map_err(|error| error.to_string());
        super::assert_records_materialized(&self.log_dir(target));
        outcome
    }

    pub fn rejected(&self, target: &Path) -> Vec<graven::sync::RejectedEpoch> {
        graven::store::synced_state(&self.log_dir(target))
            .unwrap()
            .rejected_epochs
    }

    pub fn head(&self, target: &Path) -> u64 {
        graven::store::synced_state(&self.log_dir(target))
            .unwrap()
            .epoch_number
    }
}

pub fn leaf_of(named: &Value) -> Vec<u8> {
    match named["entry_json"].as_str() {
        Some(text) => text.as_bytes().to_vec(),
        None => wist_core::jcs::canonicalize(&named["entry"]).unwrap(),
    }
}

pub fn parameter_map(map: &Value) -> BTreeMap<String, i64> {
    map.as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| (name.clone(), value.as_i64().unwrap()))
        .collect()
}
