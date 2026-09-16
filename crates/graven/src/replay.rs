//! The Consumer's replay of WIST-4 §3.1 roster acts and §5.1 canary acts
//! through core's shared engines, seeded from Snapshot tuples at a cold
//! start and persisted between syncs.
use crate::error::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wist_core::canary_replay::{CanaryProfile, CanaryReplay, CoverageProfile};
use wist_core::crypto::PublicKey;
use wist_core::declarations::{Declarations, Position};
use wist_core::roster_replay::{AcceptedAct, Outcome, RosterReplay};

pub const CREATE_REPLAY_STATE: &str = "CREATE TABLE IF NOT EXISTS replay_state(id INTEGER PRIMARY KEY CHECK(id = 1), state TEXT NOT NULL)";

/// The parameters a Block's acts are replayed under (WIST-4 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActProfile {
    pub canary: CanaryProfile,
    pub coverage: CoverageProfile,
}

impl ActProfile {
    pub fn from_schedule(schedule: &wist_core::parameters::Schedule, at_s: i64) -> Self {
        let value = |name: &str| schedule.value_at(name, at_s).unwrap() as u64;
        Self {
            canary: CanaryProfile {
                lead_blocks: value("canary_lead_blocks"),
                leaves_max: value("canary_leaves_max"),
                commitments_max: value("canary_commitments_max"),
                reveal_min_blocks: value("canary_reveal_min_blocks"),
                lifetime_blocks: value("canary_lifetime_blocks"),
                epoch_blocks: value("epoch_blocks"),
                checkpoint_budget: value("observer_checkpoint_budget"),
            },
            coverage: CoverageProfile {
                deadline_hours: value("coverage_deadline_hours"),
                seal_blocks: value("record_seal_blocks"),
            },
        }
    }
}

impl Default for ActProfile {
    fn default() -> Self {
        let default = |name: &str| {
            wist_core::parameters::spec(name)
                .and_then(|p| p.default)
                .unwrap() as u64
        };
        Self {
            canary: CanaryProfile {
                lead_blocks: default("canary_lead_blocks"),
                leaves_max: default("canary_leaves_max"),
                commitments_max: default("canary_commitments_max"),
                reveal_min_blocks: default("canary_reveal_min_blocks"),
                lifetime_blocks: default("canary_lifetime_blocks"),
                epoch_blocks: default("epoch_blocks"),
                checkpoint_budget: default("observer_checkpoint_budget"),
            },
            coverage: CoverageProfile {
                deadline_hours: default("coverage_deadline_hours"),
                seal_blocks: default("record_seal_blocks"),
            },
        }
    }
}

/// One sealed Block's inputs to the act replay.
pub struct ActBlock<'a> {
    pub height: u64,
    pub block_hash: &'a str,
    pub sealed_at_s: i64,
    pub entries: &'a [Value],
    pub log_key_id: &'a str,
    pub log_key: &'a PublicKey,
    pub profile: ActProfile,
}

#[derive(Serialize, Deserialize)]
pub struct ActReplay {
    roster: RosterReplay,
    canary: CanaryReplay,
    rejected: u64,
}

impl ActReplay {
    pub fn new(log_id: &str) -> Self {
        ActReplay {
            roster: RosterReplay::new(log_id),
            canary: CanaryReplay::new(),
            rejected: 0,
        }
    }

    pub fn from_state(state: &str) -> Result<Self> {
        let replay: ActReplay = serde_json::from_str(state)?;
        Ok(ActReplay {
            roster: replay.roster.restore(),
            canary: replay.canary,
            rejected: replay.rejected,
        })
    }

    pub fn state(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn roster(&self) -> &RosterReplay {
        &self.roster
    }

    pub fn canary(&self) -> &CanaryReplay {
        &self.canary
    }

    /// Acts the shared rules rejected since the replay started.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Starts both engines after a Snapshot's anchor Block (WIST-3 §8).
    pub fn seed_head(
        &mut self,
        block_number: u64,
        block_hash: &str,
        profile: ActProfile,
    ) -> Result<()> {
        self.roster
            .seed_head(block_number, block_hash)
            .map_err(|e| Error::Verify(e.to_string()))?;
        self.canary
            .seed_head(block_number, profile.canary, profile.coverage);
        Ok(())
    }

    pub fn adopt_auditor(
        &mut self,
        auditor_id: &str,
        key_id: &str,
        public_key: &str,
        active: bool,
    ) {
        self.roster
            .adopt_auditor(auditor_id, key_id, public_key, active);
    }

    pub fn adopt_observer(
        &mut self,
        observer_id: &str,
        key_id: &str,
        public_key: &str,
        registered_height: u64,
        active: bool,
    ) {
        self.roster
            .adopt_observer(observer_id, key_id, public_key, registered_height, active);
    }

    pub fn adopt_commitment(
        &mut self,
        id: &str,
        planter: &str,
        root: &str,
        leaves: u64,
        height: u64,
    ) {
        self.canary
            .adopt_commitment(id, planter, root, leaves, height);
    }

    /// Records a Delta the Block sealed and the Consumer verified.
    pub fn register_delta(&mut self, delta_id: &str, height: u64, publisher: &str) {
        self.canary.register_delta(delta_id, height, publisher);
    }

    /// Replays one Block's roster and canary acts, reading each planter's
    /// keys from the Declaration projection after the Block's Declarations
    /// applied and the registrations from the roster as replayed so far.
    pub fn apply_block(
        &mut self,
        block: ActBlock<'_>,
        declarations: &Declarations,
    ) -> Result<Vec<AcceptedAct>> {
        let outcomes = self
            .roster
            .apply_block(
                block.height,
                block.block_hash,
                block.sealed_at_s,
                block.entries,
                block.log_key_id,
                block.log_key,
            )
            .map_err(|e| Error::Verify(format!("block {}: {e}", block.height)))?;
        let mut accepted = Vec::new();
        for outcome in outcomes {
            match outcome {
                Outcome::Accepted(act) => accepted.push(act),
                Outcome::Rejected(_) => self.rejected += 1,
                Outcome::NotRoster | Outcome::Idempotent => {}
            }
        }
        self.canary
            .push_block(
                block.height,
                block.sealed_at_s,
                block.profile.canary,
                block.profile.coverage,
            )
            .map_err(|e| Error::Verify(format!("block {}: {e}", block.height)))?;
        for (entry_index, entry) in block.entries.iter().enumerate() {
            if entry["type"] != "registry_update" {
                continue;
            }
            let body = &entry["body"];
            if !matches!(
                body["update"]["action"].as_str(),
                Some("canary_commitment" | "canary_reveal")
            ) {
                continue;
            }
            let keys = body["update"]["subject"]
                .as_str()
                .and_then(|subject| declarations.domains().get(subject))
                .map(|domain| wist_core::declaration::publisher_of(domain.current().envelope()))
                .and_then(|publisher| publisher.ok())
                .map(|publisher| publisher.keys)
                .unwrap_or_default();
            self.canary.act(
                Position {
                    block_number: block.height,
                    entry_index,
                },
                body,
                &keys,
            );
        }
        let roster = &self.roster;
        let registered = |at: i64| -> Vec<String> {
            roster
                .registered_at(at)
                .into_iter()
                .map(|(observer_id, _)| observer_id.to_owned())
                .collect()
        };
        self.canary.settle(block.height, &registered);
        self.rejected += self.canary.take_rejected().len() as u64;
        Ok(accepted)
    }
}

pub fn load_replay(conn: &Connection) -> Result<ActReplay> {
    conn.execute_batch(CREATE_REPLAY_STATE)?;
    let state: Option<String> = conn
        .query_row("SELECT state FROM replay_state WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?;
    match state {
        Some(state) => ActReplay::from_state(&state),
        None => Err(Error::Verify(
            "the store carries no act replay state; run a cold start".into(),
        )),
    }
}

pub fn save_state(conn: &Connection, replay: &ActReplay) -> Result<()> {
    conn.execute_batch(CREATE_REPLAY_STATE)?;
    conn.execute(
        "INSERT INTO replay_state(id, state) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET state = excluded.state",
        [replay.state()?],
    )?;
    Ok(())
}

/// Mirrors one accepted roster act into the adopted-state tables at the
/// height of the Block that sealed it: an admission ends its subject's
/// registration and a registration ends the subject's earlier tenure,
/// the only ways a registration ends (WIST-4 §3.1).
pub fn mirror_act(conn: &Connection, act: &AcceptedAct, height: u64) -> Result<()> {
    let height = height as i64;
    match act.action.as_str() {
        "auditor_admit" => {
            conn.execute(
                "INSERT INTO auditors(auditor_id, key_id, public_key, admitted_height, removed_height) VALUES (?1, ?2, ?3, ?4, NULL) ON CONFLICT(auditor_id, key_id) DO UPDATE SET public_key = excluded.public_key, admitted_height = excluded.admitted_height, removed_height = NULL",
                (&act.subject, &act.key_id, &act.public_key, height),
            )?;
            conn.execute(
                "UPDATE observers SET ended_height = ?2 WHERE observer_id = ?1 AND ended_height IS NULL",
                (&act.subject, height),
            )?;
        }
        "observer_register" => {
            conn.execute(
                "UPDATE observers SET ended_height = ?3 WHERE observer_id = ?1 AND key_id <> ?2 AND ended_height IS NULL",
                (&act.subject, &act.key_id, height),
            )?;
            conn.execute(
                "INSERT INTO observers(observer_id, key_id, public_key, registered_height, ended_height) VALUES (?1, ?2, ?3, ?4, NULL) ON CONFLICT(observer_id, key_id) DO UPDATE SET public_key = excluded.public_key, registered_height = excluded.registered_height, ended_height = NULL",
                (&act.subject, &act.key_id, &act.public_key, height),
            )?;
        }
        "auditor_remove" => {
            conn.execute(
                "UPDATE auditors SET removed_height = ?3 WHERE auditor_id = ?1 AND key_id = ?2 AND removed_height IS NULL",
                (&act.subject, &act.key_id, height),
            )?;
        }
        _ => {}
    }
    Ok(())
}

/// Persists the engines and mirrors the commitments still live at
/// `height` into the adopted-state tables.
pub fn save_replay(conn: &Connection, replay: &ActReplay, height: u64) -> Result<()> {
    save_state(conn, replay)?;
    conn.execute_batch(crate::store::CREATE_ADOPTED_STATE)?;
    conn.execute("DELETE FROM canary_commitments", [])?;
    for commitment in replay.canary().live_commitments(height) {
        conn.execute(
            "INSERT INTO canary_commitments(update_id, planter, root, leaves, sealing_height) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                &commitment.id,
                &commitment.planter,
                &commitment.root,
                commitment.leaves as i64,
                commitment.height as i64,
            ),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wist_core::crypto::SigningKey;
    use wist_core::envelope::sign_envelope;

    fn act(action: &str, subject: &str, details: Value, key: &SigningKey, key_id: &str) -> Value {
        let update = json!({
            "wist_version": "1.0.0", "action": action, "subject": subject,
            "effective_at": "2026-08-09T14:00:00Z", "details": details,
        });
        json!({"type": "registry_update", "body": sign_envelope(&update, "update", key_id, key).unwrap()})
    }

    #[test]
    fn log_signed_admission_and_self_signed_registration_are_accepted() {
        let log = SigningKey::from_seed(&[1u8; 32]);
        let auditor = SigningKey::from_seed(&[7u8; 32]);
        let observer = SigningKey::from_seed(&[8u8; 32]);
        let key = |sk: &SigningKey, key_id: &str| json!({"key_id": key_id, "alg": "Ed25519", "public_key": sk.public().to_b64u()});
        let entries = vec![
            act(
                "auditor_admit",
                "audit.sample.net",
                key(&auditor, "a1"),
                &log,
                "log1",
            ),
            act(
                "auditor_admit",
                "forged.sample.net",
                key(&auditor, "a2"),
                &auditor,
                "log1",
            ),
            act(
                "observer_register",
                "watch.sample.net",
                key(&observer, "w1"),
                &observer,
                "w1",
            ),
            act(
                "observer_register",
                "spoof.sample.net",
                key(&observer, "w2"),
                &auditor,
                "w2",
            ),
        ];
        let mut replay = ActReplay::new("graven-test-log");
        replay
            .seed_head(
                0,
                &format!("sha256:{}", "0".repeat(64)),
                ActProfile::default(),
            )
            .unwrap();
        let accepted = replay
            .apply_block(
                ActBlock {
                    height: 1,
                    block_hash: &format!("sha256:{}", "1".repeat(64)),
                    sealed_at_s: 1_786_000_000,
                    entries: &entries,
                    log_key_id: "log1",
                    log_key: &log.public(),
                    profile: ActProfile::default(),
                },
                &Declarations::default(),
            )
            .unwrap();
        let names: Vec<(&str, &str)> = accepted
            .iter()
            .map(|a| (a.action.as_str(), a.subject.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("auditor_admit", "audit.sample.net"),
                ("observer_register", "watch.sample.net")
            ]
        );
        assert_eq!(replay.rejected(), 2);
    }
}
