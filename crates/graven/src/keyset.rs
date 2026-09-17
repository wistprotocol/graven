//! The Consumer's view of every Publisher's Declaration chain: core's
//! WIST-1 §5.2 replay engine applied Block by Block, seeded from Snapshot
//! state at a cold start and persisted between syncs, plus the WIST-3 §7
//! reading of which Deltas materialize.
use crate::error::{Error, Result};
use reqwest::Url;
use serde_json::Value;
use std::collections::HashMap;
use wist_core::declarations::{Declarations, Effects, Position};
use wist_core::delta::delta_id;
use wist_core::objects::PublisherEnvelope;
use wist_core::objects::{DeltaEnvelope, Publisher};

/// A sealed Delta that verifies under WIST-1 §5.2: its ID, the Publisher
/// whose key signed it — the record key WIST-3 §7 uses — and whether
/// §7's one-URL-one-Publisher rule lets it materialize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelta {
    pub id: String,
    pub publisher: String,
    pub materializes: bool,
}

#[derive(Debug, Default)]
pub struct KeyHistory {
    declarations: Declarations,
    publishers: HashMap<String, Publisher>,
}

pub fn url_authority(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

fn history_error(e: wist_core::Error) -> Error {
    Error::PublisherVerify(e.to_string())
}

impl KeyHistory {
    pub fn new() -> KeyHistory {
        KeyHistory::default()
    }

    pub fn from_state(state: &str) -> Result<KeyHistory> {
        Ok(KeyHistory {
            declarations: serde_json::from_str(state)?,
            publishers: HashMap::new(),
        })
    }

    pub fn state(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.declarations)?)
    }

    pub fn declarations(&self) -> &Declarations {
        &self.declarations
    }

    /// Starts the accepted prefix at a Snapshot's `log_position`.
    pub fn seed_head(&mut self, block_number: u64, block_hash: &str) {
        self.declarations.seed_head(block_number, block_hash, None);
    }

    /// WIST-3 §§7/8: adopts a Snapshot's `declaration` tuple — the
    /// Declaration in force at its sealing height and the highest accepted
    /// `seq`, which a settlement that restored a lower-sequence head leaves
    /// above the current `seq` and every later Declaration must exceed.
    pub fn adopt_domain(
        &mut self,
        domain: &str,
        declaration: &Value,
        sealing_height: u64,
        highest_accepted_seq: u64,
    ) -> Result<()> {
        self.declarations
            .adopt(
                domain,
                declaration.clone(),
                Position {
                    block_number: sealing_height,
                    entry_index: 0,
                },
                0,
                highest_accepted_seq,
                None,
                None,
            )
            .map_err(history_error)
    }

    /// WIST-3 §§7/8: restores an open recovery window from its tuple. The
    /// tuple carries the chain head and the frozen end; a Consumer never
    /// admits Deltas, so the owner and pre-recovery source it lacks are
    /// seeded from the head and the current Declaration.
    pub fn adopt_window(
        &mut self,
        domain: &str,
        window_end: &str,
        head: &Value,
        head_height: u64,
    ) -> Result<()> {
        let end_s = i128::from(wist_core::timestamp::log_seconds(window_end)?);
        let window = Some((
            head.clone(),
            Position {
                block_number: head_height,
                entry_index: 0,
            },
            0,
            end_s,
        ));
        self.readopt(domain, "recovery window", window, None)
    }

    /// WIST-3 §§7/8: restores a pending fresh identity from its tuple —
    /// the pending head, its sealing height and the activation height at
    /// which WIST-1 §5.2 makes it current unless a reversal arrives first.
    pub fn adopt_pending(
        &mut self,
        domain: &str,
        head: &Value,
        head_height: u64,
        activation_height: u64,
    ) -> Result<()> {
        let pending = Some((
            head.clone(),
            Position {
                block_number: head_height,
                entry_index: 0,
            },
            0,
            activation_height,
        ));
        self.readopt(domain, "pending declaration", None, pending)
    }

    fn readopt(
        &mut self,
        domain: &str,
        tuple: &str,
        window: Option<(Value, Position, i64, i128)>,
        pending: Option<(Value, Position, i64, u64)>,
    ) -> Result<()> {
        let current = self.declarations.domains().get(domain).ok_or_else(|| {
            Error::PublisherVerify(format!(
                "{domain}: {tuple} tuple without a declaration tuple"
            ))
        })?;
        let (envelope, position, sealed_at_s, floor) = (
            current.current().envelope().clone(),
            current.current().position(),
            current.current().sealed_at_s(),
            current.highest_accepted_seq(),
        );
        let window = window.or_else(|| {
            current.window().map(|w| {
                (
                    w.head().envelope().clone(),
                    w.head().position(),
                    w.head().sealed_at_s(),
                    w.end_s(),
                )
            })
        });
        let pending = pending.or_else(|| {
            current.pending().map(|p| {
                (
                    p.head().envelope().clone(),
                    p.head().position(),
                    p.head().sealed_at_s(),
                    p.activation_height(),
                )
            })
        });
        self.declarations
            .adopt(
                domain,
                envelope,
                position,
                sealed_at_s,
                floor,
                window,
                pending,
            )
            .map_err(history_error)
    }

    /// Applies one sealed Block's `publisher_declaration` Entries under
    /// WIST-1 §5.2 with the `recovery_window_days` and
    /// `declaration_activation_blocks` in force at its `sealed_at`; a
    /// Block whose Declarations the shared rules reject fails the sync.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_block(
        &mut self,
        block_number: u64,
        prev_block_hash: &str,
        block_hash: &str,
        sealed_at: &str,
        recovery_window_days: i64,
        declaration_activation_blocks: i64,
        entries: &[Value],
    ) -> Result<Effects> {
        self.declarations
            .apply_block(
                block_number,
                prev_block_hash,
                block_hash,
                sealed_at,
                recovery_window_days,
                declaration_activation_blocks,
                entries,
            )
            .map_err(history_error)
    }

    /// True once the host's own Declaration chain exists, from which
    /// height only that Publisher's Deltas materialize for its URLs
    /// (WIST-3 §7).
    pub fn declared(&self, host: &str) -> bool {
        self.declarations.domains().contains_key(host)
    }

    fn publisher(&mut self, hash: &str, envelope: &Value) -> Result<&Publisher> {
        if !self.publishers.contains_key(hash) {
            let publisher =
                wist_core::declaration::publisher_of(envelope).map_err(Error::PublisherVerify)?;
            self.publishers.insert(hash.to_owned(), publisher);
        }
        Ok(&self.publishers[hash])
    }

    /// WIST-2 §3.3: the Declaration a Label or dispute of `domain` is
    /// validated under at the current projection — the one a Delta is
    /// sealed under, none inside an open recovery window.
    pub fn declaration_for(&self, domain: &str) -> Option<PublisherEnvelope> {
        let state = self.declarations.domains().get(domain)?;
        let source = state.delta_sealing_source()?;
        serde_json::from_value(source.envelope().clone()).ok()
    }

    /// WIST-1 §7's precedence for a sealed Delta: complete field validation
    /// and §3.1 major support, the presence and parameter-profile caps, the
    /// §5.2 author binding and scope under the Declaration in force for
    /// sealing at the current projection, then the §3.4 clock check against
    /// the committing Block's `sealed_at` and the allowance accepted there.
    /// A Delta sealed inside an open recovery window, which WIST-1 §5.2
    /// queues instead, verifies under nothing.
    pub fn verify_delta(
        &mut self,
        height: u64,
        sealed_at_s: i64,
        profile: &DeltaProfile,
        entry_body: &Value,
    ) -> Result<VerifiedDelta> {
        let diagnostic = |code: &str, detail: &str| {
            Error::PublisherVerify(format!("{code}: height {height}: {detail}"))
        };
        wist_core::delta_fields::validate_static(
            entry_body,
            profile.url_cap_bytes,
            profile.commitment_cap_bytes,
        )
        .map_err(|code| diagnostic(code, "Delta field, version or static check failed"))?;
        let domain = wist_core::delta::publisher(&entry_body["delta"])?.to_string();
        let env: DeltaEnvelope = serde_json::from_value(entry_body.clone())?;
        let url = Url::parse(&env.delta.url)
            .map_err(|e| diagnostic("WIST1-E03", &format!("delta url {}: {e}", env.delta.url)))?;
        let host = url_authority(&url).ok_or_else(|| {
            diagnostic(
                "WIST1-E03",
                &format!("delta url {}: no authority", env.delta.url),
            )
        })?;
        let (hash, envelope) = {
            let state = self
                .declarations
                .domains()
                .get(&domain)
                .ok_or_else(|| diagnostic("WIST1-E02", &format!("{domain}: no Declaration")))?;
            let source = state.delta_sealing_source().ok_or_else(|| {
                diagnostic(
                    "WIST1-E02",
                    &format!("{domain}: sealed inside an open recovery window"),
                )
            })?;
            (source.hash().to_owned(), source.envelope().clone())
        };
        let publisher = self.publisher(&hash, &envelope)?;
        wist_core::declaration::verify_delta_authority(&[publisher], entry_body).map_err(
            |code| {
                diagnostic(
                    code,
                    &format!("{domain}: Delta signing or scope authority failed"),
                )
            },
        )?;
        wist_core::delta_fields::verify_clock(entry_body, sealed_at_s, profile.clock_skew_seconds)
            .map_err(|code| {
                diagnostic(
                    code,
                    &format!(
                        "{domain}: observed_at {} exceeds the sealing clock allowance",
                        env.delta.observed_at
                    ),
                )
            })?;
        Ok(VerifiedDelta {
            id: delta_id(&entry_body["delta"])?,
            materializes: domain == host || !self.declared(&host),
            publisher: domain,
        })
    }
}

/// The parameter profile a sealed Delta is validated under: the caps and
/// clock allowance the accepted schedule holds at its Block's `sealed_at`
/// (WIST-1 §§3.2/3.4/3.6, WIST-4 §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaProfile {
    pub url_cap_bytes: i64,
    pub commitment_cap_bytes: i128,
    pub clock_skew_seconds: i64,
}

impl DeltaProfile {
    pub fn from_schedule(schedule: &wist_core::parameters::Schedule, at_s: i64) -> Self {
        let value = |name: &str| schedule.value_at(name, at_s).unwrap();
        Self {
            url_cap_bytes: value("url_cap_bytes"),
            commitment_cap_bytes: wist_core::delta_fields::commitment_cap(
                value("extract_cap_bytes"),
                value("links_cap_bytes"),
                value("summary_cap_bytes"),
            ),
            clock_skew_seconds: value("clock_skew_seconds"),
        }
    }
}

impl Default for DeltaProfile {
    fn default() -> Self {
        let default = |name: &str| {
            wist_core::parameters::spec(name)
                .and_then(|p| p.default)
                .unwrap()
        };
        Self {
            url_cap_bytes: default("url_cap_bytes"),
            commitment_cap_bytes: wist_core::delta_fields::commitment_cap(
                default("extract_cap_bytes"),
                default("links_cap_bytes"),
                default("summary_cap_bytes"),
            ),
            clock_skew_seconds: default("clock_skew_seconds"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_core::crypto::{b64u_encode, SigningKey};
    use wist_core::envelope::sign_envelope;

    const LATE_S: i64 = 1_800_000_000;

    struct Signer {
        seed: [u8; 32],
        sk: SigningKey,
    }

    impl Signer {
        fn new(seed: [u8; 32]) -> Self {
            Signer {
                seed,
                sk: SigningKey::from_seed(&seed),
            }
        }

        fn public_b64u(&self) -> String {
            b64u_encode(
                &ed25519_dalek::SigningKey::from_bytes(&self.seed)
                    .verifying_key()
                    .to_bytes(),
            )
        }

        fn kid(&self) -> String {
            wist_core::objects::publisher::thumbprint(&self.public_b64u())
        }
    }

    fn key_entry(signer: &Signer, not_before: &str) -> Value {
        serde_json::to_value(wist_core::objects::PublisherKey::new(
            &signer.public_b64u(),
            wist_core::timestamp::log_seconds(not_before).unwrap() as u64,
            None,
        ))
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn decl(
        domain: &str,
        seq: u64,
        prev: Option<&str>,
        keys: Vec<Value>,
        recovery_keys: Option<Vec<Value>>,
        scope: Option<Vec<&str>>,
        sign: &Signer,
    ) -> Value {
        let mut doc = serde_json::json!({
            "wist_version": "1.0.0",
            "domain": domain,
            "keys": keys,
            "seq": seq,
        });
        if let Some(p) = prev {
            doc["prev_declaration"] = p.into();
        }
        if let Some(rk) = recovery_keys {
            doc["recovery_keys"] = serde_json::json!(rk);
        }
        if let Some(scope) = scope {
            doc["subdomain_scope"] = serde_json::json!(scope);
        }
        sign_envelope(&doc, "publisher", &sign.kid(), &sign.sk).unwrap()
    }

    fn hash_of(declaration: &Value) -> String {
        wist_core::declaration::inner_hash(declaration).unwrap()
    }

    fn delta_env(signer: &Signer, key_id: &str, url: &str, observed_at: &str) -> Value {
        let delta = serde_json::json!({
            "wist_version": "1.0.0",
            "publisher": "records.example",
            "url": url,
            "change_type": "new",
            "observed_at": observed_at,
            "payload": {"commitment": format!("hmac-sha256:{}", "0".repeat(64)), "alg": "HMAC-SHA256", "bytes": 0},
            "meta": {"lang": "en"},
        });
        sign_envelope(&delta, "delta", key_id, &signer.sk).unwrap()
    }

    /// Seals one Block carrying the given Declarations at the next height.
    struct Chain {
        history: KeyHistory,
        height: Option<u64>,
        activation_blocks: i64,
    }

    impl Chain {
        fn new() -> Self {
            Chain::with_activation(0)
        }

        fn with_activation(activation_blocks: i64) -> Self {
            Chain {
                history: KeyHistory::new(),
                height: None,
                activation_blocks,
            }
        }

        fn seal(&mut self, sealed_at: &str, declarations: &[&Value]) -> Result<Effects> {
            let height = self.height.map_or(0, |h| h + 1);
            let entries: Vec<Value> = declarations
                .iter()
                .map(|d| serde_json::json!({"type": "publisher_declaration", "body": d}))
                .collect();
            let prev = self
                .height
                .map_or("sha256:genesis".to_string(), |h| format!("h{h}"));
            let effects = self.history.apply_block(
                height,
                &prev,
                &format!("h{height}"),
                sealed_at,
                7,
                self.activation_blocks,
                &entries,
            )?;
            self.height = Some(height);
            Ok(effects)
        }

        fn verifies(&mut self, delta: &Value) -> bool {
            self.history
                .verify_delta(
                    self.height.unwrap_or(0),
                    LATE_S,
                    &DeltaProfile::default(),
                    delta,
                )
                .is_ok()
        }
    }

    #[test]
    fn a_declared_key_verifies_and_unknown_or_forged_signatures_do_not() {
        let pk1 = Signer::new([1u8; 32]);
        let pk9 = Signer::new([9u8; 32]);
        let mut chain = Chain::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "2026-08-09T00:00:00Z")],
            None,
            None,
            &pk1,
        );
        chain.seal("2026-08-09T12:00:00Z", &[&decl0]).unwrap();
        let url = "https://records.example/a";
        let ok = delta_env(&pk1, &pk1.kid(), url, "2026-08-09T12:00:00Z");
        let verified = chain
            .history
            .verify_delta(0, LATE_S, &DeltaProfile::default(), &ok)
            .unwrap();
        assert_eq!(verified.publisher, "records.example");
        assert!(verified.materializes);
        let unknown = delta_env(&pk9, &pk9.kid(), url, "2026-08-09T12:00:00Z");
        let err = chain
            .history
            .verify_delta(0, LATE_S, &DeltaProfile::default(), &unknown)
            .unwrap_err();
        assert!(err.to_string().contains("WIST1-E02"), "{err}");
        let forged = delta_env(&pk9, &pk1.kid(), url, "2026-08-09T12:00:00Z");
        let err = chain
            .history
            .verify_delta(0, LATE_S, &DeltaProfile::default(), &forged)
            .unwrap_err();
        assert!(err.to_string().contains("WIST1-E01"), "{err}");
        let early = delta_env(&pk1, &pk1.kid(), url, "2026-08-08T00:00:00Z");
        let err = chain
            .history
            .verify_delta(0, LATE_S, &DeltaProfile::default(), &early)
            .unwrap_err();
        assert!(err.to_string().contains("WIST1-E02"), "{err}");
    }

    #[test]
    fn an_ordinary_rotation_retires_the_old_key_from_its_block() {
        let pk1 = Signer::new([1u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let mut chain = Chain::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "2026-08-09T00:00:00Z")],
            None,
            None,
            &pk1,
        );
        chain.seal("2026-08-09T12:00:00Z", &[&decl0]).unwrap();
        let url = "https://records.example/a";
        assert!(chain.verifies(&delta_env(&pk1, &pk1.kid(), url, "2026-08-09T12:00:00Z")));
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash_of(&decl0)),
            vec![key_entry(&pk2, "2026-08-09T00:00:00Z")],
            None,
            None,
            &pk1,
        );
        let effects = chain.seal("2026-08-10T00:00:00Z", &[&decl1]).unwrap();
        assert_eq!(
            effects.installations[0].decision,
            Some(wist_core::declaration::Decision::Ordinary)
        );
        assert!(!chain.verifies(&delta_env(&pk1, &pk1.kid(), url, "2026-08-09T12:00:00Z")));
        assert!(chain.verifies(&delta_env(&pk2, &pk2.kid(), url, "2026-08-09T12:00:00Z")));
        let stale = decl(
            "records.example",
            1,
            Some(&hash_of(&decl0)),
            vec![key_entry(&pk1, "2026-08-09T00:00:00Z")],
            None,
            None,
            &pk1,
        );
        let err = chain.seal("2026-08-11T00:00:00Z", &[&stale]).unwrap_err();
        assert!(err.to_string().contains("WIST1-E08"), "{err}");
    }

    #[test]
    fn a_recovery_window_queues_deltas_and_settles_on_the_legitimate_chain() {
        let pk1 = Signer::new([1u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let atk = Signer::new([90u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let rk2 = Signer::new([12u8; 32]);
        let pk3 = Signer::new([3u8; 32]);
        let domain = "records.example";
        let url = "https://records.example/a";
        let mut chain = Chain::new();
        let decl0 = decl(
            domain,
            0,
            None,
            vec![key_entry(&pk1, "2026-08-01T00:00:00Z")],
            Some(vec![key_entry(&rk1, "2026-08-01T00:00:00Z")]),
            None,
            &pk1,
        );
        chain.seal("2026-08-01T00:00:00Z", &[&decl0]).unwrap();
        let theft = decl(
            domain,
            1,
            Some(&hash_of(&decl0)),
            vec![key_entry(&atk, "2026-08-01T00:00:00Z")],
            Some(vec![key_entry(&rk1, "2026-08-01T00:00:00Z")]),
            None,
            &pk1,
        );
        chain.seal("2026-08-02T00:00:00Z", &[&theft]).unwrap();
        assert!(chain.verifies(&delta_env(&atk, &atk.kid(), url, "2026-08-02T00:00:00Z")));
        let recovery = decl(
            domain,
            2,
            Some(&hash_of(&theft)),
            vec![key_entry(&pk2, "2026-08-01T00:00:00Z")],
            Some(vec![key_entry(&rk2, "2026-08-01T00:00:00Z")]),
            None,
            &rk1,
        );
        let effects = chain.seal("2026-08-03T00:00:00Z", &[&recovery]).unwrap();
        assert!(effects.installations[0].opens_window);
        assert!(!chain.verifies(&delta_env(&pk2, &pk2.kid(), url, "2026-08-03T00:00:00Z")));
        assert!(!chain.verifies(&delta_env(&atk, &atk.kid(), url, "2026-08-03T00:00:00Z")));
        let follower = decl(
            domain,
            3,
            Some(&hash_of(&recovery)),
            vec![key_entry(&pk3, "2026-08-01T00:00:00Z")],
            Some(vec![key_entry(&rk2, "2026-08-01T00:00:00Z")]),
            None,
            &pk2,
        );
        chain.seal("2026-08-04T00:00:00Z", &[&follower]).unwrap();
        let competitor = decl(
            domain,
            4,
            Some(&hash_of(&follower)),
            vec![key_entry(&atk, "2026-08-01T00:00:00Z")],
            Some(vec![key_entry(&rk2, "2026-08-01T00:00:00Z")]),
            None,
            &atk,
        );
        chain.seal("2026-08-05T00:00:00Z", &[&competitor]).unwrap();
        let effects = chain.seal("2026-08-11T00:00:00Z", &[]).unwrap();
        assert_eq!(effects.settlements.len(), 1);
        assert_eq!(effects.settlements[0].restored.hash(), hash_of(&follower));
        assert_eq!(effects.settlements[0].superseded.len(), 1);
        assert!(chain.verifies(&delta_env(&pk3, &pk3.kid(), url, "2026-08-11T00:00:00Z")));
        assert!(!chain.verifies(&delta_env(&pk2, &pk2.kid(), url, "2026-08-11T00:00:00Z")));
        assert!(!chain.verifies(&delta_env(&atk, &atk.kid(), url, "2026-08-11T00:00:00Z")));
    }

    #[test]
    fn a_fresh_identity_governs_and_only_a_recovery_signer_may_alter_recovery_keys() {
        let pk1 = Signer::new([1u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let pky = Signer::new([51u8; 32]);
        let domain = "records.example";
        let url = "https://records.example/a";
        let mut chain = Chain::new();
        let decl0 = decl(
            domain,
            0,
            None,
            vec![key_entry(&pk1, "2026-08-01T00:00:00Z")],
            Some(vec![key_entry(&rk1, "2026-08-01T00:00:00Z")]),
            None,
            &pk1,
        );
        chain.seal("2026-08-01T00:00:00Z", &[&decl0]).unwrap();
        let altered = decl(
            domain,
            1,
            Some(&hash_of(&decl0)),
            vec![key_entry(&pky, "2026-08-01T00:00:00Z")],
            None,
            None,
            &pky,
        );
        let err = chain.seal("2026-08-02T00:00:00Z", &[&altered]).unwrap_err();
        assert!(err.to_string().contains("WIST1-E08"), "{err}");
        let mut chain = Chain::new();
        chain.seal("2026-08-01T00:00:00Z", &[&decl0]).unwrap();
        let fresh = decl(
            domain,
            1,
            Some(&hash_of(&decl0)),
            vec![key_entry(&pky, "2026-08-01T00:00:00Z")],
            Some(vec![key_entry(&rk1, "2026-08-01T00:00:00Z")]),
            None,
            &pky,
        );
        let effects = chain.seal("2026-08-02T00:00:00Z", &[&fresh]).unwrap();
        assert!(effects.installations[0].resets_identity);
        assert!(chain.verifies(&delta_env(&pky, &pky.kid(), url, "2026-08-02T00:00:00Z")));
        assert!(!chain.verifies(&delta_env(&pk1, &pk1.kid(), url, "2026-08-02T00:00:00Z")));
    }

    #[test]
    fn scope_and_self_declaration_decide_materialization() {
        let pk1 = Signer::new([1u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let mut chain = Chain::new();
        let parent = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "2026-08-09T00:00:00Z")],
            None,
            Some(vec!["sub.records.example"]),
            &pk1,
        );
        chain.seal("2026-08-09T12:00:00Z", &[&parent]).unwrap();
        let scoped = delta_env(
            &pk1,
            &pk1.kid(),
            "https://sub.records.example/a",
            "2026-08-09T12:00:00Z",
        );
        let verified = chain
            .history
            .verify_delta(0, LATE_S, &DeltaProfile::default(), &scoped)
            .unwrap();
        assert!(verified.materializes);
        let outside = delta_env(
            &pk1,
            &pk1.kid(),
            "https://other.records.example/a",
            "2026-08-09T12:00:00Z",
        );
        let err = chain
            .history
            .verify_delta(0, LATE_S, &DeltaProfile::default(), &outside)
            .unwrap_err();
        assert!(err.to_string().contains("WIST1-E03"), "{err}");
        let own = decl(
            "sub.records.example",
            0,
            None,
            vec![key_entry(&pk2, "2026-08-09T00:00:00Z")],
            None,
            None,
            &pk2,
        );
        chain.seal("2026-08-09T13:00:00Z", &[&own]).unwrap();
        let verified = chain
            .history
            .verify_delta(1, LATE_S, &DeltaProfile::default(), &scoped)
            .unwrap();
        assert!(
            !verified.materializes,
            "the subdomain's own Declaration takes its URLs"
        );
    }

    #[test]
    fn state_round_trips_and_a_seeded_head_continues_the_chain() {
        let pk1 = Signer::new([1u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "2026-08-09T00:00:00Z")],
            None,
            None,
            &pk1,
        );
        let mut history = KeyHistory::new();
        history
            .adopt_domain("records.example", &decl0, 4, 0)
            .unwrap();
        history.seed_head(4, "sha256:anchor");
        let mut history = KeyHistory::from_state(&history.state().unwrap()).unwrap();
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash_of(&decl0)),
            vec![key_entry(&pk2, "2026-08-09T00:00:00Z")],
            None,
            None,
            &pk1,
        );
        let entry = serde_json::json!({"type": "publisher_declaration", "body": decl1});
        assert!(history
            .apply_block(
                6,
                "sha256:anchor",
                "h6",
                "2026-08-10T00:00:00Z",
                7,
                24,
                std::slice::from_ref(&entry)
            )
            .is_err());
        history
            .apply_block(
                5,
                "sha256:anchor",
                "h5",
                "2026-08-10T00:00:00Z",
                7,
                24,
                &[entry],
            )
            .unwrap();
        let url = "https://records.example/a";
        assert!(history
            .verify_delta(
                5,
                LATE_S,
                &DeltaProfile::default(),
                &delta_env(&pk2, &pk2.kid(), url, "2026-08-09T12:00:00Z")
            )
            .is_ok());
    }

    #[test]
    fn signed_publisher_attribution_vectors_select_only_the_named_author() {
        let root = std::env::var_os("WIST_SPEC_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
            });
        let vector: Value = serde_json::from_slice(
            &std::fs::read(root.join("vectors/wist1/delta-attribution.json")).unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            if case.get("feed_domain").is_some() {
                continue;
            }
            for reverse in [false, true] {
                let mut declarations: Vec<&Value> =
                    case["declarations"].as_array().unwrap().iter().collect();
                if reverse {
                    declarations.reverse();
                }
                let mut chain = Chain::new();
                for (index, declaration) in declarations.iter().enumerate() {
                    chain
                        .seal(&format!("2026-08-01T{index:02}:00:00Z"), &[declaration])
                        .unwrap();
                }
                for (index, envelope) in case["envelopes"].as_array().unwrap().iter().enumerate() {
                    let original = envelope.clone();
                    let actual =
                        chain
                            .history
                            .verify_delta(0, LATE_S, &DeltaProfile::default(), envelope);
                    assert_eq!(
                        actual.is_ok(),
                        case["expected"][index] == "accepted",
                        "{}: {actual:?}",
                        case["name"]
                    );
                    if let Ok(verified) = actual {
                        assert_eq!(verified.publisher, envelope["delta"]["publisher"]);
                        assert_eq!(verified.id, case["delta_ids"][index]);
                    }
                    assert_eq!(*envelope, original);
                }
            }
        }
    }
}
