//! WIST-1 §5.2 and WIST-3 §7.
use crate::error::{Error, Result};
use serde_json::Value;
use wist_core::collection::Limits;
use wist_core::declarations::{Declarations, Effects, Position};
use wist_core::objects::PublisherEnvelope;

#[derive(Debug, Default)]
pub struct KeyHistory {
    declarations: Declarations,
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
        })
    }

    pub fn state(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.declarations)?)
    }

    pub fn declarations(&self) -> &Declarations {
        &self.declarations
    }

    pub fn seed_head(&mut self, epoch_number: u64, epoch_root: &str, sealed_at_s: Option<i64>) {
        self.declarations
            .seed_head(epoch_number, epoch_root, sealed_at_s);
    }

    /// WIST-3 §§7/8: every later Declaration must exceed the highest accepted `seq`, which a
    /// settlement can leave above the current one.
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
                    epoch_number: sealing_height,
                    entry_index: 0,
                },
                0,
                highest_accepted_seq,
                None,
                None,
            )
            .map_err(history_error)
    }

    /// WIST-3 §§7/8: the owner and pre-recovery source the tuple lacks are seeded from the head and
    /// the current Declaration.
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
                epoch_number: head_height,
                entry_index: 0,
            },
            0,
            end_s,
        ));
        self.readopt(domain, "recovery window", window, None)
    }

    /// WIST-3 §§7/8 and WIST-1 §5.2.
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
                epoch_number: head_height,
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

    /// WIST-1 §5.2 under the parameters in force at the Epoch's `sealed_at`; a rejected Declaration
    /// fails the sync.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_epoch(
        &mut self,
        epoch_number: u64,
        epoch_root: &str,
        sealed_at: &str,
        recovery_window_days: i64,
        declaration_activation_epochs: i64,
        limits: &Limits,
        entries: &[Value],
    ) -> Result<Effects> {
        self.declarations
            .apply_epoch(
                epoch_number,
                epoch_root,
                sealed_at,
                recovery_window_days,
                declaration_activation_epochs,
                limits,
                entries,
            )
            .map_err(history_error)
    }

    /// WIST-3 §7.
    pub fn declared(&self, host: &str) -> bool {
        self.declarations.domains().contains_key(host)
    }

    /// WIST-2 §3.3: none inside an open recovery window.
    pub fn declaration_for(&self, domain: &str) -> Option<PublisherEnvelope> {
        let state = self.declarations.domains().get(domain)?;
        let source = state.sealing_source()?;
        serde_json::from_value(source.envelope().clone()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_core::crypto::{b64u_encode, SigningKey};
    use wist_core::envelope::sign_envelope;

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

    struct Chain {
        history: KeyHistory,
        height: Option<u64>,
        activation_epochs: i64,
    }

    impl Chain {
        fn new() -> Self {
            Chain::with_activation(0)
        }

        fn with_activation(activation_epochs: i64) -> Self {
            Chain {
                history: KeyHistory::new(),
                height: None,
                activation_epochs,
            }
        }

        fn seal(&mut self, sealed_at: &str, declarations: &[&Value]) -> Result<Effects> {
            let height = self.height.map_or(0, |h| h + 1);
            let entries: Vec<Value> = declarations
                .iter()
                .map(|d| serde_json::json!({"type": "publisher_declaration", "body": d}))
                .collect();
            let effects = self.history.apply_epoch(
                height,
                &format!("sha256:{height:064}"),
                sealed_at,
                7,
                self.activation_epochs,
                &limits(),
                &entries,
            )?;
            self.height = Some(height);
            Ok(effects)
        }

        fn sealing_key(&self, domain: &str, signer: &Signer) -> bool {
            self.history
                .declaration_for(domain)
                .is_some_and(|envelope| {
                    envelope
                        .publisher
                        .keys
                        .iter()
                        .any(|key| key.kid == signer.kid())
                })
        }
    }

    fn limits() -> Limits {
        let default = |name: &str| {
            wist_core::parameters::spec(name)
                .and_then(|p| p.default)
                .unwrap()
        };
        Limits::new(
            default("collections_max"),
            default("scope_entries_max"),
            default("url_cap_bytes"),
        )
        .unwrap()
    }

    #[test]
    fn an_ordinary_rotation_retires_the_old_key_from_its_epoch() {
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
        assert!(chain.sealing_key("records.example", &pk1));
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
        assert!(!chain.sealing_key("records.example", &pk1));
        assert!(chain.sealing_key("records.example", &pk2));
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
    fn a_recovery_window_withholds_the_sealing_source_and_settles_on_the_legitimate_chain() {
        let pk1 = Signer::new([1u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let atk = Signer::new([90u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let rk2 = Signer::new([12u8; 32]);
        let pk3 = Signer::new([3u8; 32]);
        let domain = "records.example";
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
        assert!(chain.sealing_key("records.example", &atk));
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
        assert!(!chain.sealing_key("records.example", &pk2));
        assert!(!chain.sealing_key("records.example", &atk));
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
        assert!(chain.sealing_key("records.example", &pk3));
        assert!(!chain.sealing_key("records.example", &pk2));
        assert!(!chain.sealing_key("records.example", &atk));
    }

    #[test]
    fn a_fresh_identity_governs_and_only_a_recovery_signer_may_alter_recovery_keys() {
        let pk1 = Signer::new([1u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let pky = Signer::new([51u8; 32]);
        let domain = "records.example";
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
        assert!(chain.sealing_key("records.example", &pky));
        assert!(!chain.sealing_key("records.example", &pk1));
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
        history.seed_head(4, "sha256:anchor", None);
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
            .apply_epoch(
                6,
                "sha256:h6",
                "2026-08-10T00:00:00Z",
                7,
                24,
                &limits(),
                std::slice::from_ref(&entry)
            )
            .is_err());
        history
            .apply_epoch(
                5,
                "sha256:h5",
                "2026-08-10T00:00:00Z",
                7,
                24,
                &limits(),
                &[entry],
            )
            .unwrap();
        assert!(history
            .declaration_for("records.example")
            .is_some_and(|envelope| envelope.publisher.keys[0].kid == pk2.kid()));
    }
}
