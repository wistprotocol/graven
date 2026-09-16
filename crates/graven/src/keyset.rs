use crate::error::{Error, Result};
use reqwest::Url;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use wist_core::crypto::hex_encode;
use wist_core::delta::delta_id;
use wist_core::objects::{DeltaEnvelope, Publisher, PublisherEnvelope};

/// A sealed Delta that verifies: its ID, the domain of the Publisher
/// whose key signed it — the record key WIST-3 §7 uses — and whether
/// §7's one-URL-one-Publisher rule lets it materialize.
/// How a sealed Declaration relates to its domain's accepted chain
/// (WIST-1 §5.2, ADR-0023).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Duplicate,
    Initial,
    Ordinary,
    Recovery,
    FreshIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelta {
    pub id: String,
    pub publisher: String,
    pub materializes: bool,
}

struct DeclRecord {
    seq: u64,
    height: u64,
    superseded: bool,
    window_end: Option<jiff::Timestamp>,
    publisher: Publisher,
    envelope: Value,
    hash: String,
}

#[derive(Default)]
pub struct KeyHistory {
    domains: HashMap<String, Vec<DeclRecord>>,
    floors: HashMap<String, u64>,
}

pub fn url_authority(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

fn publisher_hash(publisher_value: &Value) -> Result<String> {
    let canon = wist_core::jcs::canonicalize(publisher_value)?;
    Ok(format!("sha256:{}", hex_encode(&Sha256::digest(&canon))))
}

fn parse_timestamp(domain: &str, seq: u64, raw: &str) -> Result<jiff::Timestamp> {
    raw.parse::<jiff::Timestamp>()
        .map_err(|e| Error::PublisherVerify(format!("{domain} seq {seq}: sealed_at {raw}: {e}")))
}

impl KeyHistory {
    pub fn new() -> KeyHistory {
        KeyHistory::default()
    }

    pub fn add_baseline(&mut self, height: u64, envelope: &Value) -> Result<()> {
        let env: PublisherEnvelope = serde_json::from_value(envelope.clone())?;
        let publisher_value = envelope
            .get("publisher")
            .ok_or_else(|| Error::PublisherVerify("baseline envelope missing publisher".into()))?;
        let hash = publisher_hash(publisher_value)?;
        let domain = env.publisher.domain.clone();
        self.domains.entry(domain).or_default().push(DeclRecord {
            seq: env.publisher.seq,
            height,
            superseded: false,
            window_end: None,
            publisher: env.publisher,
            envelope: envelope.clone(),
            hash,
        });
        Ok(())
    }

    /// WIST-1 §5.2 / WIST-3 §7: the highest accepted `seq` a Snapshot's
    /// `declaration` tuple carries, which a settlement that restored a
    /// lower-sequence head leaves above the current `seq`; every later
    /// Declaration must exceed it.
    pub fn adopt_floor(&mut self, domain: &str, seq: u64) {
        let floor = self.floors.entry(domain.to_owned()).or_insert(0);
        *floor = (*floor).max(seq);
    }

    /// WIST-3 §§7/8: restore an open recovery window from its tuple. The
    /// recovery-chain head is baselined at its own height when it is not
    /// the current Declaration, and the window end is set on it so
    /// followers chain off the head and fresh identities inside the
    /// window are superseded.
    pub fn adopt_window(
        &mut self,
        domain: &str,
        window_end: &str,
        head: &Value,
        head_height: u64,
    ) -> Result<()> {
        let head_hash = head
            .get("publisher")
            .ok_or_else(|| Error::PublisherVerify("window head envelope missing publisher".into()))
            .and_then(publisher_hash)?;
        let known = self
            .domains
            .get(domain)
            .is_some_and(|entries| entries.iter().any(|e| e.hash == head_hash));
        if !known {
            self.add_baseline(head_height, head)?;
        }
        let end: jiff::Timestamp = window_end.parse().map_err(|e| {
            Error::PublisherVerify(format!("{domain}: recovery window end {window_end}: {e}"))
        })?;
        if let Some(record) = self
            .domains
            .get_mut(domain)
            .and_then(|entries| entries.iter_mut().find(|e| e.hash == head_hash))
        {
            record.window_end = Some(end);
        }
        Ok(())
    }

    /// WIST-3 §8 step 10: restore an open recovery window a Snapshot
    /// carries, so a Declaration sealed inside it is superseded at the
    /// window's end exactly as it would be on a full replay.
    pub fn open_window(&mut self, domain: &str, window_end: &str) -> Result<()> {
        let end: jiff::Timestamp = window_end.parse().map_err(|e| {
            Error::PublisherVerify(format!("{domain}: recovery window end {window_end}: {e}"))
        })?;
        if let Some(record) = self
            .domains
            .get_mut(domain)
            .and_then(|entries| entries.iter_mut().rfind(|e| !e.superseded))
        {
            record.window_end = Some(end);
        }
        Ok(())
    }

    /// Admits a sealed Declaration under WIST-1 §5.2 and ADR-0023 through
    /// core's shared rules and says how it relates to the accepted chain.
    /// `recovery_window_days` is the value in force at the sealing Block,
    /// which freezes a recovery window's end (WIST-1 §5.2).
    pub fn add_declaration(
        &mut self,
        height: u64,
        sealed_at: &str,
        recovery_window_days: i64,
        envelope: &Value,
    ) -> Result<Admission> {
        let env: PublisherEnvelope = serde_json::from_value(envelope.clone())?;
        let publisher_value = envelope.get("publisher").ok_or_else(|| {
            Error::PublisherVerify("declaration envelope missing publisher".into())
        })?;
        let hash = publisher_hash(publisher_value)?;
        let domain = env.publisher.domain.clone();
        let seq = env.publisher.seq;
        let floor = self.floors.get(&domain).copied().unwrap_or(0);
        let entries = self.domains.entry(domain.clone()).or_default();
        if entries.iter().any(|e| e.hash == hash) {
            return Ok(Admission::Duplicate);
        }
        let rejection = |(code, detail): wist_core::declaration::Rejection| {
            Error::PublisherVerify(format!("{code}: {domain} seq {seq}: {detail}"))
        };
        let head = entries.iter().rev().find(|e| !e.superseded);
        let (admission, sealed, window_end) = match head {
            None => {
                wist_core::declaration::evaluate_initial(envelope).map_err(rejection)?;
                if seq <= floor && self.floors.contains_key(&domain) {
                    return Err(Error::PublisherVerify(format!(
                        "WIST1-E08: {domain} seq {seq}: not greater than the accepted sequence floor {floor}"
                    )));
                }
                (
                    Admission::Initial,
                    parse_timestamp(&domain, seq, sealed_at)?,
                    None,
                )
            }
            Some(pred) => {
                let decision = wist_core::declaration::evaluate_with_heads(
                    &pred.envelope,
                    None,
                    floor.max(pred.seq),
                    envelope,
                )
                .map_err(rejection)?;
                let sealed = parse_timestamp(&domain, seq, sealed_at)?;
                let admission = match decision {
                    wist_core::declaration::Decision::Unchanged => return Ok(Admission::Duplicate),
                    wist_core::declaration::Decision::Ordinary => Admission::Ordinary,
                    wist_core::declaration::Decision::Recovery => Admission::Recovery,
                    wist_core::declaration::Decision::FreshIdentity => Admission::FreshIdentity,
                };
                let window_end = if admission == Admission::Recovery {
                    Some(
                        sealed
                            .checked_add(jiff::SignedDuration::from_secs(
                                recovery_window_days.saturating_mul(86_400),
                            ))
                            .map_err(|e| {
                                Error::PublisherVerify(format!(
                                    "{domain} seq {seq}: recovery window overflow: {e}"
                                ))
                            })?,
                    )
                } else {
                    pred.window_end
                };
                (admission, sealed, window_end)
            }
        };

        // WIST-1 §5.2: inside an open recovery window only the chain that
        // legitimately follows the recovery Declaration takes effect. An
        // ordinary or recovery rotation off the chain head is that chain; a
        // fresh identity is not, and is superseded at the window's end.
        let recovery = admission == Admission::Recovery;
        let fresh = admission == Admission::FreshIdentity;
        let inside_window = window_end.is_some_and(|end| sealed < end);
        let superseded = fresh && inside_window;
        entries.push(DeclRecord {
            seq,
            height,
            superseded,
            window_end: if superseded || !inside_window {
                if recovery {
                    window_end
                } else {
                    None
                }
            } else {
                window_end
            },
            publisher: env.publisher,
            envelope: envelope.clone(),
            hash,
        });
        let floor = self.floors.entry(domain).or_insert(0);
        *floor = (*floor).max(seq);
        Ok(admission)
    }

    fn resolve(&self, domain: &str, height: u64) -> Result<&DeclRecord> {
        let entries = self.domains.get(domain).ok_or_else(|| {
            Error::PublisherVerify(format!("{domain}: no declaration at height {height}"))
        })?;
        let mut winner: Option<&DeclRecord> = None;
        for entry in entries
            .iter()
            .filter(|e| e.height <= height && !e.superseded)
        {
            winner = Some(entry);
        }
        winner.ok_or_else(|| {
            Error::PublisherVerify(format!("{domain}: no declaration at height <= {height}"))
        })
    }

    /// True once the host's own `seq`-0 Declaration has sealed, from
    /// which height only that Publisher's Deltas materialize for its
    /// URLs (WIST-3 §7).
    pub fn self_declared_at(&self, host: &str, height: u64) -> bool {
        self.domains.get(host).is_some_and(|entries| {
            entries
                .iter()
                .any(|e| e.seq == 0 && e.height <= height && !e.superseded)
        })
    }

    /// WIST-1 §7's precedence for a sealed Delta: complete field validation
    /// and §3.1 major support, the presence and parameter-profile caps, the
    /// §5.2 author binding and scope, then the §3.4 clock check against the
    /// committing Block's `sealed_at` and the allowance accepted there.
    pub fn verify_delta(
        &self,
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
        let domain = wist_core::delta::publisher(&entry_body["delta"])?;
        let env: DeltaEnvelope = serde_json::from_value(entry_body.clone())?;
        let url = Url::parse(&env.delta.url)
            .map_err(|e| diagnostic("WIST1-E03", &format!("delta url {}: {e}", env.delta.url)))?;
        let host = url_authority(&url).ok_or_else(|| {
            diagnostic(
                "WIST1-E03",
                &format!("delta url {}: no authority", env.delta.url),
            )
        })?;
        let record = self.resolve(domain, height)?;
        let domain = domain.to_string();
        wist_core::declaration::verify_delta_authority(&[&record.publisher], entry_body).map_err(
            |code| {
                diagnostic(
                    code,
                    &format!(
                        "{domain}: Delta signing or scope authority failed at height {height}"
                    ),
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
            materializes: domain == host || !self.self_declared_at(&host, height),
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

    const LATE_S: i64 = 1_800_000_000;
    use serde_json::Value;
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
    }

    fn key_entry(signer: &Signer, key_id: &str, valid_from: &str) -> Value {
        serde_json::json!({
            "key_id": key_id,
            "alg": "Ed25519",
            "public_key": signer.public_b64u(),
            "valid_from": valid_from,
        })
    }

    fn decl(
        domain: &str,
        seq: u64,
        prev: Option<&str>,
        keys: Vec<Value>,
        recovery_keys: Option<Vec<Value>>,
        sign: &Signer,
        sign_key_id: &str,
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
        sign_envelope(&doc, "publisher", sign_key_id, &sign.sk).unwrap()
    }

    fn decl_scoped(
        domain: &str,
        keys: Vec<Value>,
        subdomain_scope: Vec<&str>,
        sign: &Signer,
        sign_key_id: &str,
    ) -> Value {
        let doc = serde_json::json!({
            "wist_version": "1.0.0",
            "domain": domain,
            "keys": keys,
            "seq": 0,
            "subdomain_scope": subdomain_scope,
        });
        sign_envelope(&doc, "publisher", sign_key_id, &sign.sk).unwrap()
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

    #[test]
    fn baseline_then_delta_verifies() {
        let pk1 = Signer::new([1u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let delta = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        let verified = kh
            .verify_delta(1, LATE_S, &DeltaProfile::default(), &delta)
            .unwrap();
        assert!(verified.id.starts_with("sha256:"));
        assert!(verified.materializes);
    }

    #[test]
    fn unknown_key_id_fails() {
        let pk1 = Signer::new([1u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let delta = delta_env(
            &pk1,
            "nope",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        let err = kh
            .verify_delta(1, LATE_S, &DeltaProfile::default(), &delta)
            .unwrap_err();
        assert!(err.to_string().contains("WIST1-E02"), "{err}");
    }

    #[test]
    fn wrong_signature_fails() {
        let pk1 = Signer::new([1u8; 32]);
        let attacker = Signer::new([7u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let delta = delta_env(
            &attacker,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(1, LATE_S, &DeltaProfile::default(), &delta)
            .is_err());
    }

    #[test]
    fn observed_before_valid_from_fails() {
        let pk1 = Signer::new([1u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-10T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let delta = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T00:00:00Z",
        );
        let err = kh
            .verify_delta(1, LATE_S, &DeltaProfile::default(), &delta)
            .unwrap_err();
        assert!(err.to_string().contains("WIST1-E02"), "{err}");
    }

    #[test]
    fn no_declaration_at_height_fails() {
        let pk1 = Signer::new([1u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_declaration(5, "2026-08-09T12:00:00Z", 7, &decl0)
            .unwrap();
        let delta = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(3, LATE_S, &DeltaProfile::default(), &delta)
            .is_err());
    }

    #[test]
    fn rotation_resolves_by_height() {
        let pk1 = Signer::new([1u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash0),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_declaration(5, "2026-08-10T00:00:00Z", 7, &decl1)
            .unwrap();

        let delta_early = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(3, LATE_S, &DeltaProfile::default(), &delta_early)
            .is_ok());

        let delta_late_pk1 = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(6, LATE_S, &DeltaProfile::default(), &delta_late_pk1)
            .is_err());

        let delta_pk2 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(6, LATE_S, &DeltaProfile::default(), &delta_pk2)
            .is_ok());
    }

    #[test]
    fn non_monotonic_seq_rejected() {
        let pk1 = Signer::new([1u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let pk3 = Signer::new([3u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash0),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_declaration(1, "2026-08-09T12:00:00Z", 7, &decl1)
            .unwrap();
        let decl1_dup = decl(
            "records.example",
            1,
            Some(&hash0),
            vec![key_entry(&pk3, "pk3", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        let err = kh
            .add_declaration(2, "2026-08-09T13:00:00Z", 7, &decl1_dup)
            .unwrap_err();
        assert!(err.to_string().contains("seq"), "{err}");
    }

    #[test]
    fn broken_prev_declaration_rejected() {
        let pk1 = Signer::new([1u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let bad_prev = format!("sha256:{}", "0".repeat(64));
        let decl1 = decl(
            "records.example",
            1,
            Some(&bad_prev),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        let err = kh
            .add_declaration(1, "2026-08-09T12:00:00Z", 7, &decl1)
            .unwrap_err();
        assert!(err.to_string().contains("WIST1-E08"), "{err}");
    }

    #[test]
    fn duplicate_declaration_skipped() {
        let pk1 = Signer::new([1u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_declaration(0, "2026-08-09T12:00:00Z", 7, &decl0)
            .unwrap();
        kh.add_declaration(0, "2026-08-09T12:00:00Z", 7, &decl0)
            .unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash0),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_declaration(1, "2026-08-09T13:00:00Z", 7, &decl1)
            .unwrap();
        let delta = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T14:00:00Z",
        );
        assert!(kh
            .verify_delta(2, LATE_S, &DeltaProfile::default(), &delta)
            .is_ok());
    }

    #[test]
    fn recovery_prevails_inside_window() {
        let pk1 = Signer::new([1u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let atk = Signer::new([90u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let rk2 = Signer::new([12u8; 32]);
        let pk3 = Signer::new([3u8; 32]);
        let pk4 = Signer::new([4u8; 32]);
        let domain = "records.example";
        let mut kh = KeyHistory::new();

        let decl0 = decl(
            domain,
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk1, "rk1", "2026-08-09T00:00:00Z")]),
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();

        let decl1 = decl(
            domain,
            1,
            Some(&hash0),
            vec![key_entry(&atk, "atk", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk1, "rk1", "2026-08-09T00:00:00Z")]),
            &pk1,
            "pk1",
        );
        kh.add_declaration(2, "2026-08-02T00:00:00Z", 7, &decl1)
            .unwrap();
        let hash1 = publisher_hash(&decl1["publisher"]).unwrap();

        let decl2 = decl(
            domain,
            2,
            Some(&hash1),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk2, "rk2", "2026-08-09T00:00:00Z")]),
            &rk1,
            "rk1",
        );
        kh.add_declaration(3, "2026-08-03T00:00:00Z", 7, &decl2)
            .unwrap();
        let hash2 = publisher_hash(&decl2["publisher"]).unwrap();

        let decl3 = decl(
            domain,
            3,
            Some(&hash2),
            vec![key_entry(&pk3, "pk3", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk2, "rk2", "2026-08-09T00:00:00Z")]),
            &pk2,
            "pk2",
        );
        kh.add_declaration(4, "2026-08-04T00:00:00Z", 7, &decl3)
            .unwrap();
        let hash3 = publisher_hash(&decl3["publisher"]).unwrap();

        let decl4 = decl(
            domain,
            4,
            Some(&hash3),
            vec![key_entry(&pk4, "pk4", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk2, "rk2", "2026-08-09T00:00:00Z")]),
            &pk3,
            "pk3",
        );
        kh.add_declaration(6, "2026-08-11T00:00:00Z", 7, &decl4)
            .unwrap();

        // decl3 is signed by the recovery Declaration's own signing key, so it
        // legitimately follows the recovery chain and governs from its height
        // (WIST-1 §5.2): the recovering Publisher may rotate inside its own
        // window, and pk2 is rotated out when it does.
        let via_pk3_at5 = delta_env(
            &pk3,
            "pk3",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(5, LATE_S, &DeltaProfile::default(), &via_pk3_at5)
            .is_ok());
        let via_pk2_at5 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(5, LATE_S, &DeltaProfile::default(), &via_pk2_at5)
            .is_err());
        // The attacker's ordinary rotation, sealed before the recovery, never
        // governs inside the window.
        let via_atk_at5 = delta_env(
            &atk,
            "atk",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(5, LATE_S, &DeltaProfile::default(), &via_atk_at5)
            .is_err());

        let via_pk4_at7 = delta_env(
            &pk4,
            "pk4",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(7, LATE_S, &DeltaProfile::default(), &via_pk4_at7)
            .is_ok());
        let via_pk2_at7 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(7, LATE_S, &DeltaProfile::default(), &via_pk2_at7)
            .is_err());
    }

    #[test]
    fn fresh_identity_declaration_accepted_and_governs() {
        let pk1 = Signer::new([1u8; 32]);
        let pkx = Signer::new([50u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash0),
            vec![key_entry(&pkx, "pkx", "2026-08-09T00:00:00Z")],
            None,
            &pkx,
            "pkx",
        );
        kh.add_declaration(2, "2026-08-09T13:00:00Z", 7, &decl1)
            .unwrap();

        let delta_old = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(1, LATE_S, &DeltaProfile::default(), &delta_old)
            .is_ok());
        assert!(kh
            .verify_delta(2, LATE_S, &DeltaProfile::default(), &delta_old)
            .is_err());

        let delta_new = delta_env(
            &pkx,
            "pkx",
            "https://records.example/a",
            "2026-08-09T14:00:00Z",
        );
        assert!(kh
            .verify_delta(2, LATE_S, &DeltaProfile::default(), &delta_new)
            .is_ok());
    }

    #[test]
    fn fresh_identity_yields_to_open_recovery_window() {
        let pk1 = Signer::new([1u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let rk2 = Signer::new([12u8; 32]);
        let pky = Signer::new([51u8; 32]);
        let pkz = Signer::new([52u8; 32]);
        let domain = "records.example";
        let mut kh = KeyHistory::new();

        let decl0 = decl(
            domain,
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk1, "rk1", "2026-08-09T00:00:00Z")]),
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();

        let decl1 = decl(
            domain,
            1,
            Some(&hash0),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk2, "rk2", "2026-08-09T00:00:00Z")]),
            &rk1,
            "rk1",
        );
        kh.add_declaration(2, "2026-08-03T00:00:00Z", 7, &decl1)
            .unwrap();
        let hash1 = publisher_hash(&decl1["publisher"]).unwrap();

        let decl2 = decl(
            domain,
            2,
            Some(&hash1),
            vec![key_entry(&pky, "pky", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk2, "rk2", "2026-08-09T00:00:00Z")]),
            &pky,
            "pky",
        );
        assert_eq!(
            kh.add_declaration(3, "2026-08-04T00:00:00Z", 7, &decl2)
                .unwrap(),
            Admission::FreshIdentity
        );
        let hash2 = publisher_hash(&decl2["publisher"]).unwrap();

        let via_pk2_at3 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(3, LATE_S, &DeltaProfile::default(), &via_pk2_at3)
            .is_ok());
        let via_pky_at3 = delta_env(
            &pky,
            "pky",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(3, LATE_S, &DeltaProfile::default(), &via_pky_at3)
            .is_err());

        // The fresh identity is superseded, so its own successor chains off a
        // Declaration that never took effect and is rejected: after the
        // window, the domain continues from the recovery chain's head.
        let orphan = decl(
            domain,
            3,
            Some(&hash2),
            vec![key_entry(&pkz, "pkz", "2026-08-09T00:00:00Z")],
            None,
            &pky,
            "pky",
        );
        assert!(kh
            .add_declaration(4, "2026-08-11T00:00:00Z", 7, &orphan)
            .is_err());

        let continued = decl(
            domain,
            3,
            Some(&hash1),
            vec![key_entry(&pkz, "pkz", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk2, "rk2", "2026-08-09T00:00:00Z")]),
            &pk2,
            "pk2",
        );
        kh.add_declaration(4, "2026-08-11T00:00:00Z", 7, &continued)
            .unwrap();

        let via_pkz_at4 = delta_env(
            &pkz,
            "pkz",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(4, LATE_S, &DeltaProfile::default(), &via_pkz_at4)
            .is_ok());
        let via_pk2_at4 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(4, LATE_S, &DeltaProfile::default(), &via_pk2_at4)
            .is_err());
    }

    #[test]
    fn ordinary_rotation_dropping_recovery_keys_rejected() {
        let pk1 = Signer::new([1u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk1, "rk1", "2026-08-09T00:00:00Z")]),
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash0),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        let err = kh
            .add_declaration(2, "2026-08-09T13:00:00Z", 7, &decl1)
            .unwrap_err();
        assert!(err.to_string().contains("recovery_keys"), "{err}");
    }

    #[test]
    fn ordinary_rotation_with_identical_recovery_keys_accepted() {
        let pk1 = Signer::new([1u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk1, "rk1", "2026-08-09T00:00:00Z")]),
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash0),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk1, "rk1", "2026-08-09T00:00:00Z")]),
            &pk1,
            "pk1",
        );
        kh.add_declaration(2, "2026-08-09T13:00:00Z", 7, &decl1)
            .unwrap();
        let delta = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T14:00:00Z",
        );
        assert!(kh
            .verify_delta(2, LATE_S, &DeltaProfile::default(), &delta)
            .is_ok());
    }

    #[test]
    fn ordinary_rotation_establishes_recovery_keys_from_none() {
        let pk1 = Signer::new([1u8; 32]);
        let pk2 = Signer::new([2u8; 32]);
        let rk1 = Signer::new([11u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl(
            "records.example",
            0,
            None,
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            None,
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let hash0 = publisher_hash(&decl0["publisher"]).unwrap();
        let decl1 = decl(
            "records.example",
            1,
            Some(&hash0),
            vec![key_entry(&pk2, "pk2", "2026-08-09T00:00:00Z")],
            Some(vec![key_entry(&rk1, "rk1", "2026-08-09T00:00:00Z")]),
            &pk1,
            "pk1",
        );
        kh.add_declaration(2, "2026-08-09T13:00:00Z", 7, &decl1)
            .unwrap();
        let delta = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T14:00:00Z",
        );
        assert!(kh
            .verify_delta(2, LATE_S, &DeltaProfile::default(), &delta)
            .is_ok());
    }

    #[test]
    fn subdomain_listed_in_parent_scope_verifies() {
        let pk1 = Signer::new([1u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl_scoped(
            "records.example",
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            vec!["sub.records.example"],
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let delta = delta_env(
            &pk1,
            "pk1",
            "https://sub.records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh
            .verify_delta(1, LATE_S, &DeltaProfile::default(), &delta)
            .is_ok());
    }

    #[test]
    fn subdomain_not_listed_in_parent_scope_is_rejected() {
        let pk1 = Signer::new([1u8; 32]);
        let mut kh = KeyHistory::new();
        let decl0 = decl_scoped(
            "records.example",
            vec![key_entry(&pk1, "pk1", "2026-08-09T00:00:00Z")],
            vec!["other.records.example"],
            &pk1,
            "pk1",
        );
        kh.add_baseline(0, &decl0).unwrap();
        let delta = delta_env(
            &pk1,
            "pk1",
            "https://sub.records.example/a",
            "2026-08-09T12:00:00Z",
        );
        let err = kh
            .verify_delta(1, LATE_S, &DeltaProfile::default(), &delta)
            .unwrap_err();
        assert!(err.to_string().contains("WIST1-E03"), "{err}");
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
                let mut declarations = case["declarations"].as_array().unwrap().clone();
                if reverse {
                    declarations.reverse();
                }
                let mut history = KeyHistory::new();
                for declaration in declarations {
                    history
                        .add_declaration(0, "2026-08-01T00:00:00Z", 7, &declaration)
                        .unwrap();
                }
                for (index, envelope) in case["envelopes"].as_array().unwrap().iter().enumerate() {
                    let original = envelope.clone();
                    let actual =
                        history.verify_delta(1, LATE_S, &DeltaProfile::default(), envelope);
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
