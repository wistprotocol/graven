use crate::error::{Error, Result};
use reqwest::Url;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use wist_core::crypto::{hex_encode, PublicKey};
use wist_core::delta::delta_id;
use wist_core::envelope::verify_envelope;
use wist_core::objects::{DeltaEnvelope, Publisher, PublisherEnvelope, PublisherKey};

pub const RECOVERY_WINDOW_DAYS: i64 = 7;

struct DeclRecord {
    seq: u64,
    height: u64,
    recovery: bool,
    sealed_at: Option<jiff::Timestamp>,
    window_end: Option<jiff::Timestamp>,
    publisher: Publisher,
    hash: String,
}

#[derive(Default)]
pub struct KeyHistory {
    domains: HashMap<String, Vec<DeclRecord>>,
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

fn key_by_id<'a>(keys: &'a [PublisherKey], key_id: &str) -> Option<&'a PublisherKey> {
    keys.iter().find(|k| k.key_id == key_id)
}

fn verify_under_set(envelope: &Value, keys: &[PublisherKey], key_id: &str) -> bool {
    key_by_id(keys, key_id)
        .and_then(|k| PublicKey::from_b64u(&k.public_key).ok())
        .is_some_and(|pk| verify_envelope(envelope, "publisher", &pk).is_ok())
}

fn recovery_keys_canon(keys: &Option<Vec<PublisherKey>>) -> Result<Vec<u8>> {
    let value = serde_json::to_value(keys)?;
    Ok(wist_core::jcs::canonicalize(&value)?)
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
            recovery: false,
            sealed_at: None,
            window_end: None,
            publisher: env.publisher,
            hash,
        });
        Ok(())
    }

    pub fn add_declaration(
        &mut self,
        height: u64,
        sealed_at: &str,
        envelope: &Value,
    ) -> Result<()> {
        let env: PublisherEnvelope = serde_json::from_value(envelope.clone())?;
        let publisher_value = envelope.get("publisher").ok_or_else(|| {
            Error::PublisherVerify("declaration envelope missing publisher".into())
        })?;
        let hash = publisher_hash(publisher_value)?;
        let domain = env.publisher.domain.clone();
        let entries = self.domains.entry(domain.clone()).or_default();

        if entries.iter().any(|e| e.hash == hash) {
            return Ok(());
        }

        let seq = env.publisher.seq;
        let (recovery, sealed, window_end) = match entries.last() {
            None => {
                if seq != 0 {
                    return Err(Error::PublisherVerify(format!(
                        "{domain} seq {seq}: first declaration for domain must have seq 0"
                    )));
                }
                if !verify_under_set(envelope, &env.publisher.keys, &env.sig.key_id) {
                    return Err(Error::PublisherVerify(format!(
                        "{domain} seq {seq}: self-signature does not verify under its own keys"
                    )));
                }
                let sealed = parse_timestamp(&domain, seq, sealed_at)?;
                (false, sealed, None)
            }
            Some(pred) => {
                if seq <= pred.seq {
                    return Err(Error::PublisherVerify(format!(
                        "{domain} seq {seq}: not greater than previous seq {}",
                        pred.seq
                    )));
                }
                if env.publisher.prev_declaration.as_deref() != Some(pred.hash.as_str()) {
                    return Err(Error::PublisherVerify(format!(
                        "{domain} seq {seq}: prev_declaration does not match previous declaration hash"
                    )));
                }
                let sealed = parse_timestamp(&domain, seq, sealed_at)?;
                if verify_under_set(envelope, &pred.publisher.keys, &env.sig.key_id) {
                    let pred_has_recovery = pred
                        .publisher
                        .recovery_keys
                        .as_ref()
                        .is_some_and(|rk| !rk.is_empty());
                    if pred_has_recovery
                        && recovery_keys_canon(&pred.publisher.recovery_keys)?
                            != recovery_keys_canon(&env.publisher.recovery_keys)?
                    {
                        return Err(Error::PublisherVerify(format!(
                            "{domain} seq {seq}: ordinary rotation must carry recovery_keys byte-identical to predecessor's"
                        )));
                    }
                    (false, sealed, None)
                } else if verify_under_set(
                    envelope,
                    pred.publisher.recovery_keys.as_deref().unwrap_or(&[]),
                    &env.sig.key_id,
                ) {
                    let window_end = sealed
                        .checked_add(jiff::Span::new().hours(RECOVERY_WINDOW_DAYS * 24))
                        .map_err(|e| {
                            Error::PublisherVerify(format!(
                                "{domain} seq {seq}: recovery window overflow: {e}"
                            ))
                        })?;
                    (true, sealed, Some(window_end))
                } else if verify_under_set(envelope, &env.publisher.keys, &env.sig.key_id) {
                    (false, sealed, None)
                } else {
                    return Err(Error::PublisherVerify(format!(
                        "{domain} seq {seq}: signature does not verify under previous keys, recovery_keys, or its own keys"
                    )));
                }
            }
        };

        entries.push(DeclRecord {
            seq,
            height,
            recovery,
            sealed_at: Some(sealed),
            window_end,
            publisher: env.publisher,
            hash,
        });
        Ok(())
    }

    fn resolve(&self, domain: &str, height: u64) -> Result<&DeclRecord> {
        let entries = self.domains.get(domain).ok_or_else(|| {
            Error::PublisherVerify(format!("{domain}: no declaration at height {height}"))
        })?;
        let mut winner: Option<&DeclRecord> = None;
        for entry in entries.iter().filter(|e| e.height <= height) {
            if let Some(w) = winner {
                if w.recovery && !entry.recovery {
                    if let (Some(end), Some(sealed)) = (w.window_end, entry.sealed_at) {
                        if sealed < end {
                            continue;
                        }
                    }
                }
            }
            winner = Some(entry);
        }
        winner.ok_or_else(|| {
            Error::PublisherVerify(format!("{domain}: no declaration at height <= {height}"))
        })
    }

    fn resolve_scoped(&self, domain: &str, height: u64) -> Result<&DeclRecord> {
        if let Ok(record) = self.resolve(domain, height) {
            return Ok(record);
        }
        let mut rest = domain;
        while let Some((_, parent)) = rest.split_once('.') {
            if let Ok(record) = self.resolve(parent, height) {
                if record.publisher.subdomain_scope.is_some() {
                    return Ok(record);
                }
            }
            rest = parent;
        }
        Err(Error::PublisherVerify(format!(
            "{domain} height {height}: no declaration for domain or scoped parent"
        )))
    }

    pub fn verify_delta(&self, height: u64, entry_body: &Value) -> Result<String> {
        let env: DeltaEnvelope = serde_json::from_value(entry_body.clone())?;
        let url = Url::parse(&env.delta.url)
            .map_err(|e| Error::PublisherVerify(format!("delta url {}: {e}", env.delta.url)))?;
        let domain = url_authority(&url).ok_or_else(|| {
            Error::PublisherVerify(format!("delta url {}: no authority", env.delta.url))
        })?;
        let record = self.resolve_scoped(&domain, height)?;
        let key = key_by_id(&record.publisher.keys, &env.sig.key_id).ok_or_else(|| {
            Error::PublisherVerify(format!(
                "{domain} height {height}: unknown key_id {}",
                env.sig.key_id
            ))
        })?;
        let pk = PublicKey::from_b64u(&key.public_key)?;
        verify_envelope(entry_body, "delta", &pk)
            .map_err(|e| Error::PublisherVerify(format!("{domain} height {height}: {e}")))?;
        let observed_at: jiff::Timestamp = env.delta.observed_at.parse().map_err(|e| {
            Error::PublisherVerify(format!(
                "{domain} height {height}: observed_at {}: {e}",
                env.delta.observed_at
            ))
        })?;
        let valid_from: jiff::Timestamp = key.valid_from.parse().map_err(|e| {
            Error::PublisherVerify(format!(
                "{domain} height {height}: key valid_from {}: {e}",
                key.valid_from
            ))
        })?;
        if observed_at < valid_from {
            return Err(Error::PublisherVerify(format!(
                "{domain} height {height}: observed_at precedes key valid_from"
            )));
        }
        Ok(delta_id(&entry_body["delta"])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn delta_env(signer: &Signer, key_id: &str, url: &str, observed_at: &str) -> Value {
        let delta = serde_json::json!({
            "wist_version": "1.0.0",
            "url": url,
            "change_type": "new",
            "observed_at": observed_at,
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
        let id = kh.verify_delta(1, &delta).unwrap();
        assert!(id.starts_with("sha256:"));
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
        let err = kh.verify_delta(1, &delta).unwrap_err();
        assert!(err.to_string().contains("key_id"), "{err}");
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
        assert!(kh.verify_delta(1, &delta).is_err());
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
        let err = kh.verify_delta(1, &delta).unwrap_err();
        assert!(err.to_string().contains("valid_from"), "{err}");
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
        kh.add_declaration(5, "2026-08-09T12:00:00Z", &decl0)
            .unwrap();
        let delta = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(3, &delta).is_err());
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
        kh.add_declaration(5, "2026-08-10T00:00:00Z", &decl1)
            .unwrap();

        let delta_early = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(3, &delta_early).is_ok());

        let delta_late_pk1 = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(6, &delta_late_pk1).is_err());

        let delta_pk2 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(6, &delta_pk2).is_ok());
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
        kh.add_declaration(1, "2026-08-09T12:00:00Z", &decl1)
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
            .add_declaration(2, "2026-08-09T13:00:00Z", &decl1_dup)
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
            .add_declaration(1, "2026-08-09T12:00:00Z", &decl1)
            .unwrap_err();
        assert!(err.to_string().contains("prev_declaration"), "{err}");
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
        kh.add_declaration(0, "2026-08-09T12:00:00Z", &decl0)
            .unwrap();
        kh.add_declaration(0, "2026-08-09T12:00:00Z", &decl0)
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
        kh.add_declaration(1, "2026-08-09T13:00:00Z", &decl1)
            .unwrap();
        let delta = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T14:00:00Z",
        );
        assert!(kh.verify_delta(2, &delta).is_ok());
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
        kh.add_declaration(2, "2026-08-02T00:00:00Z", &decl1)
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
        kh.add_declaration(3, "2026-08-03T00:00:00Z", &decl2)
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
        kh.add_declaration(4, "2026-08-04T00:00:00Z", &decl3)
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
        kh.add_declaration(6, "2026-08-11T00:00:00Z", &decl4)
            .unwrap();

        let via_pk2_at5 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(5, &via_pk2_at5).is_ok());
        let via_pk3_at5 = delta_env(
            &pk3,
            "pk3",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(5, &via_pk3_at5).is_err());

        let via_pk4_at7 = delta_env(
            &pk4,
            "pk4",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(7, &via_pk4_at7).is_ok());
        let via_pk2_at7 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(7, &via_pk2_at7).is_err());
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
        kh.add_declaration(2, "2026-08-09T13:00:00Z", &decl1)
            .unwrap();

        let delta_old = delta_env(
            &pk1,
            "pk1",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(1, &delta_old).is_ok());
        assert!(kh.verify_delta(2, &delta_old).is_err());

        let delta_new = delta_env(
            &pkx,
            "pkx",
            "https://records.example/a",
            "2026-08-09T14:00:00Z",
        );
        assert!(kh.verify_delta(2, &delta_new).is_ok());
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
        kh.add_declaration(2, "2026-08-03T00:00:00Z", &decl1)
            .unwrap();
        let hash1 = publisher_hash(&decl1["publisher"]).unwrap();

        let decl2 = decl(
            domain,
            2,
            Some(&hash1),
            vec![key_entry(&pky, "pky", "2026-08-09T00:00:00Z")],
            None,
            &pky,
            "pky",
        );
        kh.add_declaration(3, "2026-08-04T00:00:00Z", &decl2)
            .unwrap();
        let hash2 = publisher_hash(&decl2["publisher"]).unwrap();

        let via_pk2_at3 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(3, &via_pk2_at3).is_ok());
        let via_pky_at3 = delta_env(
            &pky,
            "pky",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(3, &via_pky_at3).is_err());

        let decl3 = decl(
            domain,
            3,
            Some(&hash2),
            vec![key_entry(&pkz, "pkz", "2026-08-09T00:00:00Z")],
            None,
            &pky,
            "pky",
        );
        kh.add_declaration(4, "2026-08-11T00:00:00Z", &decl3)
            .unwrap();

        let via_pkz_at4 = delta_env(
            &pkz,
            "pkz",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(4, &via_pkz_at4).is_ok());
        let via_pk2_at4 = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T12:00:00Z",
        );
        assert!(kh.verify_delta(4, &via_pk2_at4).is_err());
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
            .add_declaration(2, "2026-08-09T13:00:00Z", &decl1)
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
        kh.add_declaration(2, "2026-08-09T13:00:00Z", &decl1)
            .unwrap();
        let delta = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T14:00:00Z",
        );
        assert!(kh.verify_delta(2, &delta).is_ok());
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
        kh.add_declaration(2, "2026-08-09T13:00:00Z", &decl1)
            .unwrap();
        let delta = delta_env(
            &pk2,
            "pk2",
            "https://records.example/a",
            "2026-08-09T14:00:00Z",
        );
        assert!(kh.verify_delta(2, &delta).is_ok());
    }
}
