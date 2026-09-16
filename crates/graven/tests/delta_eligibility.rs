mod common;

use graven::keyset::{DeltaProfile, KeyHistory};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use wist_core::crypto::b64u_encode;

fn spec_dir() -> std::path::PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
}

fn vector(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(spec_dir().join("vectors/wist1").join(name)).unwrap())
        .unwrap()
}

fn baseline(domain: &str, key_id: &str, public_key: &Value, valid_from: &str) -> KeyHistory {
    let mut history = KeyHistory::new();
    history
        .adopt_domain(
            domain,
            &json!({
                "publisher": {"wist_version": "1.0.0", "domain": domain, "seq": 0,
                    "keys": [{"key_id": key_id, "alg": "Ed25519", "public_key": public_key,
                        "valid_from": valid_from}]},
                "sig": {"key_id": key_id, "alg": "Ed25519", "value": b64u_encode(&[0; 64])},
            }),
            0,
            0,
        )
        .unwrap();
    history
}

fn code(error: &graven::error::Error) -> String {
    let text = error.to_string();
    let start = text
        .find("WIST")
        .unwrap_or_else(|| panic!("no diagnostic code in {text}"));
    text[start..start + 9].to_string()
}

#[test]
fn signed_field_vectors_are_rejected_before_any_semantic_check() {
    let vector = vector("delta-fields.json");
    let mut history = baseline(
        "example.com",
        "test-k1",
        &vector["author_key"],
        "2026-08-01T00:00:00Z",
    );
    for case in vector["cases"].as_array().unwrap() {
        let doc = &case["envelope"];
        let before = doc.clone();
        let allowed: BTreeSet<&str> = case["allowed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let profile = DeltaProfile {
            url_cap_bytes: case["url_cap_bytes"].as_i64().unwrap_or(2048),
            commitment_cap_bytes: i128::from(
                case["commitment_cap_bytes"].as_i64().unwrap_or(38944),
            ),
            clock_skew_seconds: 9_007_199_254_740_991,
        };
        match history.verify_delta(
            1,
            wist_core::timestamp::log_seconds("2026-08-05T00:00:00Z").unwrap(),
            &profile,
            doc,
        ) {
            Ok(verified) => {
                assert!(allowed.is_empty(), "{}: accepted", case["name"]);
                assert_eq!(verified.id, case["id"]);
                assert_eq!(verified.publisher, "example.com");
            }
            Err(error) => {
                let code = code(&error);
                assert!(
                    allowed.contains(code.as_str()),
                    "{}: {code} outside {allowed:?}",
                    case["name"]
                );
            }
        }
        assert_eq!(*doc, before);
    }
}

#[test]
fn version_cases_keep_same_major_values_and_reject_other_majors() {
    let vector = vector("delta-attribution.json");
    let mut history = KeyHistory::new();
    let mut entries: Vec<Value> = vector["cases"][0]["declarations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| json!({"type": "publisher_declaration", "body": d}))
        .collect();
    entries
        .sort_by_key(|e| wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(e).unwrap()));
    history
        .apply_block(
            0,
            "sha256:genesis",
            "h0",
            "2026-08-01T00:00:00Z",
            7,
            &entries,
        )
        .unwrap();
    for case in vector["version_cases"].as_array().unwrap() {
        let doc = &case["envelope"];
        let before = doc.clone();
        let outcome = history.verify_delta(
            1,
            wist_core::timestamp::log_seconds("2026-08-02T13:00:00Z").unwrap(),
            &DeltaProfile::default(),
            doc,
        );
        let actual = outcome
            .as_ref()
            .map(|_| "accepted".to_string())
            .unwrap_or_else(code);
        assert_eq!(actual, case["expected"], "{}: {outcome:?}", case["name"]);
        if let Ok(verified) = outcome {
            assert_eq!(
                verified.id,
                wist_core::delta::delta_id(&doc["delta"]).unwrap()
            );
        }
        assert_eq!(*doc, before);
    }
}

#[test]
fn historical_clock_probes_use_the_committing_block_and_its_allowance() {
    let vector = vector("delta-clock-time.json");
    let mut history = baseline(
        "example.com",
        "test-k1",
        &vector["public_key"],
        "0000-01-01T00:00:00+23:59",
    );
    for probe in vector["probes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["stage"] == "historical")
    {
        let sealed_at_s =
            wist_core::timestamp::log_seconds(probe["sealed_at"].as_str().unwrap()).unwrap();
        let profile = DeltaProfile {
            clock_skew_seconds: probe["expected_allowance"].as_i64().unwrap(),
            ..DeltaProfile::default()
        };
        let outcome = history.verify_delta(1, sealed_at_s, &profile, &probe["envelope"]);
        assert_eq!(
            json!(outcome.as_ref().err().map(code)),
            probe["expected"],
            "{}: {outcome:?}",
            probe["name"]
        );
    }
}
