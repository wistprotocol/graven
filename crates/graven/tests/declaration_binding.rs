mod common;

use graven::keyset::{Admission, KeyHistory};
use serde_json::Value;

fn spec_dir() -> std::path::PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
}

fn outcome(stored: &Value, fetched: &Value) -> String {
    let mut history = KeyHistory::new();
    if !stored.is_null() {
        assert_eq!(
            history
                .add_declaration(0, "2026-08-02T12:00:00Z", 7, stored)
                .unwrap(),
            Admission::Initial
        );
    }
    match history.add_declaration(1, "2026-08-03T12:00:00Z", 7, fetched) {
        Ok(Admission::Initial) => "initial".into(),
        Ok(Admission::Ordinary) => "ordinary_rotation".into(),
        Ok(Admission::Recovery) => "recovery_rotation".into(),
        Ok(Admission::FreshIdentity) => "fresh_identity".into(),
        Ok(Admission::Duplicate) => "idempotent".into(),
        Err(error) => {
            let text = error.to_string();
            let start = text
                .find("WIST")
                .unwrap_or_else(|| panic!("no diagnostic code in {text}"));
            text[start..start + 9].to_string()
        }
    }
}

#[test]
fn declaration_binding_and_key_eligibility_vectors_select_the_documented_outcome() {
    for name in ["declaration-binding", "declaration-key-eligibility"] {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(spec_dir().join(format!("vectors/wist1/{name}.json"))).unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let before = case["fetched"].clone();
            assert_eq!(
                outcome(&case["stored"], &case["fetched"]),
                case["expected"],
                "{name}: {}",
                case["name"]
            );
            assert_eq!(case["fetched"], before);
        }
    }
}

#[test]
fn a_renamed_signing_key_keeps_its_identity_and_deltas_verify_under_the_alias() {
    let vector: Value = serde_json::from_slice(
        &std::fs::read(spec_dir().join("vectors/wist1/declaration-binding.json")).unwrap(),
    )
    .unwrap();
    let case = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "renamed signing key preserves identity")
        .unwrap();
    let mut history = KeyHistory::new();
    history
        .add_declaration(0, "2026-08-02T12:00:00Z", 7, &case["stored"])
        .unwrap();
    assert_eq!(
        history
            .add_declaration(3, "2026-08-03T12:00:00Z", 7, &case["fetched"])
            .unwrap(),
        Admission::Ordinary
    );
    assert!(history.self_declared_at("example.com", 3));
}
