mod common;

use graven::keyset::KeyHistory;
use serde_json::{json, Value};
use wist_core::declaration::Decision;

fn spec_dir() -> std::path::PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec")
        })
}

fn entry(declaration: &Value) -> Value {
    json!({"type": "publisher_declaration", "body": declaration})
}

fn code(text: &str) -> String {
    let start = text
        .find("WIST")
        .unwrap_or_else(|| panic!("no diagnostic code in {text}"));
    text[start..start + 9].to_string()
}

fn outcome(stored: &Value, fetched: &Value) -> String {
    let mut history = KeyHistory::new();
    if !stored.is_null() {
        let effects = history
            .apply_block(
                0,
                "sha256:genesis",
                "h0",
                "2026-08-02T12:00:00Z",
                7,
                &[entry(stored)],
            )
            .unwrap();
        assert_eq!(effects.installations[0].decision, None);
    }
    let (height, prev) = if stored.is_null() {
        (0, "sha256:genesis")
    } else {
        (1, "h0")
    };
    match history.apply_block(
        height,
        prev,
        "h1",
        "2026-08-03T12:00:00Z",
        7,
        &[entry(fetched)],
    ) {
        Ok(effects) => match effects.installations.first().and_then(|i| i.decision) {
            None if effects.installations.is_empty() => "idempotent".into(),
            None => "initial".into(),
            Some(Decision::Ordinary) => "ordinary_rotation".into(),
            Some(Decision::Recovery) => "recovery_rotation".into(),
            Some(Decision::FreshIdentity) => "fresh_identity".into(),
            Some(Decision::Unchanged) => "idempotent".into(),
        },
        Err(error) => code(&error.to_string()),
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
fn a_renamed_signing_key_keeps_its_identity() {
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
        .apply_block(
            0,
            "sha256:genesis",
            "h0",
            "2026-08-02T12:00:00Z",
            7,
            &[entry(&case["stored"])],
        )
        .unwrap();
    let effects = history
        .apply_block(
            1,
            "h0",
            "h1",
            "2026-08-03T12:00:00Z",
            7,
            &[entry(&case["fetched"])],
        )
        .unwrap();
    assert_eq!(effects.installations[0].decision, Some(Decision::Ordinary));
    assert!(!effects.installations[0].resets_identity);
    assert!(history.declared("example.com"));
}
