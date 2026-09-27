//! Shared `pii-v1` activation/error conformance.

#![allow(clippy::unwrap_used, clippy::panic)]

use redact_secret::{DefaultPolicy, DetectorRegistry, PiiSelection, Profile, scan};
use serde_json::Value;

#[test]
fn pii_runtime_fixture_matches_the_public_rust_surface() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../conformance/fixtures/pii-runtime-v1.json"
    ))
    .unwrap();
    for case in fixture["activationCases"].as_array().unwrap() {
        let owned: Vec<String> = case["selectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();
        let selection = PiiSelection::parse(&borrowed).unwrap();
        assert_eq!(
            selection.activation_identity(Profile::Full),
            case["expected"].as_str().unwrap()
        );
    }
    for case in fixture["errorCases"].as_array().unwrap() {
        let owned: Vec<String> = case["selectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();
        let error = PiiSelection::parse(&borrowed).unwrap_err();
        assert_eq!(error.code().as_str(), case["code"].as_str().unwrap());
        assert_eq!(error.message(), case["message"].as_str().unwrap());
    }
}

#[test]
fn empty_selection_is_byte_for_byte_credential_only() {
    let legacy = DetectorRegistry::with_built_in([]).unwrap();
    let selected = DetectorRegistry::with_built_in_and_pii(&PiiSelection::default()).unwrap();
    assert_eq!(
        legacy.ids().collect::<Vec<_>>(),
        selected.ids().collect::<Vec<_>>()
    );
    assert_eq!(legacy.activation_identity(), selected.activation_identity());

    for input in [
        "plain synthetic text",
        "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE_12345",
        "prefix 🔑 Authorization: Bearer sk-syntheticRevokedExampleToken00000000000000000000",
    ] {
        assert_eq!(
            scan(input, &legacy, &DefaultPolicy).unwrap(),
            scan(input, &selected, &DefaultPolicy).unwrap(),
            "{input:?}"
        );
    }
}
