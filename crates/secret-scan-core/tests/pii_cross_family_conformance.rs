//! Cross-family PII context association: every fixture case under a
//! selection that runs several families together, its incremental
//! partitions, and PII-off credential-only equivalence.

#![allow(clippy::panic, clippy::unwrap_used)]

mod support;

use redact_secret::{DefaultPolicy, DetectorRegistry, IncrementalSanitizer, PiiSelection, scan};
use serde_json::Value;

const CORPUS: &str = include_str!("../../../conformance/fixtures/pii-cross-family-v1.json");

fn fixture() -> Value {
    serde_json::from_str(CORPUS).unwrap()
}

/// The selectors a case runs under: its own `selectors` when present (a
/// case that must hold under `pii:us` and `pii:global` alike), otherwise
/// the document's `selector`.
fn selections(document: &Value, case: &Value) -> Vec<(String, PiiSelection)> {
    let selectors: Vec<&str> = case.get("selectors").and_then(Value::as_array).map_or_else(
        || vec![document["selector"].as_str().unwrap()],
        |selectors| {
            selectors
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect()
        },
    );
    selectors
        .into_iter()
        .map(|selector| {
            (
                selector.to_owned(),
                PiiSelection::parse(&[selector]).unwrap(),
            )
        })
        .collect()
}

fn observable(finding: &redact_secret::Finding) -> Value {
    serde_json::json!({
        "detector": finding.detector(),
        "type": finding.type_name(),
        "confidence": finding.confidence().as_str(),
        "action": finding.action().as_str(),
        "start": finding.range().start(),
        "end": finding.range().end(),
    })
}

#[test]
fn cross_family_fixture_matches_the_public_rust_surface() {
    let document = fixture();
    for case in document["cases"].as_array().unwrap() {
        for (selector, selected) in selections(&document, case) {
            let registry = DetectorRegistry::with_built_in_and_pii(&selected).unwrap();
            let findings =
                scan(case["input"].as_str().unwrap(), &registry, &DefaultPolicy).unwrap();
            let actual: Vec<Value> = findings.iter().map(observable).collect();
            let expected = case["expected"].as_array().unwrap();
            assert_eq!(
                &actual,
                expected,
                "{} {selector}",
                case["id"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn every_cross_family_fixture_partition_matches_whole_input() {
    let document = fixture();
    for case in document["cases"].as_array().unwrap() {
        for (selector, selected) in selections(&document, case) {
            assert_every_partition_matches_whole_input(case, &selector, &selected);
        }
    }
}

fn assert_every_partition_matches_whole_input(
    case: &Value,
    selector: &str,
    selected: &PiiSelection,
) {
    let registry = DetectorRegistry::with_built_in_and_pii(selected).unwrap();
    let input = case["input"].as_str().unwrap();
    let expected = scan(input, &registry, &DefaultPolicy).unwrap();
    for split in input
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(input.len()))
    {
        let mut session =
            IncrementalSanitizer::with_built_in_and_pii(support::generous_limits(), selected)
                .unwrap();
        let mut findings = session.append(&input[..split]).unwrap().findings().to_vec();
        findings.extend_from_slice(session.append(&input[split..]).unwrap().findings());
        findings.extend_from_slice(session.finalize().unwrap().findings());
        assert_eq!(
            findings,
            expected,
            "{} {selector} split={split}",
            case["id"].as_str().unwrap()
        );
    }
}

#[test]
fn pii_off_keeps_credential_only_output_for_every_cross_family_input() {
    let legacy = DetectorRegistry::with_built_in([]).unwrap();
    let off = DetectorRegistry::with_built_in_and_pii(&PiiSelection::default()).unwrap();
    for case in fixture()["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let credential_only = scan(input, &legacy, &DefaultPolicy).unwrap();
        assert_eq!(
            credential_only,
            scan(input, &off, &DefaultPolicy).unwrap(),
            "{}",
            case["id"].as_str().unwrap()
        );
        assert!(
            credential_only
                .iter()
                .all(|finding| !finding.type_name().starts_with("pii_")),
            "{}",
            case["id"].as_str().unwrap()
        );
    }
}
