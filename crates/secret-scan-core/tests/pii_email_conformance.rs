//! Shared email-family conformance and incremental partition equivalence.

#![allow(clippy::panic, clippy::unwrap_used)]

mod support;

use redact_secret::{DefaultPolicy, DetectorRegistry, IncrementalSanitizer, PiiSelection, scan};
use serde_json::Value;

const CORPUS: &str = include_str!("../../../conformance/fixtures/pii-email-v1.json");

fn fixture() -> Value {
    serde_json::from_str(CORPUS).unwrap()
}

fn selection(document: &Value) -> PiiSelection {
    PiiSelection::parse(&[document["selector"].as_str().unwrap()]).unwrap()
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
fn email_fixture_matches_the_public_rust_surface() {
    let document = fixture();
    let registry = DetectorRegistry::with_built_in_and_pii(&selection(&document)).unwrap();
    for case in document["cases"].as_array().unwrap() {
        let findings = scan(case["input"].as_str().unwrap(), &registry, &DefaultPolicy).unwrap();
        let actual: Vec<Value> = findings.iter().map(observable).collect();
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(&actual, expected, "{}", case["id"].as_str().unwrap());
    }
}

#[test]
fn every_email_fixture_partition_matches_whole_input() {
    let document = fixture();
    let selected = selection(&document);
    for case in document["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let registry = DetectorRegistry::with_built_in_and_pii(&selected).unwrap();
        let expected = scan(input, &registry, &DefaultPolicy).unwrap();
        for split in input
            .char_indices()
            .map(|(index, _)| index)
            .chain(std::iter::once(input.len()))
        {
            let mut session =
                IncrementalSanitizer::with_built_in_and_pii(support::generous_limits(), &selected)
                    .unwrap();
            let mut findings = session.append(&input[..split]).unwrap().findings().to_vec();
            findings.extend_from_slice(session.append(&input[split..]).unwrap().findings());
            findings.extend_from_slice(session.finalize().unwrap().findings());
            assert_eq!(
                findings,
                expected,
                "{} split={split}",
                case["id"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn pii_off_changes_nothing_for_email_shaped_input() {
    let input = "email: fixture876-q7m9@x4z8v2n6.synthetic";
    let legacy = DetectorRegistry::with_built_in([]).unwrap();
    let off = DetectorRegistry::with_built_in_and_pii(&PiiSelection::default()).unwrap();
    assert_eq!(
        scan(input, &legacy, &DefaultPolicy).unwrap(),
        scan(input, &off, &DefaultPolicy).unwrap()
    );
    assert!(scan(input, &off, &DefaultPolicy).unwrap().is_empty());
}
