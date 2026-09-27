//! Shared payment-card conformance and incremental partition equivalence.

#![allow(clippy::panic, clippy::unwrap_used)]

mod support;

use redact_secret::{DefaultPolicy, DetectorRegistry, IncrementalSanitizer, PiiSelection, scan};
use serde_json::Value;

const CORPUS: &str = include_str!("../../../conformance/fixtures/pii-payment-card-v1.json");

fn fixture() -> Value {
    serde_json::from_str(CORPUS).unwrap()
}

fn selection(document: &Value) -> PiiSelection {
    PiiSelection::parse(&[document["selector"].as_str().unwrap()]).unwrap()
}

fn observable(finding: &redact_secret::Finding) -> Value {
    let mut value = serde_json::json!({
        "detector": finding.detector(),
        "type": finding.type_name(),
        "confidence": finding.confidence().as_str(),
        "action": finding.action().as_str(),
        "start": finding.range().start(),
        "end": finding.range().end(),
    });
    if finding.obfuscation() != redact_secret::Obfuscation::None {
        value["obfuscation"] = Value::String(finding.obfuscation().as_str().to_owned());
    }
    value
}

#[test]
fn payment_card_fixture_matches_the_public_rust_surface() {
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
fn every_payment_card_fixture_partition_matches_whole_input() {
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
fn exact_and_global_selectors_close_over_payment_card_and_off_is_unchanged() {
    let input = "card_number=4000008770000003";
    let exact = PiiSelection::parse(&["pii:family:global:payment-card"]).unwrap();
    let global = PiiSelection::parse(&["pii:global"]).unwrap();
    for selected in [&exact, &global] {
        let registry = DetectorRegistry::with_built_in_and_pii(selected).unwrap();
        let findings = scan(input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].type_name(), "pii_global_payment_card");
    }

    let legacy = DetectorRegistry::with_built_in([]).unwrap();
    let off = DetectorRegistry::with_built_in_and_pii(&PiiSelection::default()).unwrap();
    assert_eq!(
        scan(input, &legacy, &DefaultPolicy).unwrap(),
        scan(input, &off, &DefaultPolicy).unwrap()
    );
    assert!(scan(input, &off, &DefaultPolicy).unwrap().is_empty());
}

#[test]
fn global_selection_preserves_disjoint_payment_card_and_network_address_findings() {
    let input = "card_number=4000008770000003 client_ip=10.0.0.8";
    let selected = PiiSelection::parse(&["pii:global"]).unwrap();
    let registry = DetectorRegistry::with_built_in_and_pii(&selected).unwrap();
    let findings = scan(input, &registry, &DefaultPolicy).unwrap();
    assert_eq!(
        findings
            .iter()
            .map(redact_secret::Finding::type_name)
            .collect::<Vec<_>>(),
        ["pii_global_payment_card", "pii_global_network_address"]
    );
}
