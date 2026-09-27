//! Shared US SSN PII family conformance and incremental partition equivalence.

#![allow(clippy::panic, clippy::unwrap_used)]

mod support;

use redact_secret::{DefaultPolicy, DetectorRegistry, IncrementalSanitizer, PiiSelection, scan};
use serde_json::Value;

const CORPUS: &str = include_str!("../../../conformance/fixtures/pii-us-ssn-v1.json");
const EMAIL_CORPUS: &str = include_str!("../../../conformance/fixtures/pii-email-v1.json");

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
fn us_ssn_fixture_matches_the_public_rust_surface() {
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
fn every_us_ssn_fixture_partition_matches_whole_input() {
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
fn exact_and_us_selectors_enable_ssn_while_global_and_off_do_not() {
    let document = fixture();
    let input = document["cases"][0]["input"].as_str().unwrap();
    let exact = PiiSelection::parse(&["pii:family:us:ssn"]).unwrap();
    let jurisdiction = PiiSelection::parse(&["pii:us"]).unwrap();
    for selected in [&exact, &jurisdiction] {
        let registry = DetectorRegistry::with_built_in_and_pii(selected).unwrap();
        let findings = scan(input, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].type_name(), "pii_jurisdiction_us_ssn");
    }

    let global =
        DetectorRegistry::with_built_in_and_pii(&PiiSelection::parse(&["pii:global"]).unwrap())
            .unwrap();
    assert!(scan(input, &global, &DefaultPolicy).unwrap().is_empty());

    let legacy = DetectorRegistry::with_built_in([]).unwrap();
    let off = DetectorRegistry::with_built_in_and_pii(&PiiSelection::default()).unwrap();
    assert_eq!(
        scan(input, &legacy, &DefaultPolicy).unwrap(),
        scan(input, &off, &DefaultPolicy).unwrap()
    );
    assert!(scan(input, &off, &DefaultPolicy).unwrap().is_empty());
}

#[test]
fn us_selection_closes_over_global_without_exact_family_widening() {
    let document = fixture();
    let ssn_input = document["cases"][0]["input"].as_str().unwrap();
    let email_document: Value = serde_json::from_str(EMAIL_CORPUS).unwrap();
    let email_input = email_document["cases"][0]["input"].as_str().unwrap();
    let jurisdiction = PiiSelection::parse(&["pii:us"]).unwrap();
    let exact = PiiSelection::parse(&["pii:family:us:ssn"]).unwrap();
    let ssn_findings = scan(
        ssn_input,
        &DetectorRegistry::with_built_in_and_pii(&jurisdiction).unwrap(),
        &DefaultPolicy,
    )
    .unwrap();
    assert_eq!(
        ssn_findings
            .iter()
            .map(redact_secret::Finding::type_name)
            .collect::<Vec<_>>(),
        ["pii_jurisdiction_us_ssn"]
    );
    let global_findings = scan(
        email_input,
        &DetectorRegistry::with_built_in_and_pii(&jurisdiction).unwrap(),
        &DefaultPolicy,
    )
    .unwrap();
    assert_eq!(global_findings.len(), 1);
    assert_eq!(global_findings[0].type_name(), "pii_global_email");

    let exact_does_not_widen = scan(
        email_input,
        &DetectorRegistry::with_built_in_and_pii(&exact).unwrap(),
        &DefaultPolicy,
    )
    .unwrap();
    assert!(exact_does_not_widen.is_empty());
}

#[test]
fn us_selection_preserves_disjoint_ssn_and_global_findings() {
    let document = fixture();
    let email_document: Value = serde_json::from_str(EMAIL_CORPUS).unwrap();
    let input = format!(
        "{}\n{}",
        document["cases"][0]["input"].as_str().unwrap(),
        email_document["cases"][0]["input"].as_str().unwrap()
    );
    let jurisdiction = PiiSelection::parse(&["pii:us"]).unwrap();
    let findings = scan(
        &input,
        &DetectorRegistry::with_built_in_and_pii(&jurisdiction).unwrap(),
        &DefaultPolicy,
    )
    .unwrap();
    assert_eq!(
        findings
            .iter()
            .map(redact_secret::Finding::type_name)
            .collect::<Vec<_>>(),
        ["pii_jurisdiction_us_ssn", "pii_global_email"]
    );
    assert_eq!(
        (findings[0].range().start(), findings[0].range().end()),
        (4, 13)
    );
}
