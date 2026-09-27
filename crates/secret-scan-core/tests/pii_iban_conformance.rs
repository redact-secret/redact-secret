//! Shared IBAN-family conformance and incremental partition equivalence.

#![allow(clippy::panic, clippy::unwrap_used)]

mod support;

use redact_secret::{DefaultPolicy, DetectorRegistry, IncrementalSanitizer, PiiSelection, scan};
use serde_json::Value;
use std::collections::BTreeSet;

const CORPUS: &str = include_str!("../../../conformance/fixtures/pii-iban-v1.json");

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

fn generated_iban(country: &str, bban: &str) -> String {
    let mut remainder = 0_u16;
    for byte in bban
        .bytes()
        .chain(country.bytes())
        .chain(b"00".iter().copied())
    {
        if byte.is_ascii_digit() {
            remainder = (remainder * 10 + u16::from(byte - b'0')) % 97;
        } else {
            let expanded = byte - b'A' + 10;
            remainder = (remainder * 10 + u16::from(expanded / 10)) % 97;
            remainder = (remainder * 10 + u16::from(expanded % 10)) % 97;
        }
    }
    format!("{country}{:02}{bban}", 98 - remainder)
}

#[test]
fn recorded_synthetic_fixture_generator_is_reproducible() {
    let document = fixture();
    let generator = &document["fixtureGenerator"];
    assert_eq!(generator["id"], "iban-v1-uppercase-bban-check-digits");
    assert_eq!(generator["seed"], "redact-secret-iban-v1-fixture-878");
    for input in generator["inputs"].as_array().unwrap() {
        assert_eq!(
            generated_iban(
                input["country"].as_str().unwrap(),
                input["bban"].as_str().unwrap()
            ),
            input["expectedElectronic"].as_str().unwrap()
        );
    }
}

#[test]
fn every_positive_is_one_of_the_recorded_unmistakably_synthetic_values() {
    let document = fixture();
    let generated: BTreeSet<&str> = document["fixtureGenerator"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["expectedElectronic"].as_str().unwrap())
        .collect();

    for case in document["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        for finding in case["expected"].as_array().unwrap() {
            let start = usize::try_from(finding["start"].as_u64().unwrap()).unwrap();
            let end = usize::try_from(finding["end"].as_u64().unwrap()).unwrap();
            let electronic = input[start..end].replace(' ', "");
            assert!(electronic.contains("SYNX"), "{}", case["id"]);
            assert!(generated.contains(electronic.as_str()), "{}", case["id"]);
        }
    }
}

#[test]
fn iban_fixture_matches_the_public_rust_surface() {
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
fn every_iban_fixture_partition_matches_whole_input() {
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
fn exact_and_global_selectors_close_over_the_same_iban_family() {
    let input = "iban: GB18SYNX00000000000000";
    let exact = PiiSelection::parse(&["pii:family:global:iban"]).unwrap();
    let global = PiiSelection::parse(&["pii:global"]).unwrap();
    let exact_registry = DetectorRegistry::with_built_in_and_pii(&exact).unwrap();
    let global_registry = DetectorRegistry::with_built_in_and_pii(&global).unwrap();
    assert_eq!(
        scan(input, &exact_registry, &DefaultPolicy).unwrap(),
        scan(input, &global_registry, &DefaultPolicy).unwrap()
    );
}

#[test]
fn pii_off_changes_nothing_for_iban_shaped_input() {
    let input = "iban: GB18SYNX00000000000000";
    let legacy = DetectorRegistry::with_built_in([]).unwrap();
    let off = DetectorRegistry::with_built_in_and_pii(&PiiSelection::default()).unwrap();
    assert_eq!(
        scan(input, &legacy, &DefaultPolicy).unwrap(),
        scan(input, &off, &DefaultPolicy).unwrap()
    );
    assert!(scan(input, &off, &DefaultPolicy).unwrap().is_empty());
}
