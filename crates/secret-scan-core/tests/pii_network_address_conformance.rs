//! Shared network-address PII family conformance.

#![allow(clippy::panic, clippy::unwrap_used)]

use redact_secret::{
    Action, DefaultPolicy, IncrementalLimits, IncrementalSanitizer, PiiSelection, Profile,
    default_placeholder_formatter, scan,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../conformance/fixtures/pii-network-address-v1.json"
    ))
    .unwrap()
}

fn selection() -> PiiSelection {
    PiiSelection::parse(&["pii:family:global:network-address"]).unwrap()
}

#[test]
fn network_address_fixture_matches_whole_input_and_metadata() {
    let selection = selection();
    let registry = redact_secret::DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
    assert_eq!(
        registry.activation_identity(),
        "credentials=full;selectors=pii:family:global:network-address;families=pii:global:network-address;vocabulary=pii-context/v1"
    );
    for case in fixture()["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let result = scan(input, &registry, &DefaultPolicy).unwrap();
        let findings: Vec<_> = result
            .iter()
            .filter(|finding| finding.type_name() == "pii_global_network_address")
            .collect();
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(findings.len(), expected.len(), "{}", case["id"]);
        for (finding, expected) in findings.iter().zip(expected) {
            assert_eq!(finding.detector(), "pii-domain");
            assert_eq!(finding.confidence().as_str(), "high");
            assert_eq!(finding.action(), Action::Redact);
            if let Some(obfuscation) = expected.get("obfuscation") {
                assert_eq!(
                    finding.obfuscation().as_str(),
                    obfuscation.as_str().unwrap()
                );
            }
            assert_eq!(
                finding.range().start(),
                usize::try_from(expected["start"].as_u64().unwrap()).unwrap()
            );
            assert_eq!(
                finding.range().end(),
                usize::try_from(expected["end"].as_u64().unwrap()).unwrap()
            );
        }
    }
}

#[test]
fn network_address_is_partition_invariant_at_every_utf8_boundary() {
    let limits = IncrementalLimits::new(
        4096,
        IncrementalLimits::minimum_buffered_bytes(512, 512),
        512,
        512,
    )
    .unwrap();
    for case in fixture()["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let selection = selection();
        let registry = redact_secret::DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
        let expected = scan(input, &registry, &DefaultPolicy).unwrap();
        for split in input
            .char_indices()
            .map(|(index, _)| index)
            .chain([input.len()])
        {
            let mut session = IncrementalSanitizer::with_built_in_and_pii_policy_and_formatter(
                limits,
                &selection,
                Box::new(DefaultPolicy),
                Box::new(default_placeholder_formatter),
            )
            .unwrap();
            let first = session.append(&input[..split]).unwrap();
            let second = session.append(&input[split..]).unwrap();
            let final_part = session.finalize().unwrap();
            let findings: Vec<_> = first
                .findings()
                .iter()
                .chain(second.findings())
                .chain(final_part.findings())
                .cloned()
                .collect();
            assert_eq!(findings, expected, "{} split {split}", case["id"]);
        }
    }
}

#[test]
fn pii_off_keeps_network_addresses_unreported() {
    let registry = redact_secret::DetectorRegistry::with_built_in([]).unwrap();
    assert!(
        scan("client_ip=192.168.1.7", &registry, &DefaultPolicy)
            .unwrap()
            .iter()
            .all(|finding| finding.type_name() != "pii_global_network_address")
    );
    assert_eq!(
        selection().activation_identity(Profile::Common),
        "credentials=common;selectors=pii:family:global:network-address;families=pii:global:network-address;vocabulary=pii-context/v1"
    );
}
