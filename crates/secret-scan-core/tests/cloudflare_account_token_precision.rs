//! Issue #481: the Cloudflare account-token (`cfat_`) contract, driven
//! through the public API exactly as the issue's own measurement did.
//!
//! `cfat_` is adopted into the reviewed `cloudflare-token` contract (issue
//! #367/#373, `docs/audits/evidence/367/precision-contracts.json`,
//! `families.cloudflare-token`) at the same shape as `cfut_`: the
//! provider's token-formats page documents both prefixes with the identical
//! `[40 characters][checksum]` format cell, and trufflehog 3.97.4's
//! `cloudflareapitoken` v2 rule (`cf[ua]t_[a-zA-Z0-9]{40}[a-f0-9]{8}`)
//! corroborates the same 40-byte alphanumeric body and 8-byte lowercase-hex
//! checksum for both.
//!
//! The three inputs below are the issue's self-contained synthetic
//! reproduction: a paired positive (`cfat_` plus the reviewed 48-byte
//! body/checksum suffix), its negative twin (the same value with a
//! non-hexadecimal eight-byte tail -- carrying no checksum segment of any
//! shape a consulted source describes), and the positive again after a
//! Unicode comment line with CRLF endings. `@redact-secret/core@0.1.0-beta.4`
//! reported all three positive shapes empty; this file pins the corrected
//! behavior on the whole-input surface, the provider detector in isolation,
//! and every UTF-8 byte partition of the incremental surface. Every value is
//! locally constructed and was never provider-issued.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{
    ByteRange, Confidence, DefaultPolicy, DetectorContext, DetectorRegistry, Specificity,
    default_placeholder_formatter, scan, scan_and_redact,
};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// One snapshot: the issue's own fixture id stem, the positive input, its
/// negative twin, and the UTF-8 byte range the positive must match at.
struct Snapshot {
    id: &'static str,
    positive: String,
    twin: String,
    start: usize,
}

fn snapshots() -> Vec<Snapshot> {
    // The issue's self-contained reproduction JSON: a 40-byte alphanumeric
    // body followed by an 8-byte lowercase-hex checksum, exactly as the
    // reviewed contract requires.
    let value = "cfat_SYNTHETICREVOKEDCLOUDFLAREBODY00000000006c4f0732";
    let twin = "cfat_SYNTHETICREVOKEDCLOUDFLAREBODY0000000000ghijklmn";
    assert_eq!(value.len(), 53);
    assert_eq!(twin.len(), 53);

    vec![
        Snapshot {
            id: "cloudflare-token-account-plain",
            positive: value.to_string(),
            twin: twin.to_string(),
            start: 0,
        },
        Snapshot {
            id: "cloudflare-token-account-quoted",
            positive: format!("token=\"{value}\""),
            twin: format!("token=\"{twin}\""),
            start: 7,
        },
        Snapshot {
            id: "cloudflare-token-account-unicode-crlf",
            positive: format!("# \u{1F511} reviewed format\r\n{value}\n\r\n"),
            twin: format!("# \u{1F511} reviewed format\r\n{twin}\n\r\n"),
            start: 24,
        },
    ]
}

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

#[test]
fn the_whole_input_scan_matches_every_paired_positive_at_its_exact_byte_range() {
    let registry = registry();
    for case in snapshots() {
        let findings = scan(&case.positive, &registry, &DefaultPolicy).unwrap();
        assert_eq!(findings.len(), 1, "{}", case.id);
        let finding = &findings[0];
        assert_eq!(finding.detector(), "cloudflare-token", "{}", case.id);
        assert_eq!(finding.type_name(), "cloudflare_api_token", "{}", case.id);
        assert_eq!(finding.confidence(), Confidence::High, "{}", case.id);
        assert_eq!(
            finding.range(),
            ByteRange::new(case.start, case.start + 53).unwrap(),
            "{}",
            case.id
        );
        assert!(finding.action().replaces_text(), "{}", case.id);
    }
}

/// The reproduced beta.4 false negative's mirror: the non-hex-checksum twin
/// stays silent under the default pipeline in every shape, exactly as
/// `cloudflare-token-user-plain-twin` already does for `cfut_`.
#[test]
fn the_whole_input_scan_is_silent_on_every_negative_twin() {
    let registry = registry();
    for case in snapshots() {
        let findings = scan(&case.twin, &registry, &DefaultPolicy).unwrap();
        assert!(
            findings.is_empty(),
            "{}-twin: unexpected {:?}",
            case.id,
            findings
                .iter()
                .map(|finding| (finding.detector(), finding.range()))
                .collect::<Vec<_>>()
        );
    }
}

/// The provider detector in isolation, driven through the registry's public
/// `RegisteredDetector` surface, agrees with the default pipeline on both
/// halves of every pair and claims provider specificity for the positive.
#[test]
fn the_provider_detector_in_isolation_agrees_with_the_default_pipeline() {
    let registry = registry();
    let detector = registry
        .detectors()
        .iter()
        .find(|registered| registered.id() == "cloudflare-token")
        .expect("cloudflare-token is a built-in detector")
        .detector();
    for case in snapshots() {
        let context = DetectorContext::new(case.positive.len());
        let candidates = detector.detect(&case.positive, &context).unwrap();
        assert_eq!(candidates.len(), 1, "{}", case.id);
        assert_eq!(candidates[0].type_name(), "cloudflare_api_token");
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(case.start, case.start + 53).unwrap(),
            "{}",
            case.id
        );

        let context = DetectorContext::new(case.twin.len());
        let candidates = detector.detect(&case.twin, &context).unwrap();
        assert!(candidates.is_empty(), "{}-twin", case.id);
    }
}

/// Redaction replaces exactly the token bytes and leaves every surrounding
/// byte untouched; a twin's text passes through byte-for-byte.
#[test]
fn redaction_replaces_only_the_token_and_preserves_the_surrounding_bytes() {
    let registry = registry();
    for case in snapshots() {
        let redacted = scan_and_redact(
            &case.positive,
            &registry,
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap();
        let expected = format!(
            "{}<SECRET_1>{}",
            &case.positive[..case.start],
            &case.positive[case.start + 53..]
        );
        assert_eq!(redacted.text(), expected, "{}", case.id);
        assert_eq!(redacted.findings().len(), 1, "{}", case.id);

        let untouched = scan_and_redact(
            &case.twin,
            &registry,
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap();
        assert_eq!(untouched.text(), case.twin, "{}-twin", case.id);
        assert!(untouched.findings().is_empty(), "{}-twin", case.id);
    }
}

/// Whole-input/incremental parity at every UTF-8 byte partition of every
/// snapshot input, including splits inside the multi-byte emoji, the CRLF
/// pair, and the token itself.
#[test]
fn every_byte_partition_reproduces_the_whole_input_result() {
    for case in snapshots() {
        for (label, input) in [("positive", &case.positive), ("twin", &case.twin)] {
            let (expected_text, expected_findings) = whole_input(input);
            for pieces in utf8_byte_partitions(input) {
                let session = run(&as_chunks(&pieces));
                assert_eq!(
                    session.text(),
                    expected_text,
                    "{}-{label}: text at partition {pieces:?}",
                    case.id
                );
                let findings = session.findings();
                assert_eq!(
                    findings.len(),
                    expected_findings.len(),
                    "{}-{label}: finding count at partition {pieces:?}",
                    case.id
                );
                for (finding, expected) in findings.iter().zip(&expected_findings) {
                    assert_eq!(finding.range(), expected.range(), "{}-{label}", case.id);
                    assert_eq!(
                        finding.detector(),
                        expected.detector(),
                        "{}-{label}",
                        case.id
                    );
                }
            }
        }
    }
}
