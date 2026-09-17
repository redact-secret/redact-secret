//! Issue #369: the `DigitalOcean` v1 token contract, driven through the public
//! API exactly as the beta.4 benchmark drove the published package.
//!
//! The twelve inputs below are the issue's self-contained synthetic
//! snapshot: for each documented prefix, a paired positive (documented prefix
//! plus exactly 64 lowercase hex bytes) and its negative twin (the same value
//! with its final byte dropped), each bare and after a Unicode comment line
//! with CRLF endings. `@redact-secret/core@0.1.0-beta.4` flagged all six
//! twins under the earlier 20-byte `[A-Za-z0-9_-]` minimum; this file pins
//! the corrected behavior on the whole-input surface, the provider detector
//! in isolation, and every UTF-8 byte partition of the incremental surface.
//! Every value is locally constructed and was never provider-issued.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{
    ByteRange, Confidence, DefaultPolicy, DetectorContext, DetectorRegistry, Specificity,
    default_placeholder_formatter, scan, scan_and_redact,
};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

const PAT_BODY: &str = "1f24601fd1e661dc9b0a5f6e206888cac4ba0147c46563ccd2d81004e954cad9";
const OAUTH_ACCESS_BODY: &str = "025343c0555235768c29735f523ad644fbfe1569b1d88f46b4f506628ae8b08a";
const OAUTH_REFRESH_BODY: &str = "686b232b8722f7ab110b24d01fd9a96539cdec166f27e643ae9852b28d2b0da5";

/// One snapshot pair: the benchmark fixture id stem, the positive input, and
/// the UTF-8 byte range the positive must match at (the twin is the same
/// framing around the value with its last byte dropped and must match
/// nothing).
struct Snapshot {
    id: &'static str,
    positive: String,
    twin: String,
    start: usize,
}

fn snapshots() -> Vec<Snapshot> {
    let mut cases = Vec::new();
    for (prefix, body, name) in [
        ("dop_v1_", PAT_BODY, "dop"),
        ("doo_v1_", OAUTH_ACCESS_BODY, "doo"),
        ("dor_v1_", OAUTH_REFRESH_BODY, "dor"),
    ] {
        let token = format!("{prefix}{body}");
        let twin = &token[..token.len() - 1];
        cases.push(Snapshot {
            id: match name {
                "dop" => "digitalocean-token-dop-plain",
                "doo" => "digitalocean-token-doo-plain",
                _ => "digitalocean-token-dor-plain",
            },
            positive: format!("{token}\n\n"),
            twin: format!("{twin}\n\n"),
            start: 0,
        });
        cases.push(Snapshot {
            id: match name {
                "dop" => "digitalocean-token-dop-unicode-crlf",
                "doo" => "digitalocean-token-doo-unicode-crlf",
                _ => "digitalocean-token-dor-unicode-crlf",
            },
            positive: format!("# \u{1F511} reviewed format\r\n{token}\n\r\n"),
            twin: format!("# \u{1F511} reviewed format\r\n{twin}\n\r\n"),
            start: 24,
        });
    }
    cases
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
        assert_eq!(finding.detector(), "digitalocean-token", "{}", case.id);
        assert_eq!(finding.type_name(), "digitalocean_token", "{}", case.id);
        assert_eq!(finding.confidence(), Confidence::High, "{}", case.id);
        assert_eq!(
            finding.range(),
            ByteRange::new(case.start, case.start + 71).unwrap(),
            "{}",
            case.id
        );
        assert!(finding.action().replaces_text(), "{}", case.id);
    }
}

/// The reproduced beta.4 false positives: not only is the provider detector
/// silent on each 63-byte twin, no other default detector claims the bare
/// value either, so the default scan produces nothing to attribute.
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
        .find(|registered| registered.id() == "digitalocean-token")
        .expect("digitalocean-token is a built-in detector")
        .detector();
    for case in snapshots() {
        let context = DetectorContext::new(case.positive.len());
        let candidates = detector.detect(&case.positive, &context).unwrap();
        assert_eq!(candidates.len(), 1, "{}", case.id);
        assert_eq!(candidates[0].type_name(), "digitalocean_token");
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(case.start, case.start + 71).unwrap(),
            "{}",
            case.id
        );

        let context = DetectorContext::new(case.twin.len());
        let candidates = detector.detect(&case.twin, &context).unwrap();
        assert!(candidates.is_empty(), "{}-twin", case.id);
    }
}

/// Redaction replaces exactly the token bytes and leaves every surrounding
/// byte -- the Unicode comment, both line endings, and the trailing blank
/// line -- untouched; a twin's text passes through byte-for-byte.
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
            &case.positive[case.start + 71..]
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
/// snapshot input, including the split that isolates the single final body
/// byte distinguishing a twin from its paired positive, and splits inside
/// the multi-byte emoji and the CRLF pair.
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
