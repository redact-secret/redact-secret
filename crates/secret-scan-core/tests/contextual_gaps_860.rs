//! Issue #860 Tier B generic-coverage gaps through the public API with the
//! full default registry: the `bearer-token` joined-value span (#918) and
//! the `generic-token` exact names and `Authorization: Key` scheme (#919).
//!
//! Every value is built at run time from synthetic filler, so no realistic
//! credential literal is committed. The fal-shaped `<uuid>:<hex32>` and the
//! `<name>|<secret>` values are hexspeak and marker words, never issued.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Deterministic synthetic lowercase hex.
fn hex(len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(b"0123456789abcdef"[(i * 7 + seed * 5 + i / 3) % 16]))
        .collect()
}

/// A fal-shaped `<uuid>:<hex32>` value (the id half is public-ish, the
/// secret half is the credential).
fn id_secret() -> String {
    format!("5e7c0ded-feed-4bad-9ace-0ddba11c0de5:{}", hex(32, 1))
}

/// A `<name>|<secret>` value that is not Convex-shaped.
fn name_secret() -> String {
    "svc-deploy|SyntheticRevokedJoinedSecretValue0000".to_owned()
}

fn sole_finding(input: &str) -> Finding {
    let (_, findings) = whole_input(input);
    assert_eq!(findings.len(), 1, "{input}: {findings:?}");
    findings.into_iter().next().unwrap()
}

fn assert_whole_value(input: &str, value: &str, detector: &str, type_name: &str) {
    let finding = sole_finding(input);
    let start = input.find(value).unwrap();
    assert_eq!(finding.detector(), detector, "{input}");
    assert_eq!(finding.type_name(), type_name, "{input}");
    assert_eq!(finding.action(), Action::Redact, "{input}");
    assert_eq!(
        (finding.range().start(), finding.range().end()),
        (start, start + value.len()),
        "{input}"
    );
    let (text, _) = whole_input(input);
    for half in value.split([':', '|']) {
        assert!(!text.contains(half), "{input}: {half} left in clear");
    }
}

fn assert_partition_parity(input: &str) {
    let (expected_text, expected) = whole_input(input);
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        assert_eq!(session.text(), expected_text, "{pieces:?}");
        let findings = session.findings();
        assert_eq!(findings.len(), expected.len(), "{pieces:?}");
        for (got, want) in findings.iter().zip(&expected) {
            assert_eq!(got.range(), want.range());
            assert_eq!(got.detector(), want.detector());
            assert_eq!(got.type_name(), want.type_name());
        }
    }
}

mod bearer_joined_value {
    use super::*;

    fn bearer_contexts(value: &str) -> Vec<String> {
        vec![
            format!("Authorization: Bearer {value}\n"),
            format!("curl -H \"Authorization: Bearer {value}\" https://example.invalid/v1\n"),
            format!("{{\"headers\": {{\"Authorization\": \"Bearer {value}\"}}}}"),
            format!("Proxy-Authorization: Bearer {value}\r\n"),
            format!("requests.get(url, headers={{'Authorization': 'Bearer {value}'}})"),
        ]
    }

    #[test]
    fn id_secret_and_name_secret_values_are_redacted_whole() {
        for value in [id_secret(), name_secret()] {
            for input in bearer_contexts(&value) {
                assert_whole_value(&input, &value, "bearer-token", "bearer_token");
            }
        }
    }

    #[test]
    fn ordinary_bearer_headers_keep_their_span() {
        let value = "SyntheticRevokedBearerValue00";
        for (input, expected) in [
            (format!("Authorization: Bearer {value}\n"), value),
            (format!("Authorization: Bearer {value}: see docs\n"), value),
            (format!("| Bearer {value} | header |\n"), value),
            (format!("Bearer {value}://example.invalid/x\n"), value),
        ] {
            let finding = sole_finding(&input);
            let start = input.find(expected).unwrap();
            assert_eq!(
                (finding.range().start(), finding.range().end()),
                (start, start + expected.len()),
                "{input}"
            );
        }
        for input in [
            "The bearer of this letter may collect it.\n",
            "an OAuth bearer https://example.invalid/rfc6750 per the spec\n",
            "The bearer 10:30 train leaves now.\n",
        ] {
            let (_, findings) = whole_input(input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!("Authorization: Bearer {}\n", id_secret()));
        assert_partition_parity(&format!("Authorization: Bearer {}\n", name_secret()));
    }
}
