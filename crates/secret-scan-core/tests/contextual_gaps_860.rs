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
    fn a_lead_glued_to_a_placeholder_or_reference_yields_no_partial_span() {
        // Benchmarks #436: the lead before a glued placeholder is public.
        for input in [
            "Authorization: Bearer signkey-prod-<YOUR-SIGNING-KEY>\n",
            "Authorization: Bearer prod:happy-otter-123|${CONVEX_BODY}\n",
            "curl -H \"Authorization: Bearer convex-self-hosted|$CONVEX_ADMIN_KEY\" https://example.invalid\n",
        ] {
            let (_, findings) = whole_input(input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
        // Twin: the same lead with a literal secret part is redacted whole.
        let value = format!(
            "prod:happy-otter-123|SyntheticRevokedJoinedSecretValue{}",
            "0".repeat(4)
        );
        assert_whole_value(
            &format!("Authorization: Bearer {value}\n"),
            &value,
            "bearer-token",
            "bearer_token",
        );
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!("Authorization: Bearer {}\n", id_secret()));
        assert_partition_parity(&format!("Authorization: Bearer {}\n", name_secret()));
    }
}

mod generic_names_and_key_scheme {
    use super::*;

    const NEUTRAL: &str = "SYNTHETICrevokedNEUTRALvalue0042xyzw";

    #[test]
    fn exact_provider_names_yield_a_high_contextual_finding_at_the_whole_value() {
        let convex = "prod:happy-otter-123|01SYNTHETICrevokedCONVEXdeployKEY0042";
        for (name, value) in [
            ("FAL_KEY", id_secret()),
            ("FAL_KEY", NEUTRAL.to_owned()),
            ("CONVEX_DEPLOY_KEY", convex.to_owned()),
            ("CONVEX_SELF_HOSTED_ADMIN_KEY", convex.to_owned()),
        ] {
            for input in [
                format!("{name}={value}\n"),
                format!("export {name}=\"{value}\"\n"),
                format!("env:\n  {name}: {value}\n"),
            ] {
                assert_whole_value(&input, &value, "generic-token", "contextual_secret");
            }
        }
    }

    #[test]
    fn a_bare_key_suffix_is_not_broadened() {
        for name in [
            "PRIMARY_KEY",
            "SORT_KEY",
            "CACHE_KEY",
            "PARTITION_KEY",
            "IDEMPOTENCY_KEY",
            "CONVEX_KEY",
            "APP_FAL_KEY",
        ] {
            let input = format!("{name}={NEUTRAL}\n");
            let (_, findings) = whole_input(&input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
        for input in [
            "PRIMARY_KEY=id\n",
            "SORT_KEY=name\n",
            "CONVEX_DEPLOYMENT=dev:happy-otter-123\n",
            "FAL_KEY=your_fal_key\n",
            "FAL_KEY=${FAL_KEY}\n",
            "The Key to good authorization is rotation.\n",
            "Authorization: Key rotation\n",
        ] {
            let (_, findings) = whole_input(input);
            assert!(findings.is_empty(), "{input}: {findings:?}");
        }
    }

    #[test]
    fn the_key_scheme_is_redacted_whole() {
        let value = id_secret();
        for input in [
            format!("Authorization: Key {value}\n"),
            format!("curl -H \"Authorization: Key {value}\" https://example.invalid/run\n"),
            format!("{{\"headers\": {{\"Authorization\": \"Key {value}\"}}}}"),
        ] {
            assert_whole_value(&input, &value, "generic-token", "authorization_credential");
        }
    }

    #[test]
    fn every_two_chunk_partition_matches_the_whole_input() {
        assert_partition_parity(&format!("FAL_KEY={}\n", id_secret()));
        assert_partition_parity(&format!("Authorization: Key {}\n", id_secret()));
    }
}
