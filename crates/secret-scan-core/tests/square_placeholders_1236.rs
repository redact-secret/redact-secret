//! Square documentation placeholders are not findings (redact-secret#1236),
//! driven through the public default pipeline.
//!
//! The three inputs are the benchmarks' `beta8-583a` must-not-flag controls,
//! authored from the #1014 Square handoff. Real-shaped controls are assembled
//! at run time from a prefix and a generated body; no credential-shaped
//! literal is committed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, single_byte_partition, whole_input};

/// Whole input, the same input in 7-byte chunks and in 1-byte chunks; the
/// incremental results must equal the whole-input one.
fn findings_with_parity(input: &str) -> Vec<Finding> {
    let (expected_text, expected) = whole_input(input);
    let one = single_byte_partition(input);
    let session = run(&as_chunks(&one));
    assert_eq!(session.text(), expected_text, "{input:?}: 1-byte");
    assert_eq!(session.findings(), expected, "{input:?}: 1-byte");
    let seven: Vec<String> = input
        .as_bytes()
        .chunks(7)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    let session = run(&as_chunks(&seven));
    assert_eq!(session.text(), expected_text, "{input:?}: 7-byte");
    assert_eq!(session.findings(), expected, "{input:?}: 7-byte");
    expected
}

fn assert_clean(input: &str) {
    let findings = findings_with_parity(input);
    assert!(findings.is_empty(), "{input:?}: {findings:?}");
}

/// Exactly one `redact` finding spanning exactly `value`, of `type_name`.
fn assert_value(input: &str, value: &str, type_name: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    let start = input.find(value).expect("the value is in the input");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    assert_eq!(findings[0].type_name(), type_name, "{input:?}");
    assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

/// A synthetic body of `len` bytes over `[A-Za-z0-9_-]`, mixed so it never
/// reads as a counting run or filler.
fn body(len: usize, seed: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    (0..len)
        .map(|index| {
            ALPHABET[(index * 29 + seed * 17 + index * index * 7) % ALPHABET.len()] as char
        })
        .collect()
}

fn key(prefix: &str, len: usize, seed: usize) -> String {
    format!("{prefix}{}", body(len, seed))
}

// ------------------------------------------------------------ the 3 inputs

#[test]
fn the_three_benchmark_placeholders_are_silent() {
    assert_clean("SQUARE_ACCESS_TOKEN=EAAA-your-access-token\n");
    assert_clean("export SQUARE_ACCESS_TOKEN=\"EAAA<your-production-access-token>\"\n");
    assert_clean("client_secret: sandbox-sq0csb-<your-sandbox-application-secret>\n");
}

#[test]
fn placeholder_variants_are_silent() {
    for input in [
        "SQUARE_ACCESS_TOKEN=EAAA-your-access-token",
        "SQUARE_ACCESS_TOKEN=EAAA_YOUR_ACCESS_TOKEN\n",
        "SQUARE_ACCESS_TOKEN=\"EAAA-xxxxxxxx\"\n",
        "SQUARE_ACCESS_TOKEN=EAAA<your-access-token>\n",
        "SQUARE_ACCESS_TOKEN: \"EAAA<YOUR_SANDBOX_ACCESS_TOKEN>\"\r\n",
        "SQUARE_ACCESS_TOKEN=YOUR_ACCESS_TOKEN\n",
        "SQUARE_ACCESS_TOKEN=<your-access-token>\n",
        "client_secret: sq0csp-xxxxxxxx\n",
        "client_secret=sq0csp-<your-application-secret>\n",
        "client_secret: sq0csp-your-application-secret\n",
        "client_secret: \"sandbox-sq0csb-xxxxxxxx\"\n",
        "client_secret: sandbox-sq0csb-your-sandbox-application-secret\n",
        "client_secret: sandbox-sq0csb-YOUR_SANDBOX_APPLICATION_SECRET\n",
        "{\"client_secret\":\"sandbox-sq0csb-<your-secret>\"}\n",
    ] {
        assert_clean(input);
    }
}

// ------------------------------------------------------- real values stay

#[test]
fn real_shaped_square_values_are_still_detected_with_exact_spans() {
    let token = key("EAAA", 60, 1);
    assert_value(
        &format!("SQUARE_ACCESS_TOKEN={token}\n"),
        &token,
        "square_access_token",
    );
    assert_value(
        &format!("export SQUARE_ACCESS_TOKEN=\"{token}\"\n"),
        &token,
        "square_access_token",
    );
    for (prefix, len) in [("sq0csp-", 43), ("sq0csp-", 44), ("sandbox-sq0csb-", 43)] {
        let secret = key(prefix, len, 2);
        assert_value(
            &format!("client_secret: {secret}\n"),
            &secret,
            "square_oauth_application_secret",
        );
    }
}

#[test]
fn off_width_or_off_prefix_random_bodies_are_not_excused_by_the_placeholder_rule() {
    // Not a Square grammar, so only the contextual detector can see them; the
    // placeholder rule must not silence a random body behind the prefix.
    for value in [
        key("EAAA", 40, 3),
        key("EAAA-", 40, 4),
        key("sq0csp-", 30, 5),
        key("sandbox-sq0csb-", 30, 6),
        key("sq0atp-", 22, 7),
    ] {
        let findings = findings_with_parity(&format!("SQUARE_ACCESS_TOKEN={value}\n"));
        assert_eq!(findings.len(), 1, "{value}: {findings:?}");
        assert_eq!(findings[0].action(), Action::Redact, "{value}");
    }
}

#[test]
fn a_placeholder_glued_to_material_or_a_word_off_the_rule_stays_reported() {
    for value in [
        format!("EAAA<your-access-token>{}", body(24, 8)),
        format!("EAAA-your-access-token-{}", body(24, 9)),
        format!("EAAAyouraccesstoken{}", body(24, 10)),
        format!("EAAA-{}", body(40, 11)),
        format!(
            "sandbox-sq0csb-your-sandbox-application-secret{}",
            body(24, 12)
        ),
    ] {
        let findings = findings_with_parity(&format!("SQUARE_ACCESS_TOKEN={value}\n"));
        assert_eq!(findings.len(), 1, "{value}: {findings:?}");
    }
}

#[test]
fn an_uppercase_lead_outside_the_square_prefix_is_unchanged() {
    // #756: only the exact `EAAA` prefix qualifies as an uppercase lead.
    let findings = findings_with_parity("SQUARE_ACCESS_TOKEN=KEY_YOUR_API_KEY\n");
    assert_eq!(findings.len(), 1, "{findings:?}");
}
