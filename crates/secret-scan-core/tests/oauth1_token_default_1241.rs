//! The default reading of the OAuth 1.0 `oauth_token` field (redact-secret#1241),
//! driven through the public default pipeline.
//!
//! The accepted contract (#1225) keeps the prefixed `_token` default: a random
//! value under `oauth_token` is `contextual_secret`, redacted, exactly like
//! `access_token`; the evidence handoff lists the same field as a public
//! lookalike. The decision of #1241 keeps the product default as an intentional,
//! documented policy deviation from the evidence role. These tests pin it so a
//! change of the default is visible, together with the neighbouring OAuth 1.0
//! fields that stay silent. Every value is synthetic and built at runtime from
//! unmistakably fake filler.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Confidence, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// Whole-input findings, and the same text and findings under every two-chunk
/// UTF-8 byte partition and a line-per-chunk incremental session.
fn findings_with_parity(input: &str) -> Vec<Finding> {
    let (expected_text, expected) = whole_input(input);
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        assert_eq!(session.text(), expected_text, "{input:?}: {pieces:?}");
        assert_eq!(session.findings(), expected, "{input:?}: {pieces:?}");
    }
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let session = run(&lines);
    assert_eq!(session.text(), expected_text, "{input:?}: per line");
    assert_eq!(session.findings(), expected, "{input:?}: per line");
    expected
}

fn assert_clean(input: &str) {
    let findings = findings_with_parity(input);
    assert!(findings.is_empty(), "{input:?}: {findings:?}");
}

/// The byte range of the one occurrence of `value` in `input`.
fn span_of(input: &str, value: &str) -> (usize, usize) {
    assert_eq!(input.matches(value).count(), 1, "{input:?}");
    let start = input.find(value).expect("the value is in the input");
    (start, start + value.len())
}

/// Exactly the given values, in order, each a `contextual_secret` `redact`
/// finding at high confidence spanning exactly that value (and no more).
fn assert_values(input: &str, values: &[&str]) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), values.len(), "{input:?}: {findings:?}");
    for (finding, value) in findings.iter().zip(values) {
        let (start, end) = span_of(input, value);
        let range = finding.range();
        assert_eq!((range.start(), range.end()), (start, end), "{input:?}");
        assert_eq!(finding.type_name(), "contextual_secret", "{input:?}");
        assert_eq!(finding.action(), Action::Redact, "{input:?}");
        assert_eq!(finding.confidence(), Confidence::High, "{input:?}");
    }
    let (text, _) = whole_input(input);
    for value in values {
        assert!(!text.contains(value), "{input:?}: {text:?}");
    }
}

/// A 20-byte random-looking token and a 44-byte random-looking secret, plus a
/// long identifier of the numeric-prefix shape some providers issue.
const TOKEN: &str = "Qf7Lm2Zp9TrW4vKc8NbY";
const SECRET: &str = "Xq7Lm2Zp9TrW4vKc8NbY3hJd6FsA1eGuQw5Rt0YkM2xN";
const NUMERIC_TOKEN: &str = "7810473289-Hn4Vd8Ks2PxQ7mLb3ZcW9tRy6FjA1eGuTo5Ek0Ms";
/// The public halves and signing outputs of a signed request.
/// A short mixed-class value that only reaches the medium, warn tier.
const SHORT_VALUE: &str = "Kw9Rm3Xv!zQb";
const SIGNATURE: &str = "Zs8%2BqTm4Wd7Lk1Rv6Hx";

#[test]
fn a_random_oauth_token_is_a_contextual_secret_like_access_token() {
    assert_values(&format!("oauth_token={TOKEN}"), &[TOKEN]);
    assert_values(&format!("access_token={TOKEN}"), &[TOKEN]);
    assert_values(&format!("{{\"oauth_token\":\"{TOKEN}\"}}"), &[TOKEN]);
    assert_values(&format!("oauth_token={NUMERIC_TOKEN}"), &[NUMERIC_TOKEN]);
}

#[test]
fn the_request_token_response_reports_both_halves_as_separate_spans() {
    let input =
        format!("oauth_token={TOKEN}&oauth_token_secret={SECRET}&oauth_callback_confirmed=true");
    assert_values(&input, &[TOKEN, SECRET]);
}

#[test]
fn an_authorize_redirect_query_parameter_is_read() {
    // No secret half is anywhere near: the identifier alone is still read,
    // which is why a "only when paired with the secret" rule is not adopted.
    let input = format!("https://api.example.test/oauth/authorize?oauth_token={TOKEN}");
    assert_values(&input, &[TOKEN]);
}

#[test]
fn only_the_oauth_token_of_a_signed_authorization_header_is_read() {
    let input = format!(
        "Authorization: OAuth oauth_consumer_key=\"consumerkey1\", oauth_nonce=\"n0nce7Kd2\", \
         oauth_signature=\"{SIGNATURE}\", oauth_signature_method=\"HMAC-SHA1\", \
         oauth_timestamp=\"1760000000\", oauth_token=\"{NUMERIC_TOKEN}\", oauth_version=\"1.0\""
    );
    assert_values(&input, &[NUMERIC_TOKEN]);
}

#[test]
fn the_signing_outputs_and_public_oauth_fields_stay_silent() {
    for input in [
        format!("oauth_signature={SIGNATURE}"),
        format!("oauth_signature={TOKEN}"),
        "oauth_consumer_key=consumerkey1".to_owned(),
        "oauth_nonce=n0nce7Kd2".to_owned(),
        "oauth_timestamp=1760000000".to_owned(),
        "oauth_version=1.0".to_owned(),
        "oauth_signature_method=HMAC-SHA1".to_owned(),
        "oauth_callback_confirmed=true".to_owned(),
        // A bare `token` name is not a credential name (#1203).
        format!("token={TOKEN}"),
    ] {
        assert_clean(&input);
    }
}

#[test]
fn a_placeholder_or_reference_under_oauth_token_is_silent() {
    for input in [
        "oauth_token=YOUR_OAUTH_TOKEN",
        "oauth_token=<oauth_token>",
        "oauth_token=${OAUTH_TOKEN}",
        "oauth_token=",
    ] {
        assert_clean(input);
    }
}

#[test]
fn a_low_entropy_oauth_token_is_a_medium_warn_not_a_redaction() {
    // The same tier as any other prefixed `_token` name: warn, text unchanged.
    let input = format!("oauth_token={SHORT_VALUE}");
    let input = input.as_str();
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].type_name(), "contextual_secret");
    assert_eq!(findings[0].action(), Action::Warn);
    assert_eq!(findings[0].confidence(), Confidence::Medium);
    let (text, _) = whole_input(input);
    assert_eq!(text, input);
}

#[test]
fn a_multibyte_prefix_shifts_the_utf8_byte_range() {
    let input = format!("토큰 oauth_token={TOKEN}");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let start = "토큰 oauth_token=".len();
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + TOKEN.len()));
}
