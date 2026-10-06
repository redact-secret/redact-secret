//! The Group D role, confidentiality and family-modelling boundaries
//! (redact-secret#1229), driven through the public default pipeline.
//!
//! `docs/audits/evidence/1229/README.md` adopts a conditional contract and
//! claims no row covered. The decision record
//! `decision-keep-credential-role-facts-out-of-detection-attribution-and-default-action`
//! freezes four boundaries that are cheap to pin and need no code change:
//!
//! * a role fact (admin, search-only, read-only, preview, delivery, plan) does
//!   not change the reading of the same carrier: the finding type, action,
//!   confidence and span are identical across roles, and no role is silent;
//! * a composite carrier value is one span, the public half included, in every
//!   layout the Meta pair is documented in;
//! * a transient authorization code is judged by the ambiguity tier, the
//!   code verifier is not;
//! * a derived output under an unmatched name is silent, and one under a
//!   credential name is read by that name (the #1241 deviation, recorded).
//!
//! These are policy pins, not coverage claims. Every value is synthetic and
//! built at runtime from a fixed pseudo-random alphabet walk.
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

/// Exactly one finding spanning exactly `value` (found once in `input`).
fn one_finding(input: &str, value: &str) -> Finding {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    assert_eq!(input.matches(value).count(), 1, "{input:?}");
    let start = input.find(value).expect("the value is in the input");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    findings[0].clone()
}

fn assert_redacted(input: &str, value: &str, type_name: &str) {
    let finding = one_finding(input, value);
    assert_eq!(finding.type_name(), type_name, "{input:?}");
    assert_eq!(finding.action(), Action::Redact, "{input:?}");
    assert_eq!(finding.confidence(), Confidence::High, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

const ALNUM: &[u8; 62] = b"Qf7Lm2Zp9TrW4vKc8NbYxJdH6sAeGuwR5tykMXnPaUoVhCiBDgEjFlIqOSTz03";
const HEX: &[u8; 16] = b"3f9a07c2e5b8d146";

fn run_of(len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| ALNUM[(i * 7 + seed * 13 + 3) % ALNUM.len()] as char)
        .collect()
}

fn hex_of(len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| HEX[(i * 5 + seed * 3 + 1) % HEX.len()] as char)
        .collect()
}

#[test]
fn every_algolia_role_is_read_like_every_other() {
    // The shared `x-algolia-api-key` header carries all seven roles, and the
    // role comes only from context. A search-only key is documented as safe in
    // frontend code and as scrapable: it is not silent, and no role is
    // attributed. The variable names are the product's reading of a prefixed
    // `*_api_key` name, not names the evidence reviewed.
    for (seed, role) in [
        "ADMIN",
        "SEARCH_ONLY",
        "WRITE",
        "ANALYTICS",
        "MONITORING",
        "USAGE",
    ]
    .iter()
    .enumerate()
    {
        let value = hex_of(32, seed);
        assert_redacted(
            &format!("ALGOLIA_{role}_API_KEY={value}"),
            &value,
            "contextual_secret",
        );
    }
    let value = hex_of(32, 9);
    assert_redacted(
        &format!("x-algolia-application-id: WXYZ1234AB\nx-algolia-api-key: {value}"),
        &value,
        "contextual_secret",
    );
    // A secured key is a derived value; as a credential in a carrier it is read
    // like the others.
    let secured = run_of(88, 10);
    assert_redacted(
        &format!("ALGOLIA_SECURED_API_KEY={secured}"),
        &secured,
        "contextual_secret",
    );
}

#[test]
fn delivery_and_preview_tokens_are_read_alike_in_every_documented_carrier() {
    // Contentful states Delivery is read-only and environment-scoped and that
    // Preview exists to avoid leaking unpublished content; no page says whether
    // either may be public. Neither is silent, and neither is attributed.
    let delivery = run_of(43, 11);
    let preview = run_of(43, 12);
    assert_redacted(
        &format!("CONTENTFUL_DELIVERY_TOKEN={delivery}"),
        &delivery,
        "contextual_secret",
    );
    assert_redacted(
        &format!("CONTENTFUL_PREVIEW_ACCESS_TOKEN={preview}"),
        &preview,
        "contextual_secret",
    );
    assert_redacted(
        &format!("https://cdn.example.test/spaces/s1/entries?access_token={delivery}"),
        &delivery,
        "contextual_secret",
    );
    assert_redacted(
        &format!("GET /spaces/s1/entries HTTP/1.1\nAuthorization: Bearer {preview}\n"),
        &preview,
        "bearer_token",
    );
}

#[test]
fn a_composite_carrier_value_is_one_span_with_the_public_half_inside() {
    // The Meta `{app-id}|{app-secret}` pair is one `access_token` value. It is
    // one finding over the whole composite in every layout, never a secret-only
    // span: splitting would need a composite grammar the evidence does not
    // state, and the whole span cannot leave the secret half readable.
    let app_id = "1234567890123456";
    let secret = hex_of(32, 13);
    let composite = format!("{app_id}|{secret}");
    assert_redacted(
        &format!("https://graph.example.test/v1/x?access_token={composite}&fields=id"),
        &composite,
        "contextual_secret",
    );
    assert_redacted(
        &format!("access_token={composite}&format=json"),
        &composite,
        "contextual_secret",
    );
    assert_redacted(
        &format!("{{\"access_token\":\"{composite}\"}}"),
        &composite,
        "contextual_secret",
    );
    assert_redacted(
        &format!("Authorization: Bearer {composite}"),
        &composite,
        "bearer_token",
    );
}

#[test]
fn a_canva_authorization_code_is_the_ambiguity_tier_and_the_verifier_is_not() {
    // `code` is an ambiguous query or form name: a 64-byte value is a medium
    // warn that leaves the text unchanged, never a redaction, because no source
    // states the code's confidentiality. `code_verifier` is a high-signal name.
    let code = run_of(64, 14);
    let verifier = run_of(64, 15);
    for input in [
        format!("https://app.example.test/cb?code={code}&state=abc"),
        format!("grant_type=authorization_code&code={code}"),
    ] {
        let finding = one_finding(&input, &code);
        assert_eq!(finding.type_name(), "contextual_secret", "{input:?}");
        assert_eq!(finding.action(), Action::Warn, "{input:?}");
        assert_eq!(finding.confidence(), Confidence::Medium, "{input:?}");
        let (text, _) = whole_input(&input);
        assert_eq!(text, input);
    }
    assert_redacted(
        &format!("grant_type=authorization_code&code_verifier={verifier}"),
        &verifier,
        "contextual_secret",
    );
}

#[test]
fn derived_outputs_are_silent_under_unmatched_names_and_read_by_name_otherwise() {
    // A signature header and a keyed proof are not secret inputs and sit under
    // names the vocabulary does not match: silent.
    assert_clean(&format!(
        "x-zm-signature: v0={}\nx-zm-request-timestamp: 1760000000",
        hex_of(64, 16)
    ));
    assert_clean(&format!("appsecret_proof={}", hex_of(64, 17)));
    // A derived value carried under a prefixed `_token` name is read by that
    // name, the same deviation from the evidence role as `oauth_token` (#1241):
    // redacted by default policy, a user lowers it with the action configuration.
    let plain = run_of(22, 18);
    let encrypted = hex_of(64, 19);
    let input = format!("{{\"plainToken\":\"{plain}\",\"encryptedToken\":\"{encrypted}\"}}");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 2, "{findings:?}");
    for (finding, value) in findings.iter().zip([&plain, &encrypted]) {
        let start = input.find(value.as_str()).expect("the value is present");
        let range = finding.range();
        assert_eq!((range.start(), range.end()), (start, start + value.len()));
        assert_eq!(finding.type_name(), "contextual_secret");
        assert_eq!(finding.action(), Action::Redact);
        assert_eq!(finding.confidence(), Confidence::High);
    }
}
