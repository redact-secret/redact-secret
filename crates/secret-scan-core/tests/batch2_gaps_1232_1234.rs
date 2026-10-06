//! Batch 2 measured product gaps (redact-secret#1232, #1233, #1234), driven
//! through the public default pipeline.
//!
//! The independent oracle is the frozen round-2 corpus of
//! redact-secret-benchmarks#761 (sha256 `a312308a...b8b921`, evidence
//! `evidence/739/round2`). Every input here is re-authored from that corpus's
//! layouts with unmistakably synthetic values; the expected span of a positive
//! is the credential value itself, as a UTF-8 byte offset inside the input,
//! and the expected action is `redact`. Nothing asserts a width, an alphabet
//! or a provider type.
//!
//! * #1232: an empty form or assignment value followed by `&next=...` no
//!   longer takes the next parameter as its value.
//! * #1233: the `HubSpot` CLI `personalAccessKey` field and the
//!   `HUBSPOT_PERSONAL_ACCESS_KEY` variable are read, as two whole names.
//! * #1234: the `YOUR_<NAME>` placeholder under a password name is silent.
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

/// Exactly one `redact` finding of `contextual_secret` spanning exactly
/// `value` (found once in `input`), at high confidence.
fn assert_value(input: &str, value: &str) {
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
    let start = input.find(value).expect("the value is in the input");
    assert_eq!(input.matches(value).count(), 1, "{input:?}");
    let range = findings[0].range();
    assert_eq!((range.start(), range.end()), (start, start + value.len()));
    assert_eq!(findings[0].type_name(), "contextual_secret", "{input:?}");
    assert_eq!(findings[0].action(), Action::Redact, "{input:?}");
    assert_eq!(findings[0].confidence(), Confidence::High, "{input:?}");
    let (text, _) = whole_input(input);
    assert!(!text.contains(value), "{input:?}: {text:?}");
}

// ------------------------------------------------- #1232 empty form value

const VALUE: &str = "Xq7Lm2Zp9TrW4vKc8NbY3hJd6FsA1eGuQw5Rt0YkM2xN";
const VALUE_B: &str = "Hn4Vd8Ks2PxQ7mLb3ZcW9tRy6FjA1eGuTo5Ek0Ms";
/// A short mixed-class value that only reaches the medium, warn tier.
const SHORT_PASSWORD: &str = "Kw9Rm3Xv!zQb";

/// The names of the 15 rows the shared parser path serves, plus `password`.
const EMPTY_VALUE_NAMES: [&str; 5] = [
    "access_token",
    "refresh_token",
    "client_secret",
    "oauth_token_secret",
    "password",
];

#[test]
fn an_empty_value_followed_by_another_form_parameter_is_not_a_finding() {
    for name in EMPTY_VALUE_NAMES {
        for tail in ["&other=1", "&grant_type=x", "&a=1&b=2", "&other="] {
            assert_clean(&format!("{name}={tail}"));
            assert_clean(&format!("?{name}={tail}"));
            assert_clean(&format!("a=1&{name}={tail}"));
            assert_clean(&format!("{name} = {tail}"));
            assert_clean(&format!("{name}: {tail}"));
        }
    }
}

#[test]
fn an_empty_value_at_every_other_delimiter_stays_silent() {
    for name in EMPTY_VALUE_NAMES {
        for input in [
            format!("{name}="),
            format!("{name}=\n"),
            format!("{name}=\r\nother=1"),
            format!("{name}=\nother=1\n"),
            format!("{name}=;other=1"),
            format!("{name}=,other=1"),
            format!("{name}= &other=1"),
            format!("{name}= other=1"),
            format!("{name}=\"\""),
            format!("{name}=\"\"&other=1"),
            format!("{name}=''&other=1"),
            format!("{name}=\"\"\n"),
            format!("{{\"{name}\":\"\",\"b\":1}}"),
            format!("{{\"{name}\":\"\"}}"),
            format!("{name}: \"\"\nb: 1\n"),
            format!("{name}: ''\r\nb: 1\r\n"),
            format!("{name}:\n"),
        ] {
            assert_clean(&input);
        }
    }
}

#[test]
fn a_parameter_after_an_empty_value_is_still_detected_on_its_own_terms() {
    for name in EMPTY_VALUE_NAMES {
        let input = format!("{name}=&client_secret={VALUE}");
        assert_value(&input, VALUE);
        let input = format!("{name}=&other=1&refresh_token={VALUE}&grant_type=x");
        assert_value(&input, VALUE);
        let input = format!("?{name}=&access_token={VALUE}#frag");
        assert_value(&input, VALUE);
    }
    // Two empty parameters in a row and then a credential.
    assert_value(
        &format!("access_token=&refresh_token=&client_secret={VALUE}"),
        VALUE,
    );
}

#[test]
fn the_same_names_with_real_values_end_at_the_form_delimiter_as_before() {
    for name in EMPTY_VALUE_NAMES {
        assert_value(&format!("{name}={VALUE}&other=1"), VALUE);
        assert_value(&format!("{name}={VALUE}"), VALUE);
        assert_value(&format!("a=1&{name}={VALUE}&b=2"), VALUE);
        assert_value(&format!("{{\"{name}\":\"{VALUE}\",\"b\":1}}"), VALUE);
        assert_value(&format!("{name}: {VALUE}\nb: 1\n"), VALUE);
    }
    // Two real parameters, both reported with their own exact value.
    let input = format!("refresh_token={VALUE}&client_secret={VALUE_B}&other=1");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 2, "{findings:?}");
    for (finding, value) in findings.iter().zip([VALUE, VALUE_B]) {
        let start = input.find(value).unwrap();
        assert_eq!(
            (finding.range().start(), finding.range().end()),
            (start, start + value.len())
        );
    }
}

#[test]
fn a_value_that_merely_starts_with_an_ampersand_is_still_a_value() {
    // `&` followed by a value is not `&name=`: it is no form delimiter of a next
    // parameter, so a password that starts with `&` is still reported.
    let input = format!("password=&{SHORT_PASSWORD}");
    let input = input.as_str();
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(
        (findings[0].range().start(), findings[0].range().end()),
        (9, input.len())
    );
    assert_eq!(findings[0].action(), Action::Warn);
}

#[test]
fn an_empty_value_never_yields_a_span_that_starts_at_the_delimiter() {
    // The benchmark's minimal repros: the old span was `&other=1` (14..22)
    // and `&grant_type=x` (14..27).
    for input in ["refresh_token=&other=1", "client_secret=&grant_type=x"] {
        let findings = findings_with_parity(input);
        for finding in &findings {
            assert_ne!(input.as_bytes()[finding.range().start()], b'&', "{input:?}");
        }
        assert!(findings.is_empty(), "{input:?}: {findings:?}");
    }
}
// --------------------------------------------- #1233 HubSpot personal key

const HUBSPOT_KEY: &str = "Xq7Lm2Zp9TrW4vKc8NbY3hJd6FsA1eGuQw5Rt0YkM2xN";

#[test]
fn hubspot_personal_access_key_is_redacted_in_every_documented_layout() {
    assert_eq!(HUBSPOT_KEY.len(), 44);
    for input in [
        // yaml-account
        format!(
            "defaultAccount: 1\naccounts:\n  - name: dev\n    accountId: 12345\n    authType: personalaccesskey\n    personalAccessKey: {HUBSPOT_KEY}\n    env: qa\n"
        ),
        // yaml-quoted
        format!(
            "accounts:\n  - authType: personalaccesskey\n    personalAccessKey: '{HUBSPOT_KEY}'\n"
        ),
        format!(
            "accounts:\n  - authType: personalaccesskey\n    personalAccessKey: \"{HUBSPOT_KEY}\"\n"
        ),
        // yaml-eof-crlf: no trailing newline, and CRLF line endings
        format!(
            "accounts:\r\n  - authType: personalaccesskey\r\n    personalAccessKey: {HUBSPOT_KEY}"
        ),
        format!(
            "accounts:\r\n  - authType: personalaccesskey\r\n    personalAccessKey: {HUBSPOT_KEY}\r\n"
        ),
        // yaml-same-shape: a public value of the same alphabet and length
        format!(
            "accounts:\n  - name: dev\n    portalId: 1234567890123456789012345678901234567890\n    personalAccessKey: {HUBSPOT_KEY}\n"
        ),
        // env, export-quoted, env-eof, docker-compose
        format!("HUBSPOT_PERSONAL_ACCESS_KEY={HUBSPOT_KEY}\nHUBSPOT_PORTAL_ID=12345\n"),
        format!("export HUBSPOT_PERSONAL_ACCESS_KEY=\"{HUBSPOT_KEY}\"\n"),
        format!("HUBSPOT_PERSONAL_ACCESS_KEY={HUBSPOT_KEY}"),
        format!(
            "services:\n  app:\n    environment:\n      - HUBSPOT_PERSONAL_ACCESS_KEY={HUBSPOT_KEY}\n"
        ),
        format!(
            "services:\n  app:\n    environment:\n      HUBSPOT_PERSONAL_ACCESS_KEY: {HUBSPOT_KEY}\n"
        ),
        // a multi-byte prefix: the span offset is in UTF-8 bytes
        format!("# caf\u{e9} \u{1F680}\npersonalAccessKey: {HUBSPOT_KEY}\n"),
    ] {
        assert_value(&input, HUBSPOT_KEY);
    }
}

#[test]
fn hubspot_personal_access_key_carries_no_provider_attribution() {
    let findings = findings_with_parity(&format!("personalAccessKey: {HUBSPOT_KEY}\n"));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].type_name(), "contextual_secret");
    assert!(!findings[0].detector().contains("hubspot"));
}

#[test]
fn a_low_entropy_hubspot_key_is_a_warn_at_medium_confidence() {
    let input = "personalAccessKey: abababababababab\n";
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].action(), Action::Warn);
    assert_eq!(findings[0].confidence(), Confidence::Medium);
}

#[test]
fn hubspot_public_config_placeholders_references_masks_and_lookalikes_stay_clean() {
    for input in [
        // public-only config
        "defaultAccount: 1\naccounts:\n  - name: dev\n    accountId: 12345\n    portalId: 12345\n    authType: personalaccesskey\n    env: qa\n".to_string(),
        // placeholders, references, masks
        "personalAccessKey: YOUR_PERSONAL_ACCESS_KEY\n".to_string(),
        "personalAccessKey: <personal-access-key>\n".to_string(),
        "personalAccessKey: ${HUBSPOT_PERSONAL_ACCESS_KEY}\n".to_string(),
        "personalAccessKey: $HUBSPOT_PERSONAL_ACCESS_KEY\n".to_string(),
        "personalAccessKey: ****************************\n".to_string(),
        "HUBSPOT_PERSONAL_ACCESS_KEY=your_personal_access_key_here\n".to_string(),
        "HUBSPOT_PERSONAL_ACCESS_KEY=${HUBSPOT_PERSONAL_ACCESS_KEY}\n".to_string(),
        "HUBSPOT_PERSONAL_ACCESS_KEY=\n".to_string(),
        "personalAccessKey: \"\"\n".to_string(),
        // neighbouring names and a further-prefixed lookalike
        format!("personalAccessKeyId: {HUBSPOT_KEY}\n"),
        format!("personalAccessKeyExpiresAt: {HUBSPOT_KEY}\n"),
        format!("personalAccessKeyHint: {HUBSPOT_KEY}\n"),
        format!("personalAccessKeyLength: {HUBSPOT_KEY}\n"),
        format!("my_personal_access_key: {HUBSPOT_KEY}\n"),
        format!("oldPersonalAccessKey: {HUBSPOT_KEY}\n"),
        format!("HUBSPOT_PERSONAL_ACCESS_KEY_ID={HUBSPOT_KEY}\n"),
        format!("HUBSPOT_PERSONAL_ACCESS_KEY_EXPIRES_AT={HUBSPOT_KEY}\n"),
        format!("portalId: {HUBSPOT_KEY}\n"),
        format!("authType: {HUBSPOT_KEY}\n"),
        // an arbitrary `*key` name is not admitted
        format!("accessKey: {HUBSPOT_KEY}\n"),
        format!("personalKey: {HUBSPOT_KEY}\n"),
        format!("hubspot_key: {HUBSPOT_KEY}\n"),
    ] {
        assert_clean(&input);
    }
}
