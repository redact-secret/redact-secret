//! The golden-path convenience layer (`sanitize`, `sanitize_with_profile`) is
//! exactly `scan_and_redact` over the matching built-in registry (#1078).
//!
//! Every input is synthetic; generators stay within 32-bit `usize` so the
//! same tests run on `wasm32`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{
    DEFAULT_MAX_INPUT_BYTES, DefaultPolicy, DetectorRegistry, Profile, SecretScanErrorCode,
    default_placeholder_formatter, sanitize, sanitize_with_profile, scan_and_redact,
};

const SECRET: &str = "ghp_SYNTHETICREVOKED00000000000000000000";

fn registry(profile: Profile) -> DetectorRegistry {
    match profile {
        Profile::Full => DetectorRegistry::with_built_in([]).unwrap(),
        Profile::Common => DetectorRegistry::with_common_built_in([]).unwrap(),
        // `Profile` is `#[non_exhaustive]`: a new profile must add its own arm here.
        _ => panic!("profile without a reference registry"),
    }
}

fn assert_profile(input: &str, profile: Profile, label: &str) {
    let reference = scan_and_redact(
        input,
        &registry(profile),
        &DefaultPolicy,
        &default_placeholder_formatter,
    );
    assert_eq!(
        sanitize_with_profile(input, profile),
        reference,
        "{label} ({})",
        profile.as_str()
    );
    if profile == Profile::Full {
        assert_eq!(sanitize(input), reference, "{label} (default)");
    }
}

fn assert_equivalent(input: &str, label: &str) {
    assert_profile(input, Profile::Full, label);
    assert_profile(input, Profile::Common, label);
}

#[test]
fn matches_scan_and_redact_over_the_canonical_corpus() {
    for fixture in support::synchronous_corpus() {
        // The adversarial tier is large; the full profile covers it, and the
        // common profile covers every ordinary fixture.
        if fixture.input.len() <= 16 * 1024 {
            assert_equivalent(&fixture.input, &fixture.id);
        } else {
            assert_profile(&fixture.input, Profile::Full, &fixture.id);
        }
    }
}

#[test]
fn matches_scan_and_redact_over_generated_edge_cases() {
    let cases: Vec<(String, String)> = vec![
        ("empty".into(), String::new()),
        ("plain".into(), "no secrets here".into()),
        (
            "non-ascii".into(),
            format!("변수=값 \u{1F600} API_KEY={SECRET} é"),
        ),
        ("multibyte-adjacent".into(), format!("é{SECRET}é")),
        (
            "zwsp-split".into(),
            format!("API_KEY={}\u{200B}{}", &SECRET[..8], &SECRET[8..]),
        ),
        (
            "tag-chars".into(),
            format!("\u{E0041}API_KEY={SECRET}\u{E0042}"),
        ),
        ("bidi".into(), format!("\u{202E}API_KEY={SECRET}\u{202C}")),
        ("only-invisible".into(), "\u{200B}\u{200C}\u{FEFF}".into()),
        ("crlf".into(), format!("a\r\nAPI_KEY={SECRET}\r\nb")),
        (
            "private-key".into(),
            "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDUkVWT0tFRA==\n-----END PRIVATE KEY-----"
                .into(),
        ),
    ];
    for (label, input) in &cases {
        assert_equivalent(input, label);
    }
    // A deterministic, prefix-truncated sweep of one mixed input, including
    // every char boundary.
    let mixed = format!("x é {SECRET} \u{200B}API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE");
    for (end, _) in mixed.char_indices().chain([(mixed.len(), ' ')]) {
        assert_equivalent(&mixed[..end], &format!("prefix {end}"));
    }
}

#[test]
fn minimal_path_redacts_with_the_documented_defaults() {
    let result = sanitize(&format!("API_KEY={SECRET}")).unwrap();
    assert_eq!(result.text(), "API_KEY=<SECRET_1>");
    assert_eq!(result.findings().len(), 1);
}

#[test]
fn input_limit_error_is_identical_and_not_truncated() {
    let input = "a".repeat(DEFAULT_MAX_INPUT_BYTES + 1);
    let expected = scan_and_redact(
        &input,
        &registry(Profile::Full),
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap_err();
    assert_eq!(expected.code(), SecretScanErrorCode::InputLimitExceeded);
    assert_eq!(sanitize(&input).unwrap_err(), expected);
    assert_eq!(
        sanitize_with_profile(&input, Profile::Common).unwrap_err(),
        expected
    );
}

#[test]
fn finding_limit_error_is_identical() {
    let input = format!("{SECRET}\n").repeat(50_001);
    let expected = scan_and_redact(
        &input,
        &registry(Profile::Full),
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap_err();
    assert_eq!(expected.code(), SecretScanErrorCode::FindingLimitExceeded);
    assert_eq!(sanitize(&input).unwrap_err(), expected);
}
