//! Issue #863: the `openai:admin-api-key` contract, driven through the public
//! API.
//!
//! Contract (`docs/contracts/precision/precision-contracts.json`,
//! `families.openai-token`, variant `admin`, tier T2): `sk-admin-` followed
//! by `<58|74 [A-Za-z0-9_-]>T3BlbkFJ<58|74 [A-Za-z0-9_-]>`, the same
//! marker-gated grammar as `sk-proj-`/`sk-svcacct-`. A marker-less
//! `sk-admin-` body (for example the 124-byte body in trufflehog#4698) is
//! out of `openai-token`'s contract: no source shows an admin key without
//! the marker, and a free `sk-admin-` body would need its own `sk-ant-`
//! reject list.
//!
//! Every key is assembled at runtime from an obviously synthetic label; none
//! was issued by a provider and none is derived from a real key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    ByteRange, Confidence, DefaultPolicy, DetectorContext, DetectorRegistry, Specificity, scan,
};

const MARKER: &str = "T3BlbkFJ";

/// A `len`-byte body cycling `label`, entirely inside `[A-Za-z0-9_-]`.
fn body(label: &str, len: usize) -> String {
    label.chars().cycle().take(len).collect()
}

fn admin_key(left: usize, right: usize) -> String {
    format!(
        "sk-admin-{}{MARKER}{}",
        body("SYNTHETIC_REVOKED_LEFT-", left),
        body("SYNTHETIC_REVOKED_RIGHT-", right)
    )
}

/// The marker-less 124-byte body shape from trufflehog#4698.
fn markerless_key() -> String {
    format!("sk-admin-{}", body("SYNTHETIC_REVOKED_UNMARKED-", 124))
}

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

fn openai_ranges(input: &str) -> Vec<(usize, usize)> {
    let registry = registry();
    let detector = registry
        .detectors()
        .iter()
        .find(|registered| registered.id() == "openai-token")
        .expect("openai-token is a built-in detector")
        .detector();
    detector
        .detect(input, &DetectorContext::new(input.len()))
        .unwrap()
        .iter()
        .map(|candidate| (candidate.range().start(), candidate.range().end()))
        .collect()
}

/// `(label, template)`; `{}` is the key.
const CONTEXTS: [(&str, &str); 7] = [
    ("bare", "{}"),
    ("env", "OPENAI_ADMIN_KEY={}\n"),
    ("export", "export OPENAI_ADMIN_KEY={}\n"),
    ("yaml", "openai:\n  admin_key: {}\n"),
    ("json", "{\"admin_api_key\": \"{}\"}"),
    (
        "curl",
        "curl -H \"Authorization: Bearer {}\" https://api.openai.com/v1/organization/costs",
    ),
    (
        "tool-call",
        "{\"name\":\"bash\",\"input\":{\"command\":\"export OPENAI_ADMIN_KEY={} && run\"}}",
    ),
];

fn in_context(template: &str, key: &str) -> (String, usize) {
    let start = template.find("{}").unwrap();
    (template.replacen("{}", key, 1), start)
}

#[test]
fn marker_bearing_keys_are_detected_at_every_documented_shape() {
    for (left, right) in [(58, 58), (74, 74), (58, 74), (74, 58)] {
        let key = admin_key(left, right);
        assert_eq!(key.len(), 9 + left + 8 + right);
        assert_eq!(openai_ranges(&key), vec![(0, key.len())], "{left}/{right}");
    }
    // The 58/58 shape is the 133-byte key gitleaks' admin vectors measure.
    assert_eq!(admin_key(58, 58).len(), 133);
}

#[test]
fn the_admin_finding_is_the_shared_openai_finding_at_provider_specificity() {
    let key = admin_key(58, 58);
    let findings = scan(&key, &registry(), &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector(), "openai-token");
    assert_eq!(findings[0].type_name(), "openai_api_key");
    assert_eq!(findings[0].confidence(), Confidence::High);
    assert_eq!(findings[0].range(), ByteRange::new(0, key.len()).unwrap());
    assert!(findings[0].action().replaces_text());

    let registry = registry();
    let detector = registry
        .detectors()
        .iter()
        .find(|registered| registered.id() == "openai-token")
        .unwrap()
        .detector();
    let candidates = detector
        .detect(&key, &DetectorContext::new(key.len()))
        .unwrap();
    assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
}

#[test]
fn marker_bearing_keys_are_redacted_in_every_context() {
    for (label, template) in CONTEXTS {
        for (left, right) in [(58, 58), (74, 74)] {
            let key = admin_key(left, right);
            let (input, start) = in_context(template, &key);
            let findings = scan(&input, &registry(), &DefaultPolicy).unwrap();
            let range = ByteRange::new(start, start + key.len()).unwrap();
            assert!(
                findings
                    .iter()
                    .any(|f| f.detector() == "openai-token" && f.range() == range),
                "{label} {left}/{right}: {:?}",
                findings
                    .iter()
                    .map(|f| (f.detector(), f.range()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(openai_ranges(&input), vec![(start, start + key.len())]);
        }
    }
}

#[test]
fn one_byte_short_or_long_twins_are_not_openai_findings() {
    for (left, right) in [
        (57, 58),
        (58, 57),
        (57, 57),
        (73, 74),
        (74, 73),
        (59, 58),
        (58, 59),
        (75, 74),
        (74, 75),
    ] {
        let key = admin_key(left, right);
        assert!(openai_ranges(&key).is_empty(), "{left}/{right}");
        for (label, template) in CONTEXTS {
            let (input, _) = in_context(template, &key);
            assert!(openai_ranges(&input).is_empty(), "{label} {left}/{right}");
        }
    }
}

#[test]
fn placeholders_and_mutated_markers_are_not_openai_findings() {
    let mutated = admin_key(58, 58).replace(MARKER, "T3BlbkFK");
    let lowercased = admin_key(58, 58).replace(MARKER, &MARKER.to_ascii_lowercase());
    let wrong_prefix = admin_key(58, 58).replacen("sk-admin-", "sk-admin_", 1);
    let short_prefix = admin_key(58, 58).replacen("sk-admin-", "sk-adm-", 1);
    for input in [
        "sk-admin-...".to_string(),
        "sk-admin-your-key-here".to_string(),
        "OPENAI_ADMIN_KEY=$OPENAI_ADMIN_KEY".to_string(),
        "OPENAI_ADMIN_KEY=".to_string(),
        "key_SYNTHETIC_REVOKED_PUBLIC_ID".to_string(),
        "the sk-admin- prefix identifies an admin key".to_string(),
        mutated,
        lowercased,
        wrong_prefix,
        short_prefix,
        format!("x{}", admin_key(58, 58)),
        format!("{}0", admin_key(58, 58)),
        format!("{}-tail", admin_key(74, 74)),
    ] {
        assert!(openai_ranges(&input).is_empty(), "{input}");
    }
}

/// The marker-less 124-byte body is out of `openai-token`'s contract in every
/// context, so the provider detector stays silent and never claims it as an
/// `openai_api_key`. What else the default pipeline does with the same bytes
/// is the generic layers' behavior (see the two tests below), not an `OpenAI`
/// contract.
#[test]
fn a_marker_less_admin_body_is_out_of_contract_for_the_provider_detector() {
    let key = markerless_key();
    assert_eq!(key.len(), 9 + 124);
    for (label, template) in CONTEXTS {
        let (input, _) = in_context(template, &key);
        assert!(openai_ranges(&input).is_empty(), "{label}");
        let findings = scan(&input, &registry(), &DefaultPolicy).unwrap();
        assert!(
            findings.iter().all(|f| f.detector() != "openai-token"),
            "{label}"
        );
    }
}

/// Recorded false negative: with no marker and no credential-shaped context,
/// nothing claims the value. This is the accepted cost of not admitting a
/// marker-less `sk-admin-` grammar (no source shows such a key exists).
#[test]
fn a_bare_or_unquoted_marker_less_admin_body_is_a_recorded_false_negative() {
    let key = markerless_key();
    for label in ["bare", "env", "export", "yaml", "tool-call"] {
        let template = CONTEXTS.iter().find(|(l, _)| *l == label).unwrap().1;
        let (input, _) = in_context(template, &key);
        let findings = scan(&input, &registry(), &DefaultPolicy).unwrap();
        assert!(findings.is_empty(), "{label}: {findings:?}");
    }
}

/// Where the value sits behind an authorization scheme or a quoted
/// credential-named assignment, the generic layers already redact the exact
/// value, so the marker-less gap is confined to the unquoted shapes above.
#[test]
fn a_marker_less_admin_body_in_a_bearer_or_quoted_assignment_is_still_redacted_by_generic_layers() {
    let key = markerless_key();
    for label in ["curl", "json"] {
        let template = CONTEXTS.iter().find(|(l, _)| *l == label).unwrap().1;
        let (input, start) = in_context(template, &key);
        let findings = scan(&input, &registry(), &DefaultPolicy).unwrap();
        let range = ByteRange::new(start, start + key.len()).unwrap();
        assert!(
            findings.iter().any(|f| f.range() == range),
            "{label}: {findings:?}"
        );
    }
}
