//! Conformance tests for the default policy and redaction working together
//! through the public `scan` + `redact` contract, using synthetic candidates
//! in place of not-yet-implemented built-in detectors.

// Integration tests are outside `#[cfg(test)]`, so the test-only relaxation in
// `clippy.toml` does not apply; these helpers may unwrap and panic on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    Action, ByteRange, Candidate, Confidence, DefaultPolicy, DetectedFinding, Detector,
    DetectorContext, DetectorRegistry, Finding, PlaceholderContext, Policy, SecretScanErrorCode,
    Specificity, default_placeholder_formatter, redact, scan,
};

struct Fixed {
    id: &'static str,
    candidates: Vec<(&'static str, Confidence, Specificity, ByteRange)>,
}

impl Detector for Fixed {
    fn id(&self) -> &str {
        self.id
    }

    fn detect(
        &self,
        _input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, redact_secret::DetectorFailure> {
        Ok(self
            .candidates
            .iter()
            .map(|(type_name, confidence, specificity, range)| {
                Candidate::new(*type_name, *confidence, *range).with_specificity(*specificity)
            })
            .collect())
    }
}

fn registry(detector: Fixed) -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();
    registry.register(Box::new(detector)).unwrap();
    registry
}

#[test]
fn default_policy_blocks_private_keys_redacts_known_formats_and_warns_on_medium_context() {
    let input = "AAAAAAAAAA BBBBBBBBBB CCCCCCCCCC";
    let range = |s: usize, e: usize| ByteRange::new(s, e).unwrap();
    let detector = Fixed {
        id: "fixture",
        candidates: vec![
            (
                "private_key",
                Confidence::High,
                Specificity::PrivateKey,
                range(0, 10),
            ),
            (
                "github_token",
                Confidence::High,
                Specificity::Provider,
                range(11, 21),
            ),
            (
                "contextual_secret",
                Confidence::Medium,
                Specificity::Contextual,
                range(22, 32),
            ),
        ],
    };

    let findings = scan(input, &registry(detector), &DefaultPolicy).unwrap();
    let actions: Vec<(&str, Action)> = findings
        .iter()
        .map(|finding| (finding.type_name(), finding.action()))
        .collect();
    assert_eq!(
        actions,
        [
            ("private_key", Action::Block),
            ("github_token", Action::Redact),
            ("contextual_secret", Action::Warn),
        ]
    );
}

#[test]
fn scan_then_redact_round_trip_leaves_no_matched_value_in_output_or_error() {
    let input = "token=AAAAAAAAAA and note=ordinary";
    let range = ByteRange::new(6, 16).unwrap();
    let detector = Fixed {
        id: "fixture",
        candidates: vec![(
            "github_token",
            Confidence::High,
            Specificity::Provider,
            range,
        )],
    };

    let findings = scan(input, &registry(detector), &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].action(), Action::Redact);

    let output = redact(input, &findings, &default_placeholder_formatter).unwrap();
    assert_eq!(output, "token=<SECRET_1> and note=ordinary");
    assert!(!output.contains("AAAAAAAAAA"));

    // Rescanning the redacted output finds nothing further.
    let rescan_registry = registry(Fixed {
        id: "fixture",
        candidates: Vec::new(),
    });
    assert!(
        scan(&output, &rescan_registry, &DefaultPolicy)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn redact_rejects_a_caller_supplied_finding_that_overlaps_another() {
    let input = "SYNTHETIC_REVOKED_VALUE";
    let findings = [
        Finding::new(
            "finding-1",
            "synthetic_credential",
            "caller",
            Confidence::High,
            Action::Redact,
            ByteRange::new(0, 10).unwrap(),
        )
        .unwrap(),
        Finding::new(
            "finding-2",
            "synthetic_credential",
            "caller",
            Confidence::High,
            Action::Redact,
            ByteRange::new(5, 15).unwrap(),
        )
        .unwrap(),
    ];

    let error = redact(input, &findings, &default_placeholder_formatter).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidFindings);
    assert!(!error.to_string().contains(input));
}

#[test]
fn redact_rejects_a_placeholder_that_reproduces_a_short_caller_supplied_finding() {
    for input in ["x", "xy", "xyz"] {
        let findings = [Finding::new(
            "finding-1",
            "synthetic_credential",
            "caller",
            Confidence::High,
            Action::Redact,
            ByteRange::new(0, input.len()).unwrap(),
        )
        .unwrap()];
        let value = input.to_string();
        let formatter = move |_: &Finding, _: &PlaceholderContext| Ok(format!("<{value}>"));

        let error = redact(input, &findings, &formatter).unwrap_err();
        assert_eq!(
            error.code(),
            SecretScanErrorCode::InvalidPlaceholder,
            "{input}"
        );
    }
}

#[test]
fn detected_finding_from_a_caller_supplied_id_participates_in_default_policy() {
    let detected = DetectedFinding::new(
        "finding-1",
        "aws_access_key_id",
        "caller",
        Confidence::Low,
        ByteRange::new(0, 4).unwrap(),
    )
    .unwrap();
    let action = DefaultPolicy
        .evaluate(&detected, &redact_secret::PolicyContext::new(0, 1))
        .unwrap();
    assert_eq!(action, Action::Redact);
}

// --- composition: overlap resolution + policy + redaction ------------------

fn multi_registry(detectors: Vec<Box<dyn Detector>>) -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();
    for detector in detectors {
        registry.register(detector).unwrap();
    }
    registry
}

fn single_cand(
    id: &'static str,
    type_name: &'static str,
    confidence: Confidence,
    specificity: Specificity,
    range: ByteRange,
) -> Box<dyn Detector> {
    Box::new(Fixed {
        id,
        candidates: vec![(type_name, confidence, specificity, range)],
    })
}

/// A detector that reports every non-overlapping occurrence of a fixed
/// literal substring, used to prove a hidden literal cannot be found again
/// in redacted output.
struct Literal {
    id: &'static str,
    needle: String,
}

impl Detector for Literal {
    fn id(&self) -> &str {
        self.id
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, redact_secret::DetectorFailure> {
        Ok(input
            .match_indices(self.needle.as_str())
            .map(|(start, matched)| {
                Candidate::new(
                    self.id,
                    Confidence::High,
                    ByteRange::new(start, start + matched.len()).unwrap(),
                )
            })
            .collect())
    }
}

fn literal(id: &'static str, needle: String) -> Box<dyn Detector> {
    Box::new(Literal { id, needle })
}

/// Marker substrings for [`build_zone_fixture`], kept for the
/// post-redaction substring assertions in the tests below.
struct ZoneMarkers {
    z1: &'static str,
    inner2: &'static str,
    outer2: String,
    outer3: String,
    z4: &'static str,
    z5_left: &'static str,
    z5_right: &'static str,
    z6: &'static str,
}

/// Six zones, each isolating one overlap-resolution axis — specificity,
/// confidence, containment, registry order, adjacency, disjointness — joined
/// by filler text. Every marker is a unique synthetic token so the
/// substring checks in the tests below cannot collide across zones.
// One linear fixture-assembly function reads far more clearly than six
// scattered ones; the length is fixture data, not branching logic.
#[allow(clippy::too_many_lines)]
fn build_zone_fixture() -> (String, DetectorRegistry, ZoneMarkers) {
    let z1 = "SYNTHETIC_Z1_VALUE";
    let inner2 = "SYNTHETIC_Z2_INNER";
    let outer2 = format!("SYNTHETIC_Z2_OUTER_{inner2}_TAIL");
    let inner3 = "SYNTHETIC_Z3_INNER";
    let outer3 = format!("SYNTHETIC_Z3_OUTER_{inner3}_TAIL");
    let z4 = "SYNTHETIC_Z4_VALUE";
    let z5_left = "SYNTHETIC_Z5_LEFT";
    let z5_right = "SYNTHETIC_Z5_RIGHT";
    let z6 = "SYNTHETIC_Z6_VALUE";
    let input =
        format!("pre {z1} mid {outer2} mid {outer3} mid {z4} mid {z5_left}{z5_right} mid {z6} end");

    let find = |needle: &str| -> ByteRange {
        let start = input.find(needle).unwrap();
        ByteRange::new(start, start + needle.len()).unwrap()
    };
    let z1_range = find(z1);
    let outer2_range = find(&outer2);
    let inner2_range = {
        let start = outer2_range.start() + outer2.find(inner2).unwrap();
        ByteRange::new(start, start + inner2.len()).unwrap()
    };
    let outer3_range = find(&outer3);
    let inner3_range = {
        let start = outer3_range.start() + outer3.find(inner3).unwrap();
        ByteRange::new(start, start + inner3.len()).unwrap()
    };
    let z4_range = find(z4);
    let z5_left_range = find(z5_left);
    let z5_right_range =
        ByteRange::new(z5_left_range.end(), z5_left_range.end() + z5_right.len()).unwrap();
    let z6_range = find(z6);

    // Zone 1 (specificity over confidence), zone 2 (confidence over span),
    // zone 3 (containment: narrower nested span wins), zone 4 (registry
    // order), zone 5 (adjacency), zone 6 (disjoint). See module doc.
    let singles = [
        (
            "z1-entropy",
            "wide_entropy",
            Confidence::High,
            Specificity::Entropy,
            z1_range,
        ),
        (
            "z1-provider",
            // A real always-redact type name (`ALWAYS_REDACT_TYPES` in
            // `src/policy.rs`), not a synthetic label like this zone's other
            // candidates: it pins this candidate's resolved-action severity
            // to `Redact` regardless of its `Low` confidence, matching
            // `wide_entropy`'s `High`-confidence severity, so this zone
            // isolates specificity beating confidence
            // (`decision-resolve-overlap-precedence-by-resolved-action-severity`
            // ranks resolved severity before specificity) rather than
            // severity deciding it instead.
            "openai_api_key",
            Confidence::Low,
            Specificity::Provider,
            z1_range,
        ),
        (
            "z2-medium-narrow",
            "medium_narrow",
            Confidence::Medium,
            Specificity::Structural,
            inner2_range,
        ),
        (
            "z2-high-wide",
            "high_wide",
            Confidence::High,
            Specificity::Structural,
            outer2_range,
        ),
        (
            "z3-outer",
            "outer_secret",
            Confidence::High,
            Specificity::Structural,
            outer3_range,
        ),
        (
            "z3-inner",
            "inner_secret",
            Confidence::High,
            Specificity::Structural,
            inner3_range,
        ),
        (
            "z4-first",
            "first_secret",
            Confidence::High,
            Specificity::Provider,
            z4_range,
        ),
        (
            "z4-second",
            "second_secret",
            Confidence::High,
            Specificity::Provider,
            z4_range,
        ),
        (
            "z6-isolated",
            "disjoint_secret",
            Confidence::High,
            Specificity::Contextual,
            z6_range,
        ),
    ];
    let mut detectors: Vec<Box<dyn Detector>> = singles
        .into_iter()
        .map(|(id, type_name, confidence, specificity, range)| {
            single_cand(id, type_name, confidence, specificity, range)
        })
        .collect();
    detectors.push(Box::new(Fixed {
        id: "z5-adjacent",
        candidates: vec![
            (
                "adjacent_left",
                Confidence::High,
                Specificity::Provider,
                z5_left_range,
            ),
            (
                "adjacent_right",
                Confidence::High,
                Specificity::Provider,
                z5_right_range,
            ),
        ],
    }));

    let markers = ZoneMarkers {
        z1,
        inner2,
        outer2,
        outer3,
        z4,
        z5_left,
        z5_right,
        z6,
    };
    (input, multi_registry(detectors), markers)
}

/// Maps each zone's winning type name to an action, independently of which
/// overlap-resolution axis produced the winner: detection and policy stay
/// decoupled.
// `Result` is required by the `Policy`/`Fn` trait bound `scan` expects, not
// an unnecessary wrapper.
#[allow(clippy::unnecessary_wraps)]
fn zone_policy(
    finding: &DetectedFinding,
    _context: &redact_secret::PolicyContext,
) -> Result<Action, redact_secret::PolicyFailure> {
    Ok(match finding.type_name() {
        "openai_api_key" => Action::Block,
        "inner_secret" => Action::Warn,
        "first_secret" => Action::Allow,
        "high_wide" | "adjacent_left" | "adjacent_right" | "disjoint_secret" => Action::Redact,
        other => panic!("unexpected surviving finding: {other}"),
    })
}

#[test]
fn overlap_resolution_axes_feed_a_multi_outcome_policy() {
    let (input, registry, _markers) = build_zone_fixture();
    let findings = scan(&input, &registry, &zone_policy).unwrap();
    let actual: Vec<(&str, Action)> = findings
        .iter()
        .map(|finding| (finding.type_name(), finding.action()))
        .collect();
    assert_eq!(
        actual,
        [
            ("openai_api_key", Action::Block),
            ("high_wide", Action::Redact),
            ("inner_secret", Action::Warn),
            ("first_secret", Action::Allow),
            ("adjacent_left", Action::Redact),
            ("adjacent_right", Action::Redact),
            ("disjoint_secret", Action::Redact),
        ]
    );
}

#[test]
fn redact_after_overlap_resolution_hides_replaced_findings_and_resists_rescan() {
    let (input, registry, markers) = build_zone_fixture();
    let findings = scan(&input, &registry, &zone_policy).unwrap();

    let output = redact(&input, &findings, &default_placeholder_formatter).unwrap();
    let expected = format!(
        "pre <SECRET_1> mid <SECRET_2> mid {} mid {} mid <SECRET_3><SECRET_4> mid <SECRET_5> end",
        markers.outer3, markers.z4
    );
    assert_eq!(output, expected);

    // Block and redact hide their matched text; warn and allow leave it
    // exactly as detected — the action is a policy decision layered on top
    // of detection, not a property of detection itself.
    assert!(!output.contains(markers.z1));
    assert!(!output.contains(&markers.outer2));
    assert!(!output.contains(markers.inner2));
    assert!(!output.contains(markers.z5_left));
    assert!(!output.contains(markers.z5_right));
    assert!(!output.contains(markers.z6));
    assert!(output.contains(&markers.outer3));
    assert!(output.contains(markers.z4));

    // Rescanning the redacted output for the exact literals that were
    // hidden finds nothing, proving the default placeholder does not leave
    // rescannable output; the same detectors do find those literals in the
    // original input, confirming the check is meaningful.
    let hidden_literals = multi_registry(vec![
        literal("l1", markers.z1.to_string()),
        literal("l2", markers.outer2.clone()),
        literal("l5l", markers.z5_left.to_string()),
        literal("l5r", markers.z5_right.to_string()),
        literal("l6", markers.z6.to_string()),
    ]);
    assert_eq!(
        redact_secret::run_detector_pipeline(&input, &hidden_literals)
            .unwrap()
            .len(),
        5
    );
    assert!(
        redact_secret::run_detector_pipeline(&output, &hidden_literals)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn redact_rejects_a_custom_placeholder_that_reproduces_a_scan_derived_secret() {
    let input = "prefix SYNTHETIC_LEAKY_VALUE suffix";
    let value = "SYNTHETIC_LEAKY_VALUE";
    let start = input.find(value).unwrap();
    let range = ByteRange::new(start, start + value.len()).unwrap();
    let detector = Fixed {
        id: "fixture",
        candidates: vec![(
            "leaky_secret",
            Confidence::High,
            Specificity::Provider,
            range,
        )],
    };

    let findings = scan(input, &registry(detector), &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].action(), Action::Redact);

    // A misconfigured formatter that always emits the exact matched text,
    // as if it had somehow reconstructed it, must still be rejected even
    // though the finding came through the full scan pipeline (overlap
    // resolution and policy) rather than a hand-built `Finding`.
    let leaky_formatter = |_: &Finding, _: &PlaceholderContext| Ok(value.to_string());
    let error = redact(input, &findings, &leaky_formatter).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidPlaceholder);
    assert!(!error.to_string().contains(value));
}
