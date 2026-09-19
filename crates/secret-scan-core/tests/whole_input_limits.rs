//! `WholeInputLimits`: the default whole-input bound, its opt-out, and
//! diagnostic identity (`decision-bound-whole-input-operations-by-default`).
//!
//! Every input is synthetic; no test embeds a credential-shaped value.

// Integration tests are outside `#[cfg(test)]`, so the test-only relaxation in
// `clippy.toml` does not apply; these helpers may unwrap and panic on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    Action, ByteRange, Candidate, Confidence, DefaultPolicy, Detector, DetectorContext,
    DetectorFailure, DetectorRegistry, Finding, SecretScanErrorCode, Specificity, WholeInputLimits,
    default_placeholder_formatter, redact, redact_with_limits, scan, scan_and_redact,
    scan_and_redact_with_limits, scan_with_limits,
};

const FIXTURE: &str = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

/// A detector that emits one fixed, non-overlapping candidate per
/// three-byte slot in `input`, so a caller can size the finding count of a
/// small input exactly.
struct DenseFindings {
    count: usize,
}

impl Detector for DenseFindings {
    fn id(&self) -> &'static str {
        "dense-findings-test-detector"
    }

    fn detect(
        &self,
        _input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok((0..self.count)
            .map(|index| {
                let start = index * 3;
                Candidate::new(
                    "dense_finding",
                    Confidence::High,
                    ByteRange::new(start, start + 3).unwrap(),
                )
                .with_specificity(Specificity::Contextual)
            })
            .collect())
    }
}

/// A registry whose one detector emits exactly `count` disjoint candidates
/// over an input sized to fit them.
fn dense_registry_and_input(count: usize) -> (DetectorRegistry, String) {
    let mut registry = DetectorRegistry::new();
    registry
        .register(Box::new(DenseFindings { count }))
        .unwrap();
    (registry, "x".repeat(count * 3))
}

fn findings_for(input: &str, registry: &DetectorRegistry) -> Vec<Finding> {
    scan(input, registry, &DefaultPolicy).unwrap()
}

// ---------------------------------------------------------------------------
// byte bound
// ---------------------------------------------------------------------------

#[test]
fn an_input_exactly_at_the_byte_bound_is_accepted() {
    let limits = WholeInputLimits::new(FIXTURE.len(), 10).unwrap();
    assert!(scan_with_limits(FIXTURE, &registry(), &DefaultPolicy, &limits).is_ok());
}

#[test]
fn an_input_one_byte_over_the_byte_bound_is_rejected_with_input_limit_exceeded() {
    let limits = WholeInputLimits::new(FIXTURE.len() - 1, 10).unwrap();
    let error = scan_with_limits(FIXTURE, &registry(), &DefaultPolicy, &limits).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InputLimitExceeded);

    let error =
        redact_with_limits(FIXTURE, &[], &default_placeholder_formatter, &limits).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InputLimitExceeded);

    let error = scan_and_redact_with_limits(
        FIXTURE,
        &registry(),
        &DefaultPolicy,
        &default_placeholder_formatter,
        &limits,
    )
    .unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InputLimitExceeded);
}

// ---------------------------------------------------------------------------
// finding-count bound
// ---------------------------------------------------------------------------

#[test]
fn a_finding_count_exactly_at_the_bound_is_accepted() {
    let (registry, input) = dense_registry_and_input(10);
    let limits = WholeInputLimits::new(input.len(), 10).unwrap();
    let findings = scan_with_limits(&input, &registry, &DefaultPolicy, &limits).unwrap();
    assert_eq!(findings.len(), 10);
}

#[test]
fn a_finding_count_one_over_the_bound_is_rejected_with_finding_limit_exceeded() {
    let (registry, input) = dense_registry_and_input(11);
    let limits = WholeInputLimits::new(input.len(), 10).unwrap();
    let error = scan_with_limits(&input, &registry, &DefaultPolicy, &limits).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::FindingLimitExceeded);

    let error = scan_and_redact_with_limits(
        &input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
        &limits,
    )
    .unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::FindingLimitExceeded);
}

#[test]
fn redact_with_limits_independently_enforces_the_finding_bound_on_externally_supplied_findings() {
    // 11 findings, produced with a generous limit, then handed straight to
    // `redact_with_limits` under a limit of 10 — no `scan_with_limits` call
    // is involved, proving the check does not depend on having come from
    // `scan`.
    let (registry, input) = dense_registry_and_input(11);
    let generous = WholeInputLimits::new(input.len(), 100).unwrap();
    let findings = scan_with_limits(&input, &registry, &DefaultPolicy, &generous).unwrap();
    assert_eq!(findings.len(), 11);

    let strict = WholeInputLimits::new(input.len(), 10).unwrap();
    let error =
        redact_with_limits(&input, &findings, &default_placeholder_formatter, &strict).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::FindingLimitExceeded);
}

// ---------------------------------------------------------------------------
// `WholeInputLimits::new` validation
// ---------------------------------------------------------------------------

#[test]
fn new_rejects_a_zero_max_input_bytes() {
    assert_eq!(
        WholeInputLimits::new(0, 10).unwrap_err().code(),
        SecretScanErrorCode::InvalidLimits
    );
}

#[test]
fn new_rejects_a_zero_max_findings() {
    assert_eq!(
        WholeInputLimits::new(10, 0).unwrap_err().code(),
        SecretScanErrorCode::InvalidLimits
    );
}

// ---------------------------------------------------------------------------
// the plain (default-limited) functions still behave as before for
// ordinary input
// ---------------------------------------------------------------------------

#[test]
fn ordinary_input_is_unaffected_by_the_default_bound() {
    let registry = registry();
    let findings = findings_for(FIXTURE, &registry);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].action(), Action::Redact);

    let text = redact(FIXTURE, &findings, &default_placeholder_formatter).unwrap();
    assert_eq!(text, "API_KEY=<SECRET_1>");

    let result = scan_and_redact(
        FIXTURE,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();
    assert_eq!(result.text(), text);
}

// ---------------------------------------------------------------------------
// diagnostic identity
// ---------------------------------------------------------------------------

#[test]
fn the_new_and_broadened_codes_carry_their_fixed_wire_identity() {
    assert_eq!(
        SecretScanErrorCode::FindingLimitExceeded.as_str(),
        "FINDING_LIMIT_EXCEEDED"
    );
    assert_eq!(
        SecretScanErrorCode::FindingLimitExceeded.message(),
        "Secret scan finding limit exceeded."
    );
    assert_eq!(
        SecretScanErrorCode::InputLimitExceeded.as_str(),
        "INPUT_LIMIT_EXCEEDED"
    );
    assert_eq!(
        SecretScanErrorCode::InputLimitExceeded.message(),
        "Secret scan input limit exceeded."
    );
    assert_eq!(
        SecretScanErrorCode::InvalidLimits.message(),
        "Secret scan limits are invalid."
    );
}
