//! The deterministic synchronous pipeline: normalize, collect, validate,
//! translate, prioritize, resolve overlaps, number, then apply policy.
//!
//! Detectors scan a copy of the input with invisible code points removed
//! ([`NormalizedInput`]); every later stage, and every public range, is in
//! original-input coordinates
//! (`decision-normalize-invisible-characters-before-detection`).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::error::{SecretScanError, SecretScanErrorCode};
use crate::limits::WholeInputLimits;
use crate::normalize::NormalizedInput;
use crate::policy::default_action_for;
use crate::redact::redact_with_limits;
use crate::registry::{DetectorRegistry, RegisteredDetector};
use crate::types::{
    Action, ByteRange, Candidate, Confidence, DetectedFinding, DetectorContext, Finding,
    Obfuscation, PlaceholderFormatter, Policy, PolicyContext, ScanResult, Specificity,
    is_identifier,
};

/// Vendor-published placeholder credentials that can never be real secrets:
/// each is a provider's own documented example value, invalid against any
/// real account. Matched by exact equality against the candidate's full text
/// only, never a substring or pattern, so the carve-out cannot be used as a
/// template to hide part of a real secret.
const KNOWN_VENDOR_PLACEHOLDER_LITERALS: &[&str] = &[
    // AWS SDK/API documentation's example access key ID (IAM docs, `boto3`,
    // countless tutorials): https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    "AKIAIOSFODNN7EXAMPLE",
    // AWS's paired example secret access key, published alongside the key
    // above in the same official documentation.
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
];

/// Whether `matched` is exactly one of [`KNOWN_VENDOR_PLACEHOLDER_LITERALS`].
fn is_known_vendor_placeholder_literal(matched: &str) -> bool {
    KNOWN_VENDOR_PLACEHOLDER_LITERALS.contains(&matched)
}

/// A validated candidate with the keys overlap resolution sorts on.
struct RankedCandidate<'a> {
    type_name: &'a str,
    detector: &'a str,
    confidence: Confidence,
    specificity: Specificity,
    /// [`Action::overlap_resolution_severity`] of the action this candidate
    /// would resolve to under the crate's fixed default classification
    /// (`crate::policy::default_action_for`) — never the caller's active
    /// [`Policy`], which is not yet chosen at this stage and, for an
    /// incremental session, cannot be evaluated before a finding is final.
    /// The first, dominant priority key
    /// (`decision-resolve-overlap-precedence-by-resolved-action-severity`):
    /// a candidate that would resolve to a weaker action can never displace
    /// one that would resolve to a stricter one, regardless of specificity.
    resolved_severity: u8,
    range: ByteRange,
    obfuscation: Obfuscation,
    detector_order: usize,
    candidate_order: usize,
}

impl RankedCandidate<'_> {
    /// Conflict precedence: resolved-action severity, specificity,
    /// confidence, narrower span, registry order, then emission order. The
    /// last two keys are unique per candidate, so the ordering is total and
    /// needs no further tie breaker.
    fn priority(&self, other: &Self) -> Ordering {
        other
            .resolved_severity
            .cmp(&self.resolved_severity)
            .then_with(|| other.specificity.cmp(&self.specificity))
            .then_with(|| other.confidence.cmp(&self.confidence))
            .then_with(|| self.range.len().cmp(&other.range.len()))
            .then_with(|| self.detector_order.cmp(&other.detector_order))
            .then_with(|| self.candidate_order.cmp(&other.candidate_order))
    }
}

/// Validates `candidate` against the scan copy it was detected in, then
/// translates its range into `input`. Everything downstream ranks, accepts,
/// and redacts in original coordinates only.
fn validate_candidate<'a>(
    input: &str,
    normalized: &NormalizedInput<'_>,
    registered: &'a RegisteredDetector,
    candidate: &'a Candidate,
    detector_order: usize,
    candidate_order: usize,
) -> Result<RankedCandidate<'a>, SecretScanError> {
    let type_name = candidate.type_name();
    let scanned = normalized.text();
    let scanned_range = candidate.range();

    if !is_identifier(type_name) || !scanned_range.is_char_aligned_in(scanned) {
        return Err(SecretScanErrorCode::InvalidCandidate.into());
    }

    // A candidate whose matched text is exactly its public type or detector
    // id would let a public field mirror input; reject it as malformed.
    let matched = &scanned[scanned_range.start()..scanned_range.end()];
    if matched == type_name || matched == registered.id() {
        return Err(SecretScanErrorCode::InvalidCandidate.into());
    }

    // Removal is order-preserving, so a range aligned in the scan copy
    // translates to one aligned in the input; re-asserted because every
    // later stage slices `input` with it.
    let range = normalized
        .to_original(scanned_range)
        .filter(|range| range.is_char_aligned_in(input))
        .ok_or(SecretScanErrorCode::InvalidCandidate)?;

    // Either source claiming obfuscation is enough: a detector's own signal
    // is honored even though none currently sets one, and the pipeline's own
    // check is independent of it.
    let obfuscation = if candidate.obfuscation() == Obfuscation::InvisibleCharacters
        || normalized.contains_removed_run(scanned_range)
    {
        Obfuscation::InvisibleCharacters
    } else {
        Obfuscation::None
    };

    let confidence = candidate.confidence();
    let resolved_severity = default_action_for(type_name, confidence).overlap_resolution_severity();

    Ok(RankedCandidate {
        type_name,
        detector: registered.id(),
        confidence,
        specificity: candidate.effective_specificity(),
        resolved_severity,
        range,
        obfuscation,
        detector_order,
        candidate_order,
    })
}

/// Runs every detector over the scan copy. The returned ranges index
/// `scanned`, not the original input.
fn collect_candidates(
    scanned: &str,
    registry: &DetectorRegistry,
) -> Result<Vec<Vec<Candidate>>, SecretScanError> {
    let context = DetectorContext::new(scanned.len());
    registry
        .detectors()
        .iter()
        .map(|registered| {
            registered
                .detector()
                .detect(scanned, &context)
                .map_err(|_| SecretScanErrorCode::DetectorFailure.into())
        })
        .collect()
}

/// Greedy acceptance over an ordered map of disjoint accepted spans keyed by
/// start offset. Because accepted spans are disjoint, the span with the
/// greatest start below `candidate.end()` is the only one that can overlap.
fn try_accept(accepted: &mut BTreeMap<usize, usize>, range: ByteRange) -> bool {
    if let Some((_, &end)) = accepted.range(..range.end()).next_back()
        && end > range.start()
    {
        return false;
    }
    accepted.insert(range.start(), range.end());
    true
}

/// Runs every registered detector over `input`, validates each candidate,
/// resolves overlaps with the documented precedence, and returns the
/// surviving findings ordered by input offset with ids `finding-1`,
/// `finding-2`, and so on.
///
/// A candidate whose full matched text exactly equals a documented
/// vendor-placeholder literal (an internal, fixed exemption list) is
/// dropped before validation, regardless of which detector proposed it.
///
/// Identical input and registry always produce identical findings.
///
/// # Errors
///
/// - [`SecretScanErrorCode::DetectorFailure`] when a detector fails.
/// - [`SecretScanErrorCode::InvalidCandidate`] when a candidate has a
///   malformed type, a range outside the input or off a character
///   boundary, or a range whose text equals its type or detector id.
///
/// Errors never carry input or candidate content.
pub fn run_detector_pipeline(
    input: &str,
    registry: &DetectorRegistry,
) -> Result<Vec<DetectedFinding>, SecretScanError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let normalized = NormalizedInput::new(input);
    let scanned = normalized.text();
    if scanned.is_empty() {
        return Ok(Vec::new());
    }

    let per_detector = collect_candidates(scanned, registry)?;

    let mut ranked: Vec<RankedCandidate<'_>> = Vec::new();
    for ((detector_order, registered), candidates) in
        registry.detectors().iter().enumerate().zip(&per_detector)
    {
        for (candidate_order, candidate) in candidates.iter().enumerate() {
            let range = candidate.range();
            if range.is_char_aligned_in(scanned)
                && is_known_vendor_placeholder_literal(&scanned[range.start()..range.end()])
            {
                continue;
            }
            ranked.push(validate_candidate(
                input,
                &normalized,
                registered,
                candidate,
                detector_order,
                candidate_order,
            )?);
        }
    }

    ranked.sort_unstable_by(RankedCandidate::priority);

    let mut accepted_spans = BTreeMap::new();
    let mut accepted: Vec<RankedCandidate<'_>> = ranked
        .into_iter()
        .filter(|candidate| try_accept(&mut accepted_spans, candidate.range))
        .collect();

    // Accepted spans are disjoint, so start offsets are unique.
    accepted.sort_unstable_by_key(|candidate| candidate.range.start());

    accepted
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| {
            Ok(DetectedFinding::new(
                format!("finding-{}", index + 1),
                candidate.type_name,
                candidate.detector,
                candidate.confidence,
                candidate.range,
            )?
            .with_obfuscation(candidate.obfuscation))
        })
        .collect()
}

/// Runs the detector pipeline and evaluates `policy` once per finding.
///
/// Findings are ordered by their offset in `input` and their ranges are
/// UTF-8 byte offsets into `input` ([`crate::RANGE_UNIT`]).
///
/// # Examples
///
/// ```
/// use redact_secret::{Action, DefaultPolicy, DetectorRegistry, scan};
///
/// let registry = DetectorRegistry::with_built_in([])?;
/// let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
///
/// let findings = scan(input, &registry, &DefaultPolicy)?;
///
/// assert_eq!(findings.len(), 1);
/// assert_eq!(findings[0].id(), "finding-1");
/// assert_eq!(findings[0].action(), Action::Redact);
/// assert_eq!(findings[0].detector(), "github-token");
/// assert_eq!(findings[0].range().start(), 8);
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
///
/// # Errors
///
/// Every [`run_detector_pipeline`] error, plus
/// [`SecretScanErrorCode::PolicyFailure`] when the policy fails,
/// [`SecretScanErrorCode::InputLimitExceeded`] when `input` exceeds the
/// default [`WholeInputLimits::max_input_bytes`], and
/// [`SecretScanErrorCode::FindingLimitExceeded`] when the accepted finding
/// count exceeds the default [`WholeInputLimits::max_findings`]. See
/// [`scan_with_limits`] to use a different limit set.
pub fn scan(
    input: &str,
    registry: &DetectorRegistry,
    policy: &dyn Policy,
) -> Result<Vec<Finding>, SecretScanError> {
    scan_with_limits(input, registry, policy, &WholeInputLimits::default())
}

/// Same as [`scan`], against `limits` instead of the default
/// [`WholeInputLimits`].
///
/// # Errors
///
/// Every [`scan`] error, checked against `limits` instead of the default.
pub fn scan_with_limits(
    input: &str,
    registry: &DetectorRegistry,
    policy: &dyn Policy,
    limits: &WholeInputLimits,
) -> Result<Vec<Finding>, SecretScanError> {
    limits.check_input(input)?;
    let detected = run_detector_pipeline(input, registry)?;
    limits.check_findings(detected.len())?;
    let finding_count = detected.len();
    detected
        .into_iter()
        .enumerate()
        .map(|(finding_index, finding)| {
            let context = PolicyContext::new(finding_index, finding_count);
            let action: Action = policy
                .evaluate(&finding, &context)
                .map_err(|_| SecretScanError::new(SecretScanErrorCode::PolicyFailure))?;
            Ok(finding.with_action(action))
        })
        .collect()
}

/// Scans `input` and redacts it in one call, returning the sanitized text
/// and the findings that produced it.
///
/// Equivalent to [`scan`] followed by [`redact`](crate::redact) with the
/// same arguments, and identical to that pair for every input: this function
/// exists so a caller that needs both does not have to keep the two in step.
///
/// The returned findings carry UTF-8 byte offsets into `input`, not into
/// [`ScanResult::text`]; see [`ScanResult`].
///
/// # Examples
///
/// ```
/// use redact_secret::{
///     DefaultPolicy, DetectorRegistry, default_placeholder_formatter, scan_and_redact,
/// };
///
/// let registry = DetectorRegistry::with_built_in([])?;
/// let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000 trailing";
///
/// let result = scan_and_redact(input, &registry, &DefaultPolicy, &default_placeholder_formatter)?;
///
/// assert_eq!(result.text(), "API_KEY=<SECRET_1> trailing");
/// assert_eq!(result.findings().len(), 1);
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
///
/// # Errors
///
/// Every [`scan`] error, plus every [`redact`](crate::redact) error when the
/// formatter fails or returns an invalid placeholder. Errors never carry
/// input, a matched value, or a placeholder.
pub fn scan_and_redact(
    input: &str,
    registry: &DetectorRegistry,
    policy: &dyn Policy,
    formatter: &dyn PlaceholderFormatter,
) -> Result<ScanResult, SecretScanError> {
    scan_and_redact_with_limits(
        input,
        registry,
        policy,
        formatter,
        &WholeInputLimits::default(),
    )
}

/// Same as [`scan_and_redact`], against `limits` instead of the default
/// [`WholeInputLimits`].
///
/// Equivalent to [`scan_with_limits`] followed by
/// [`redact_with_limits`](crate::redact_with_limits) with the same
/// `limits`.
///
/// # Errors
///
/// Every [`scan_and_redact`] error, checked against `limits` instead of the
/// default.
pub fn scan_and_redact_with_limits(
    input: &str,
    registry: &DetectorRegistry,
    policy: &dyn Policy,
    formatter: &dyn PlaceholderFormatter,
    limits: &WholeInputLimits,
) -> Result<ScanResult, SecretScanError> {
    let findings = scan_with_limits(input, registry, policy, limits)?;
    let text = redact_with_limits(input, &findings, formatter, limits)?;
    Ok(ScanResult::new(text, findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_accept_keeps_disjoint_spans_only() {
        let mut spans = BTreeMap::new();
        let range = |s, e| ByteRange::new(s, e).unwrap();
        assert!(try_accept(&mut spans, range(10, 20)));
        assert!(try_accept(&mut spans, range(30, 40)));
        assert!(!try_accept(&mut spans, range(15, 35)));
        assert!(!try_accept(&mut spans, range(5, 11)));
        assert!(!try_accept(&mut spans, range(19, 25)));
        assert!(!try_accept(&mut spans, range(0, 100)));
        assert!(!try_accept(&mut spans, range(12, 13)));
        assert!(try_accept(&mut spans, range(20, 30)));
        assert!(try_accept(&mut spans, range(0, 10)));
        assert!(try_accept(&mut spans, range(40, 41)));
        assert_eq!(spans.len(), 5);
    }

    fn built_in_registry() -> DetectorRegistry {
        DetectorRegistry::with_built_in([]).unwrap()
    }

    #[test]
    fn the_documented_aws_access_key_literal_is_never_a_finding() {
        let registry = built_in_registry();
        assert_eq!(
            run_detector_pipeline("AKIAIOSFODNN7EXAMPLE", &registry).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn the_documented_aws_access_key_literal_is_never_a_finding_when_embedded() {
        let registry = built_in_registry();
        assert_eq!(
            run_detector_pipeline("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", &registry).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn the_documented_aws_secret_access_key_literal_is_never_a_finding() {
        let registry = built_in_registry();
        let input = "secret=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"";
        assert_eq!(run_detector_pipeline(input, &registry).unwrap(), Vec::new());
    }

    #[test]
    fn a_near_miss_of_the_documented_access_key_literal_is_still_detected() {
        // Last character changed: same shape, not the exempted literal — the
        // carve-out is an exact match, not a prefix or substring one.
        let registry = built_in_registry();
        let findings = run_detector_pipeline("AKIAIOSFODNN7EXAMPLF", &registry).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].type_name(), "aws_access_key_id");
    }

    #[test]
    fn a_removed_code_point_strictly_inside_the_range_reports_obfuscation() {
        let registry = built_in_registry();
        let input = "token: ghp_SYNTHETIC\u{200c}REVOKED00000000000000000000\n";
        let findings = run_detector_pipeline(input, &registry).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].obfuscation(), Obfuscation::InvisibleCharacters);
    }

    #[test]
    fn a_clean_finding_reports_no_obfuscation() {
        let registry = built_in_registry();
        let input = "token: ghp_SYNTHETICREVOKED00000000000000000000\n";
        let findings = run_detector_pipeline(input, &registry).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].obfuscation(), Obfuscation::None);
    }

    #[test]
    fn a_removed_code_point_adjacent_to_the_range_does_not_report_obfuscation() {
        // The ZWSP sits inside the assignment keyword, not the reported
        // value range: adjacency alone does not count.
        let registry = built_in_registry();
        let input = "api\u{200b}_key = SYNTHETIC_REVOKED_VALUE_1234\n";
        let findings = run_detector_pipeline(input, &registry).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].obfuscation(), Obfuscation::None);
    }

    #[test]
    fn a_near_miss_of_the_documented_secret_key_literal_is_still_detected() {
        let registry = built_in_registry();
        let input = "secret=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEZ\"";
        let findings = run_detector_pipeline(input, &registry).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].type_name(), "contextual_secret");
    }
}
