//! The deterministic synchronous pipeline: normalize, collect, validate,
//! translate, prioritize, resolve overlaps, number, then apply policy.
//!
//! Detectors scan a copy of the input with invisible code points removed
//! ([`NormalizedInput`]); every later stage, and every public range, is in
//! original-input coordinates
//! (`decision-normalize-invisible-characters-before-detection`).

use std::borrow::Cow;
use std::cmp::Ordering;

use crate::detectors::ScanScope;
use crate::error::{DetectorFailure, SecretScanError, SecretScanErrorCode};
use crate::evidence::shadow::ShadowComparison;
use crate::limits::WholeInputLimits;
use crate::normalize::NormalizedInput;
use crate::pii::is_reserved_detector_id;
use crate::policy::DefaultPolicy;
use crate::policy::default_action_for;
use crate::redact::default_placeholder_formatter;
use crate::redact::redact_with_limits;
use crate::registry::{DetectorEntry, DetectorRegistry, DetectorSet, Profile};
use crate::types::{
    Action, ByteRange, Candidate, Confidence, DetectedFinding, Detector, DetectorContext, Finding,
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
pub(crate) fn is_known_vendor_placeholder_literal(matched: &str) -> bool {
    KNOWN_VENDOR_PLACEHOLDER_LITERALS.contains(&matched)
}

/// A validated candidate with the keys overlap resolution sorts on.
#[cfg_attr(test, derive(Clone))]
struct RankedCandidate<'a> {
    type_name: &'a Cow<'static, str>,
    detector: &'a Cow<'static, str>,
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
    /// Emission order among this detector's candidates in the same unit
    /// ([`detect_units`]); for a single unit, the index in the detector's
    /// output.
    candidate_order: usize,
    /// Index in the detector's output for the whole call, which the shadow
    /// comparison uses to find the candidate again.
    emission_index: usize,
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
    registered: &DetectorEntry<'a>,
    candidate: &'a Candidate,
    detector_order: usize,
    candidate_order: usize,
    emission_index: usize,
) -> Result<RankedCandidate<'a>, SecretScanError> {
    let type_name_cow = candidate.type_name_cow();
    let type_name = candidate.type_name();
    let scanned = normalized.text();
    let scanned_range = candidate.range();

    if !is_identifier(type_name) || !scanned_range.is_char_aligned_in(scanned) {
        return Err(SecretScanErrorCode::InvalidCandidate.into());
    }

    // A candidate whose matched text is exactly its public type or detector
    // id would let a public field mirror input; reject it as malformed.
    let matched = &scanned[scanned_range.start()..scanned_range.end()];
    if matched == type_name || *registered.id == matched {
        return Err(SecretScanErrorCode::InvalidCandidate.into());
    }

    // Removal is order-preserving, so a range aligned in the scan copy
    // translates to one aligned in the input; re-asserted because every
    // later stage slices `input` with it.
    let (range, contains_removed_run) = normalized
        .translate(scanned_range)
        .filter(|(range, _)| range.is_char_aligned_in(input))
        .ok_or(SecretScanErrorCode::InvalidCandidate)?;

    // Either source claiming obfuscation is enough: a detector's own signal
    // is honored even though none currently sets one, and the pipeline's own
    // check is independent of it.
    let obfuscation =
        if candidate.obfuscation() == Obfuscation::InvisibleCharacters || contains_removed_run {
            Obfuscation::InvisibleCharacters
        } else {
            Obfuscation::None
        };

    let confidence = candidate.confidence();
    let resolved_severity = default_action_for(type_name, confidence).overlap_resolution_severity();

    Ok(RankedCandidate {
        type_name: type_name_cow,
        detector: registered.id,
        confidence,
        specificity: candidate.effective_specificity(),
        resolved_severity,
        range,
        obfuscation,
        detector_order,
        candidate_order,
        emission_index,
    })
}

/// Runs every detector over the scan copy. The returned ranges index
/// `scanned`, not the original input.
///
/// `boundaries` are the scan-copy offsets between incremental units
/// ([`detect_units`]). The PII detector runs on each unit separately, as it
/// did when every unit was scanned alone: its context arbitration compares
/// every candidate with every other and locates each one's line from the
/// start of its input, so over a batch of units its cost would grow with the
/// batch rather than with each unit (issue #985).
///
/// A built-in detector that declared literals (issue #983) is skipped when
/// none of them occurs in the scan copy: it would have returned no
/// candidates. One pass of the registry's compiled [`LiteralMatcher`]
/// (issue #1057) finds exactly which declaring detectors have a literal in
/// the copy. A skipped detector still gets its empty list, so the lists
/// stay aligned with registration order. The pass covers the whole batch,
/// so a literal absent from it is absent from every unit. Debug builds run
/// the skipped detector anyway and assert that it proposes nothing, so
/// every test that scans also checks the declarations.
///
/// The detectors run inside a [`ScanScope`] over `scanned`, which lets a
/// ruleset detector rule its prefix out from byte pairs shared by every
/// ruleset detector of the call.
///
/// [`LiteralMatcher`]: crate::detectors::LiteralMatcher
fn collect_candidates<R: DetectorSet + ?Sized>(
    scanned: &str,
    registry: &R,
    boundaries: &[usize],
) -> Result<Vec<Vec<Candidate>>, SecretScanError> {
    let context = DetectorContext::new(scanned.len());
    // Sized once up front: collecting through `Result` loses the iterator's
    // size hint, so the list grew by doubling on every call, and an
    // incremental session makes one call per closed line (issue #950).
    let mut per_detector = Vec::with_capacity(registry.detector_count());
    let present = registry
        .compiled_prefilter()
        .map(|matcher| matcher.present(scanned.as_bytes()));
    let _scope = ScanScope::enter(scanned);
    for (position, registered) in registry.detector_entries().enumerate() {
        if registered.declares_literals
            && present
                .as_ref()
                .is_some_and(|present| !present.contains(position))
        {
            #[cfg(debug_assertions)]
            assert_skip_is_exact(scanned, context, registered);
            per_detector.push(Vec::new());
            continue;
        }
        let detector = registered.detector;
        let candidates = if boundaries.is_empty() || !is_reserved_detector_id(registered.id) {
            detector.detect(scanned, &context)
        } else {
            detect_each_unit(detector, scanned, boundaries)
        };
        per_detector.push(
            candidates.map_err(|_| SecretScanError::from(SecretScanErrorCode::DetectorFailure))?,
        );
    }
    Ok(per_detector)
}

/// Debug-build check for [`collect_candidates`]'s prefilter: a detector it
/// skipped must return no candidates and no error on the same input. A
/// failure means the detector's declared literals miss one of its
/// emission paths.
#[cfg(debug_assertions)]
fn assert_skip_is_exact(scanned: &str, context: DetectorContext, registered: DetectorEntry<'_>) {
    let skipped = registered.detector.detect(scanned, &context);
    assert!(
        skipped.as_ref().is_ok_and(Vec::is_empty),
        "prefilter skipped `{}`, which proposes candidates on this input: \
         its declared literals miss an emission path",
        registered.id
    );
}

/// Runs `detector` on every unit of `scanned` between `boundaries` alone and
/// returns the candidates in unit order, with ranges indexing `scanned`.
fn detect_each_unit(
    detector: &dyn Detector,
    scanned: &str,
    boundaries: &[usize],
) -> Result<Vec<Candidate>, DetectorFailure> {
    let mut candidates = Vec::new();
    let mut begin = 0;
    for end in boundaries.iter().copied().chain([scanned.len()]) {
        let unit = &scanned[begin..end];
        // A unit alone with an empty scan copy is never scanned.
        if !unit.is_empty() {
            for candidate in detector.detect(unit, &DetectorContext::new(unit.len()))? {
                candidates.push(candidate.shifted(begin).ok_or(DetectorFailure)?);
            }
        }
        begin = end;
    }
    Ok(candidates)
}

/// This candidate's rank within [`Specificity`], `0` for [`Specificity::Entropy`]
/// through `4` for [`Specificity::PrivateKey`] — written out rather than cast,
/// so a new variant fails to compile here instead of silently taking on
/// whatever discriminant `#[derive]` would assign it.
const fn specificity_rank(specificity: Specificity) -> u32 {
    match specificity {
        Specificity::Entropy => 0,
        Specificity::Contextual => 1,
        Specificity::Structural => 2,
        Specificity::Provider => 3,
        Specificity::PrivateKey => 4,
    }
}

/// This candidate's rank within [`Confidence`], `0` for [`Confidence::Low`]
/// through `2` for [`Confidence::High`].
const fn confidence_rank(confidence: Confidence) -> u32 {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

/// A candidate's contribution to a disjoint selection's total weight: every
/// key [`RankedCandidate::priority`] compares on, re-based so that a larger
/// value is always the better one and the fields sit in the same dominance
/// order (declaration order controls `#[derive(Ord)]`, most significant
/// first), so summing this across a selection and comparing sums
/// lexicographically reproduces `priority`'s pairwise order whenever exactly
/// one candidate can occupy a span, and extends it to "which disjoint
/// combination carries more total evidence" whenever more than one can.
///
/// Lexicographic order over vectors is compatible with component-wise
/// addition (`a > b` implies `a + c > b + c`, since addition is applied
/// independently to each field and the first field where `a` and `b` differ
/// is unaffected by `c`), which is the one property the weighted-interval-
/// scheduling optimality proof needs from a scalar weight. That proof
/// therefore carries over unchanged to this vector weight.
///
/// `severity`, `specificity`, and `confidence` are each `base.pow(rank)`
/// rather than a bare rank, where `base` is one more than the pipeline's own
/// candidate count for this call (`select_optimal_disjoint_set`'s `n + 1`).
/// A bare linear rank would let enough weaker candidates outvote one
/// stronger one purely by count — for example two `Warn`-severity
/// candidates (rank 1 each, summing to 2) outranking one `Redact`-severity
/// candidate (rank 2) despite `Redact` being the strictly stricter action
/// (`decision-resolve-overlap-precedence-by-resolved-action-severity`), even
/// when the `Redact` candidate's span is not fully covered by the two
/// weaker ones, which would leave part of it unflagged entirely rather than
/// merely un-redacted. With `base > n`, no combination of at most `n`
/// candidates at a lower rank can ever sum past one candidate at the next
/// rank up (their sum is at most `n * base^(rank-1) < base * base^(rank-1)
/// = base^rank`), so each of these three tiers behaves as true dominance —
/// exactly reproducing today's "never displace a stricter one" rule
/// (`ARCHITECTURE.md`'s overlap-resolution section) — while still letting
/// several candidates that *tie* on a tier out-total a single one there,
/// which is the actual "more total evidence" case this issue asks for.
/// `narrowness` and the two order fields stay linear: unlike the three
/// tiers above, more matched, better-registered candidates covering more of
/// the input is exactly the improvement wanted, with no dominance to
/// protect.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
struct EvidenceWeight {
    severity: u128,
    specificity: u128,
    confidence: u128,
    narrowness: u128,
    detector_priority: u128,
    candidate_priority: u128,
}

impl EvidenceWeight {
    /// Exceeds any detector-registry size or per-detector candidate count
    /// reachable in memory, so subtracting an order from it never underflows.
    const ORDER_CAP: u128 = u32::MAX as u128;
    /// Exceeds any candidate span length a `&str` can hold, so subtracting a
    /// length from it never underflows.
    const WIDTH_CAP: u128 = u64::MAX as u128;

    /// `base` is `select_optimal_disjoint_set`'s candidate count plus one;
    /// see the dominance argument on the type itself. `saturating_pow`
    /// leaves dominance intact rather than wrapping if a pathological
    /// candidate count and rank ever pushed the true value past `u128`,
    /// which the tiny exponents here (specificity's rank 4 is the largest)
    /// keep out of reach for any candidate count this pipeline could hold
    /// in memory.
    fn of(candidate: &RankedCandidate<'_>, base: u128) -> Self {
        Self {
            severity: base.saturating_pow(u32::from(candidate.resolved_severity)),
            specificity: base.saturating_pow(specificity_rank(candidate.specificity)),
            confidence: base.saturating_pow(confidence_rank(candidate.confidence)),
            narrowness: Self::WIDTH_CAP - candidate.range.len() as u128,
            detector_priority: Self::ORDER_CAP - candidate.detector_order as u128,
            candidate_priority: Self::ORDER_CAP - candidate.candidate_order as u128,
        }
    }

    fn plus(self, other: Self) -> Self {
        Self {
            severity: self.severity + other.severity,
            specificity: self.specificity + other.specificity,
            confidence: self.confidence + other.confidence,
            narrowness: self.narrowness + other.narrowness,
            detector_priority: self.detector_priority + other.detector_priority,
            candidate_priority: self.candidate_priority + other.candidate_priority,
        }
    }
}

/// Selects the subset of `ranked` with pairwise-disjoint ranges that
/// maximizes total [`EvidenceWeight`] — optimal weighted-interval selection,
/// replacing the previous greedy walk that could discard two or more
/// mutually disjoint candidates in favor of a single overlapping one even
/// when their combined weight was higher
/// (`decision-select-optimal-disjoint-candidates-by-total-evidence-weight`).
///
/// The classical `O(n log n)` dynamic program: sort by end offset, then for
/// each candidate in that order take `max(skip it, take it + the best total
/// among candidates that end at or before its start)`, with that
/// predecessor found by binary search over the (already end-sorted) end
/// offsets. One `O(n log n)` sort, `n` `O(log n)` predecessor searches, one
/// `O(n)` forward pass, one `O(n)` backward reconstruction — the same
/// complexity class as the previous sort-plus-`BTreeMap` walk, in `n`, the
/// pipeline's own candidate count; `run_detector_pipeline` has no separate,
/// externally imposed bound on `n` to lean on
/// (`decision-bound-whole-input-operations-by-default` deliberately leaves
/// it unbounded), so the bound is stated in `n` alone.
///
/// Determinism: the sort key below is total (no two candidates compare
/// equal — `RankedCandidate::priority`'s final two keys, `detector_order`
/// and `candidate_order`, are unique per candidate), so the sorted order,
/// and therefore every predecessor lookup and DP value, is fixed regardless
/// of the standard library's unstable-sort implementation. Where two
/// candidate subsets' total weight ties exactly, the recurrence keeps the
/// previously computed (excluding) state — a fixed rule fixed by the code,
/// not by iteration order over an unordered collection — so a rerun, and
/// every binding built on this same core, reproduce the identical selection.
fn select_optimal_disjoint_set(mut ranked: Vec<RankedCandidate<'_>>) -> Vec<RankedCandidate<'_>> {
    // Nothing to select: most closed lines of an incremental session carry
    // no candidate, and the tables below would each allocate (issue #950).
    if ranked.is_empty() {
        return ranked;
    }
    ranked.sort_unstable_by(|a, b| {
        a.range
            .end()
            .cmp(&b.range.end())
            .then_with(|| a.priority(b))
    });

    // Sorted by end, the set is pairwise disjoint exactly when each range
    // starts at or after the previous one's end. The DP then takes every
    // candidate (each weight is positive, and the best predecessor total
    // is always the one just before it), so the sorted order is its answer
    // and the four tables are not built.
    if ranked
        .windows(2)
        .all(|pair| pair[1].range.start() >= pair[0].range.end())
    {
        return ranked;
    }

    let n = ranked.len();
    // Strictly exceeds `n`, the number of candidates that could ever be
    // summed at one dominance tier; see `EvidenceWeight`'s doc comment. It
    // stays the *whole set's* count for every component below: a smaller base
    // would change which tier dominates and so which subset wins.
    let base = n as u128 + 1;

    // Independent components (issue #1135). Sorted by end, a prefix `..=i` is
    // closed when no later candidate starts before `ranked[i]` ends, because
    // every earlier candidate ends no later than `ranked[i]` does. A component
    // never conflicts with another, the total weight is the sum of the
    // components' totals, and the recurrence's comparisons are unchanged by
    // the constant the earlier components add to both sides, so solving each
    // one alone yields the whole-set selection, ties included. A candidate
    // alone in its component is always taken (its weight is positive and
    // nothing conflicts with it), exactly as the disjoint fast path above.
    //
    // One backward pass fills `ends` (as the unsplit DP did) and finds the
    // closing points from the running minimum start of the later candidates;
    // each component is solved the moment it closes, in reverse order, which
    // is immaterial because components do not interact. A set with no closing
    // point is one component: the unsplit DP, with the same tables.
    let mut ends = vec![0_usize; n];
    let mut selected_mask = vec![false; n];
    let mut workspace = DpWorkspace::default();
    let mut component_end = n;
    let mut min_later_start = usize::MAX;
    for (i, candidate) in ranked.iter().enumerate().rev() {
        // `ranked[i + 1..component_end]` is complete when this candidate ends
        // before any later one starts.
        if candidate.range.end() <= min_later_start && i + 1 < component_end {
            workspace.solve(
                &ranked[i + 1..component_end],
                &ends[i + 1..component_end],
                base,
                &mut selected_mask[i + 1..component_end],
            );
            component_end = i + 1;
        }
        ends[i] = candidate.range.end();
        min_later_start = min_later_start.min(candidate.range.start());
    }
    workspace.solve(
        &ranked[..component_end],
        &ends[..component_end],
        base,
        &mut selected_mask[..component_end],
    );

    ranked
        .into_iter()
        .zip(selected_mask)
        .filter_map(|(candidate, selected)| selected.then_some(candidate))
        .collect()
}

/// Dynamic-program tables reused across the components of one call, so a set
/// with many small overlapping clusters allocates them once, not per cluster.
#[derive(Default)]
struct DpWorkspace {
    totals: Vec<EvidenceWeight>,
    include: Vec<bool>,
}

impl DpWorkspace {
    /// Marks in `mask` the candidates the weighted-interval recurrence selects
    /// from `component`, which is sorted by end; `ends` and `mask` are parallel
    /// to it. `base` is the whole set's, not the component's. A one-candidate
    /// component is always selected without building any table.
    fn solve(
        &mut self,
        component: &[RankedCandidate<'_>],
        ends: &[usize],
        base: u128,
        mask: &mut [bool],
    ) {
        if component.len() <= 1 {
            mask.fill(true);
            return;
        }
        self.totals.clear();
        self.totals.reserve(component.len() + 1);
        self.totals.push(EvidenceWeight::default());
        self.include.clear();
        self.include.reserve(component.len());

        for (i, candidate) in component.iter().enumerate() {
            let pred = ends[..i].partition_point(|&end| end <= candidate.range.start());
            let with_candidate = EvidenceWeight::of(candidate, base).plus(self.totals[pred]);
            let without_candidate = self.totals[i];
            if with_candidate > without_candidate {
                self.include.push(true);
                self.totals.push(with_candidate);
            } else {
                self.include.push(false);
                self.totals.push(without_candidate);
            }
        }

        let mut i = component.len();
        while i > 0 {
            if self.include[i - 1] {
                mask[i - 1] = true;
                let start = component[i - 1].range.start();
                i = ends[..i - 1].partition_point(|&end| end <= start);
            } else {
                i -= 1;
            }
        }
    }
}

/// Runs every registered detector over `input`, validates each candidate,
/// resolves overlaps with the documented precedence, and returns the
/// surviving findings ordered by input offset with ids `finding-1`,
/// `finding-2`, and so on.
///
/// Detectors run over a scan copy of `input` with invisible code points
/// removed; every returned range indexes `input` itself.
///
/// A candidate whose full matched text exactly equals a documented
/// vendor-placeholder literal (an internal, fixed exemption list) is
/// dropped before validation, regardless of which detector proposed it.
/// There is no context-based exemption for `google-api-key`'s `AIza` shape:
/// a key inside a Firebase Web SDK client-config object is reported like
/// any other (#749, which reversed #520's B3a exemption).
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
    detect(input, registry, None)
}

/// [`run_detector_pipeline`], optionally recording the non-enforcing shadow
/// comparison of every selected candidate into `shadow`
/// (`decision-freeze-the-shadow-evidence-score-and-confidence-contract`,
/// issue #771).
///
/// Every public entry point passes `None`, so on the public path the scorer
/// never runs and the only added work is one `Option` check per call. When
/// `shadow` is `Some`, the comparisons are computed after overlap resolution,
/// from the selected candidates only, and they read the candidate and its
/// text in the scan copy; the returned findings are the same either way.
/// A candidate that loses overlap resolution is never evaluated.
pub(crate) fn detect<R: DetectorSet + ?Sized>(
    input: &str,
    registry: &R,
    shadow: Option<&mut Vec<ShadowComparison>>,
) -> Result<Vec<DetectedFinding>, SecretScanError> {
    detect_units(input, 0, registry, &[], shadow).map(Option::unwrap_or_default)
}

/// [`detect`] over `input` made of consecutive incremental units, each
/// ending at the next of `unit_ends` (ascending original offsets inside
/// `input`, each just after a line terminator; `input.len()` ends the last
/// unit and may be omitted). Issue #985.
///
/// The result equals running [`detect`] on each unit alone and
/// concatenating, apart from finding ids, provided each detector's
/// candidates inside a unit do not depend on the text of other units (the
/// per-detector audit in `docs/audits/evidence/985/`; the incremental session
/// never batches a unit the audit found a detector reading across). Three
/// things this function makes hold by construction rather than by that
/// audit:
///
/// - The PII detector runs on each unit alone ([`collect_candidates`]).
/// - A candidate's emission order, the last overlap-resolution key, is
///   counted within its unit, as a scan of that unit alone would count it.
/// - No candidate may reach a unit boundary. One that ends at or crosses
///   the end of a unit other than the last could interact with the next
///   unit's candidates or read its text, so the call returns `Ok(None)` and
///   the caller scans unit by unit instead.
///
/// With every candidate inside one unit, the optimal disjoint selection of
/// the whole call decomposes into the selection of each unit: candidates of
/// different units never overlap, the evidence weight's tiers compare the
/// same way for any base above the unit's candidate count, and every
/// earlier unit's total is a common addend.
///
/// A nonzero `lead` makes `input[..lead]`, which must end at the first of
/// `unit_ends`, a read-only unit (issue #1040): its text is scanned so a
/// detector that reads the line above a unit sees it, but none of its
/// findings are returned, and every returned range and shadow comparison is
/// relative to `input[lead..]`. The incremental session passes the already
/// released line above a batch this way instead of holding it.
pub(crate) fn detect_units<R: DetectorSet + ?Sized>(
    input: &str,
    lead: usize,
    registry: &R,
    unit_ends: &[usize],
    shadow: Option<&mut Vec<ShadowComparison>>,
) -> Result<Option<Vec<DetectedFinding>>, SecretScanError> {
    if input.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let normalized = NormalizedInput::new(input);
    let scanned = normalized.text();
    if scanned.is_empty() {
        return Ok(Some(Vec::new()));
    }

    // The boundaries between units, in scan-copy offsets. Nothing removed
    // is a line terminator, so a boundary never falls inside a removed run.
    let boundaries: Vec<usize> = unit_ends
        .iter()
        .filter(|&&end| end < input.len())
        .map(|&end| normalized.to_scanned_offset(end))
        .collect();

    let per_detector = collect_candidates(scanned, registry, &boundaries)?;

    let mut ranked: Vec<RankedCandidate<'_>> = Vec::new();
    let mut unit_counts: Vec<usize> = Vec::new();
    for ((detector_order, registered), candidates) in
        registry.detector_entries().enumerate().zip(&per_detector)
    {
        if !boundaries.is_empty() && !candidates.is_empty() {
            unit_counts.clear();
            unit_counts.resize(boundaries.len() + 1, 0);
        }
        for (emission_index, candidate) in candidates.iter().enumerate() {
            let range = candidate.range();
            let candidate_order = if boundaries.is_empty() {
                emission_index
            } else {
                let unit = boundaries.partition_point(|&boundary| boundary <= range.start());
                if boundaries.get(unit).is_some_and(|&end| range.end() >= end) {
                    return Ok(None);
                }
                let order = unit_counts[unit];
                unit_counts[unit] += 1;
                order
            };
            if candidate.rejects_invisible_normalization() && normalized.touches_removed_run(range)
            {
                continue;
            }
            if range.is_char_aligned_in(scanned)
                && is_known_vendor_placeholder_literal(&scanned[range.start()..range.end()])
            {
                continue;
            }
            ranked.push(validate_candidate(
                input,
                &normalized,
                &registered,
                candidate,
                detector_order,
                candidate_order,
                emission_index,
            )?);
        }
    }

    let mut accepted = select_optimal_disjoint_set(ranked);

    // Accepted spans are disjoint, so start offsets are unique.
    accepted.sort_unstable_by_key(|candidate| candidate.range.start());
    if lead > 0 {
        accepted.retain(|candidate| candidate.range.start() >= lead);
        for candidate in &mut accepted {
            candidate.range =
                ByteRange::new(candidate.range.start() - lead, candidate.range.end() - lead)
                    .ok_or(SecretScanErrorCode::InvalidCandidate)?;
        }
    }

    if let Some(shadow) = shadow {
        for (index, selected) in accepted.iter().enumerate() {
            let candidate = &per_detector[selected.detector_order][selected.emission_index];
            let scanned_range = candidate.range();
            shadow.push(ShadowComparison::of(
                index,
                selected.range,
                selected.detector,
                candidate,
                &scanned[scanned_range.start()..scanned_range.end()],
            ));
        }
    }

    accepted
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| {
            Ok(DetectedFinding::from_validated(
                format!("finding-{}", index + 1),
                candidate.type_name.clone(),
                candidate.detector.clone(),
                candidate.confidence,
                candidate.range,
                candidate.obfuscation,
            ))
        })
        .collect::<Result<Vec<_>, SecretScanError>>()
        .map(Some)
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
    scan_in(input, registry, policy, limits)
}

/// [`scan_with_limits`] over any detector set. The one implementation behind
/// the [`DetectorRegistry`] function and the
/// [`BuiltInRegistry`](crate::BuiltInRegistry) method, so the two cannot drift.
pub(crate) fn scan_in<R: DetectorSet + ?Sized>(
    input: &str,
    registry: &R,
    policy: &dyn Policy,
    limits: &WholeInputLimits,
) -> Result<Vec<Finding>, SecretScanError> {
    let detected = detect_finalized(input, registry, limits)?;
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

/// The detection half of [`scan_in`]: the whole-input byte bound, one
/// detection pass, then the finding bound. Shared by the enforcement path and
/// the policy comparison so both see the same finalized findings and the same
/// limit failures in the same order.
pub(crate) fn detect_finalized<R: DetectorSet + ?Sized>(
    input: &str,
    registry: &R,
    limits: &WholeInputLimits,
) -> Result<Vec<DetectedFinding>, SecretScanError> {
    limits.check_input(input)?;
    let detected = detect(input, registry, None)?;
    limits.check_findings(detected.len())?;
    Ok(detected)
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
    scan_and_redact_in(input, registry, policy, formatter, limits)
}

/// [`scan_and_redact_with_limits`] over any detector set; see [`scan_in`].
pub(crate) fn scan_and_redact_in<R: DetectorSet + ?Sized>(
    input: &str,
    registry: &R,
    policy: &dyn Policy,
    formatter: &dyn PlaceholderFormatter,
    limits: &WholeInputLimits,
) -> Result<ScanResult, SecretScanError> {
    let findings = scan_in(input, registry, policy, limits)?;
    let text = redact_with_limits(input, &findings, formatter, limits)?;
    Ok(ScanResult::new(text, findings))
}

/// Redacts `input` with the supported defaults, in one call.
///
/// This is the minimal path: the `full` built-in [`Profile`], the
/// [`DefaultPolicy`], the
/// [`default_placeholder_formatter`], and the default [`WholeInputLimits`].
/// It is exactly [`sanitize_with_profile`] with [`Profile::Full`], and through
/// it exactly [`scan_and_redact`] over a registry from
/// [`DetectorRegistry::with_built_in`] with no custom detectors. The result
/// keeps the evidence: [`ScanResult::text`] is the redacted text and
/// [`ScanResult::findings`] carries byte ranges into the original `input`.
///
/// ```
/// let result = redact_secret::sanitize("API_KEY=ghp_SYNTHETICREVOKED00000000000000000000")?;
/// assert_eq!(result.text(), "API_KEY=<SECRET_1>");
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
///
/// # Advanced use
///
/// For a `common` profile see [`sanitize_with_profile`]. For custom
/// detectors, PII activation, a custom [`Policy`] or
/// [`PlaceholderFormatter`](crate::PlaceholderFormatter), explicit
/// [`WholeInputLimits`], or a reused registry, build a [`DetectorRegistry`]
/// and call [`scan_and_redact`] or [`scan_and_redact_with_limits`]. Chunked
/// input uses [`IncrementalSanitizer`](crate::IncrementalSanitizer), which
/// supports no custom detectors, so this convenience layer does not either.
///
/// # Design decisions (#1078)
///
/// - Function, not a `Sanitizer` value: there is no state worth holding, and
///   `IncrementalSanitizer` already owns the "sanitizer" noun for a stateful
///   session.
/// - Stateless: building the built-in registry costs about 18 microseconds
///   (`registry-build` bench), so nothing is cached and no hidden global
///   exists. A caller scanning in a hot loop builds a [`DetectorRegistry`]
///   once and calls [`scan_and_redact`].
/// - Returns [`ScanResult`], never a bare `String`: dropping the findings
///   would discard the evidence callers need to audit or block. Use
///   [`ScanResult::text`] for the text.
///
/// # Errors
///
/// Exactly the errors [`scan_and_redact`] reports, unchanged: a failed
/// built-in registry construction, [`SecretScanErrorCode::InputLimitExceeded`],
/// [`SecretScanErrorCode::FindingLimitExceeded`], and policy or formatter
/// failures. Nothing is truncated, retried, or weakened.
pub fn sanitize(input: &str) -> Result<ScanResult, SecretScanError> {
    sanitize_with_profile(input, Profile::Full)
}

/// Same as [`sanitize`], for the built-in detectors of `profile`.
///
/// [`Profile::Full`] is the default and compatibility baseline;
/// [`Profile::Common`] is the smaller, format-agnostic subset for size- or
/// latency-sensitive preventive use, and may report fewer findings than
/// `full` by design. Everything else (policy, formatter, limits, errors)
/// is that of [`sanitize`]: this is [`scan_and_redact`] over a registry from
/// [`DetectorRegistry::with_built_in`] or
/// [`DetectorRegistry::with_common_built_in`] with no custom detectors.
///
/// A run-time `Profile` value references both registry constructors, so the
/// linker keeps the detectors of both profiles. For the smaller binary the
/// `common` profile exists for, call [`DetectorRegistry::with_common_built_in`]
/// directly (the Rust guide, `docs/guides/rust.md`, "Detector profiles").
///
/// ```
/// use redact_secret::Profile;
///
/// let result = redact_secret::sanitize_with_profile("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE", Profile::Common)?;
/// assert_eq!(result.text(), "API_KEY=<SECRET_1>");
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
///
/// A plain argument rather than a builder keeps the convenience layer one
/// function wide (#1078).
///
/// # Errors
///
/// See [`sanitize`].
pub fn sanitize_with_profile(input: &str, profile: Profile) -> Result<ScanResult, SecretScanError> {
    let registry = match profile {
        Profile::Full => DetectorRegistry::with_built_in([])?,
        Profile::Common => DetectorRegistry::with_common_built_in([])?,
    };
    scan_and_redact(
        input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic, otherwise-identical `RankedCandidate` so DP
    /// selection can be tested without a real detector or `&str` behind it.
    /// `severity` is 0-3 like [`crate::types::Action::overlap_resolution_severity`];
    /// `type_name` and `detector` are stable per-test leaked strings so the
    /// resulting `RankedCandidate` can outlive the function that builds it.
    const SYNTHETIC_TYPE: Cow<'static, str> = Cow::Borrowed("synthetic_type");
    const SYNTHETIC_DETECTOR: Cow<'static, str> = Cow::Borrowed("synthetic-detector");

    fn synthetic(
        severity: u8,
        specificity: Specificity,
        confidence: Confidence,
        start: usize,
        end: usize,
        detector_order: usize,
        candidate_order: usize,
    ) -> RankedCandidate<'static> {
        RankedCandidate {
            type_name: &SYNTHETIC_TYPE,
            detector: &SYNTHETIC_DETECTOR,
            confidence,
            specificity,
            resolved_severity: severity,
            range: ByteRange::new(start, end).unwrap(),
            obfuscation: Obfuscation::None,
            detector_order,
            candidate_order,
            emission_index: candidate_order,
        }
    }

    /// The resolver before the disjoint fast path (#1094): the full
    /// weighted-interval DP on every nonempty set.
    fn select_dp_oracle(mut ranked: Vec<RankedCandidate<'_>>) -> Vec<RankedCandidate<'_>> {
        // Nothing to select: most closed lines of an incremental session carry
        // no candidate, and the tables below would each allocate (issue #950).
        if ranked.is_empty() {
            return ranked;
        }
        ranked.sort_unstable_by(|a, b| {
            a.range
                .end()
                .cmp(&b.range.end())
                .then_with(|| a.priority(b))
        });

        let n = ranked.len();
        let ends: Vec<usize> = ranked
            .iter()
            .map(|candidate| candidate.range.end())
            .collect();
        // Strictly exceeds `n`, the number of candidates that could ever be
        // summed at one dominance tier; see `EvidenceWeight`'s doc comment.
        let base = n as u128 + 1;

        let mut totals: Vec<EvidenceWeight> = Vec::with_capacity(n + 1);
        totals.push(EvidenceWeight::default());
        let mut include: Vec<bool> = Vec::with_capacity(n);

        for (i, candidate) in ranked.iter().enumerate() {
            let pred = ends[..i].partition_point(|&end| end <= candidate.range.start());
            let with_candidate = EvidenceWeight::of(candidate, base).plus(totals[pred]);
            let without_candidate = totals[i];
            if with_candidate > without_candidate {
                include.push(true);
                totals.push(with_candidate);
            } else {
                include.push(false);
                totals.push(without_candidate);
            }
        }

        let mut selected_mask = vec![false; n];
        let mut i = n;
        while i > 0 {
            if include[i - 1] {
                selected_mask[i - 1] = true;
                let start = ranked[i - 1].range.start();
                i = ends[..i - 1].partition_point(|&end| end <= start);
            } else {
                i -= 1;
            }
        }

        ranked
            .into_iter()
            .zip(selected_mask)
            .filter_map(|(candidate, selected)| selected.then_some(candidate))
            .collect()
    }

    fn key(selected: &[RankedCandidate<'_>]) -> Vec<(usize, usize, usize, usize)> {
        selected
            .iter()
            .map(|c| {
                (
                    c.detector_order,
                    c.candidate_order,
                    c.range.start(),
                    c.range.end(),
                )
            })
            .collect()
    }

    /// Random candidate sets over a tiny coordinate space, so equal ranges,
    /// containment, adjacency, empty ranges and exact weight ties all occur,
    /// with mostly-disjoint sets included to hit the fast path.
    #[test]
    fn disjoint_fast_path_matches_the_full_dp_on_random_sets() {
        use crate::test_rng::XorShift32;
        let specificities = [
            Specificity::Entropy,
            Specificity::Contextual,
            Specificity::Structural,
            Specificity::Provider,
        ];
        let confidences = [Confidence::Low, Confidence::Medium, Confidence::High];
        let mut rng = XorShift32::new(0x1094_0001);
        let mut fast = 0_usize;
        for case in 0..6000_usize {
            let count = rng.below(9);
            let span = 4 + rng.below(28);
            let mostly_disjoint = case % 3 == 0;
            let mut cursor = 0_usize;
            let params: Vec<(u8, usize, usize, usize, usize, usize)> = (0..count)
                .map(|i| {
                    let (start, end) = if mostly_disjoint && rng.below(8) != 0 {
                        let start = cursor + rng.below(3);
                        let end = start + 1 + rng.below(4);
                        cursor = end;
                        (start, end)
                    } else {
                        let start = rng.below(span);
                        (start, start + 1 + rng.below(span / 2 + 1))
                    };
                    let severity = u8::try_from(rng.below(4)).unwrap_or(0);
                    (severity, rng.below(4), rng.below(3), start, end, i)
                })
                .collect();
            let build = || -> Vec<RankedCandidate<'static>> {
                params
                    .iter()
                    .map(|&(severity, spec, conf, start, end, i)| {
                        synthetic(
                            severity,
                            specificities[spec],
                            confidences[conf],
                            start,
                            end,
                            i % 3,
                            i / 3,
                        )
                    })
                    .collect()
            };
            let mut sorted = build();
            sorted.sort_unstable_by(|a, b| {
                a.range
                    .end()
                    .cmp(&b.range.end())
                    .then_with(|| a.priority(b))
            });
            if sorted
                .windows(2)
                .all(|pair| pair[1].range.start() >= pair[0].range.end())
            {
                fast += 1;
            }
            assert_eq!(
                key(&select_optimal_disjoint_set(build())),
                key(&select_dp_oracle(build())),
                "case {case}: {params:?}"
            );
        }
        assert!(fast > 500, "fast path exercised only {fast} times");
    }

    /// `(start, end, severity, specificity, confidence)` of one synthetic
    /// candidate.
    type Spec = (usize, usize, u8, usize, usize);

    /// The resolver as shipped before component splitting (#1135): the
    /// disjoint fast path, then the global DP over every candidate.
    fn select_global_oracle(ranked: Vec<RankedCandidate<'_>>) -> Vec<RankedCandidate<'_>> {
        let mut sorted = ranked;
        sorted.sort_unstable_by(|a, b| {
            a.range
                .end()
                .cmp(&b.range.end())
                .then_with(|| a.priority(b))
        });
        if sorted
            .windows(2)
            .all(|pair| pair[1].range.start() >= pair[0].range.end())
        {
            return sorted;
        }
        select_dp_oracle(sorted)
    }

    fn candidates_from(specs: &[Spec]) -> Vec<RankedCandidate<'static>> {
        let specificities = [
            Specificity::Entropy,
            Specificity::Contextual,
            Specificity::Structural,
            Specificity::Provider,
            Specificity::PrivateKey,
        ];
        let confidences = [Confidence::Low, Confidence::Medium, Confidence::High];
        specs
            .iter()
            .enumerate()
            .map(|(i, &(start, end, severity, spec, conf))| {
                synthetic(
                    severity,
                    specificities[spec % specificities.len()],
                    confidences[conf % confidences.len()],
                    start,
                    end,
                    i % 7,
                    i / 7,
                )
            })
            .collect()
    }

    fn assert_split_matches_global(specs: &[Spec], label: &str) {
        let split = select_optimal_disjoint_set(candidates_from(specs));
        let global = select_global_oracle(candidates_from(specs));
        assert_eq!(key(&split), key(&global), "{label}");
    }

    /// Larger, structured sets than the tiny-space test above: clusters
    /// separated by gaps and by exact adjacency, singletons between them,
    /// containment, identical ranges, exact ties, sets of up to 600.
    #[test]
    fn component_split_matches_the_global_dp_on_structured_and_random_sets() {
        use crate::test_rng::XorShift32;
        let mut rng = XorShift32::new(0x1135_0001);
        for case in 0..3000_usize {
            let clusters = 1 + rng.below(12);
            let mut specs = Vec::new();
            let mut cursor = 0_usize;
            for _ in 0..clusters {
                // Gap of 0 makes the next cluster exactly adjacent.
                cursor += rng.below(3);
                let members = match rng.below(5) {
                    0 => 1,
                    1 => 2,
                    2 => 1 + rng.below(6),
                    3 => 1 + rng.below(40),
                    _ => 1 + rng.below(8),
                };
                let width = 2 + rng.below(30);
                for _ in 0..members {
                    let start = cursor + rng.below(width);
                    let end = start + 1 + rng.below(width);
                    let severity = u8::try_from(rng.below(4)).unwrap_or(0);
                    specs.push((start, end, severity, rng.below(5), rng.below(3)));
                }
                cursor += 2 * width;
            }
            assert_split_matches_global(&specs, &format!("structured case {case}"));
        }
        for case in 0..2000_usize {
            let count = rng.below(600);
            let span = 4 + rng.below(4000);
            let specs: Vec<_> = (0..count)
                .map(|_| {
                    let start = rng.below(span);
                    let width = 1 + rng.below(span / 8 + 1);
                    let severity = u8::try_from(rng.below(4)).unwrap_or(0);
                    (start, start + width, severity, rng.below(5), rng.below(3))
                })
                .collect();
            assert_split_matches_global(&specs, &format!("random case {case}"));
        }
    }

    #[test]
    fn component_split_matches_the_global_dp_on_the_named_shapes() {
        let same = |start, end| (start, end, 2, 2, 2);
        // The weight base is the whole set's count, never a component's: a
        // component of two with a higher-severity pair elsewhere keeps the
        // global base, and an exact tie keeps the previously computed
        // (excluding) state.
        let cases: Vec<(&str, Vec<Spec>)> = vec![
            ("single", vec![same(0, 5)]),
            ("identical ranges", vec![same(3, 9), same(3, 9), same(3, 9)]),
            (
                "tie then singleton",
                vec![same(0, 4), same(0, 4), same(10, 12)],
            ),
            (
                "containment",
                vec![same(0, 100), same(10, 20), same(30, 40), same(200, 210)],
            ),
            (
                "adjacent clusters",
                vec![same(0, 4), same(2, 6), same(6, 9), same(7, 12)],
            ),
            (
                "pair beats single across clusters",
                vec![
                    (0, 100, 3, 3, 2),
                    (0, 40, 2, 1, 0),
                    (60, 100, 2, 1, 0),
                    same(200, 201),
                ],
            ),
            (
                "two disjoint beat one overlapper",
                vec![(0, 100, 2, 3, 2), (0, 40, 2, 2, 1), (60, 100, 2, 2, 1)],
            ),
            (
                "long chain",
                (0..200).map(|i| same(i * 3, i * 3 + 4)).collect(),
            ),
            (
                "many pairs",
                (0..400)
                    .map(|i| same((i / 2) * 20, (i / 2) * 20 + 8))
                    .collect(),
            ),
            (
                "one dense cluster",
                (0..300).map(|i| same(i, i + 1000)).collect(),
            ),
            (
                "dense cluster among singletons",
                (0..50)
                    .map(|i| same(i * 20, i * 20 + 8))
                    .chain((0..100).map(|i| same(2000 + i, 2000 + i + 500)))
                    .chain((0..50).map(|i| same(5000 + i * 20, 5000 + i * 20 + 8)))
                    .collect(),
            ),
        ];
        for (label, specs) in cases {
            assert_split_matches_global(&specs, label);
        }
        assert_split_matches_global(&[], "empty");
    }
    #[test]
    fn disjoint_fast_path_keeps_equal_endpoints_and_adjacent_ranges() {
        let make = |ranges: &[(usize, usize)]| -> Vec<RankedCandidate<'static>> {
            ranges
                .iter()
                .enumerate()
                .map(|(i, &(start, end))| {
                    synthetic(1, Specificity::Provider, Confidence::High, start, end, 0, i)
                })
                .collect()
        };
        for ranges in [
            vec![(0, 3), (3, 6), (6, 7), (7, 9)],
            vec![(2, 3), (2, 3), (2, 4)],
            vec![(5, 8), (0, 5), (8, 9)],
            vec![(0, 4), (0, 4)],
            vec![(0, 4), (1, 3)],
        ] {
            assert_eq!(
                key(&select_optimal_disjoint_set(make(&ranges))),
                key(&select_dp_oracle(make(&ranges))),
                "{ranges:?}"
            );
        }
    }

    #[test]
    fn select_optimal_disjoint_set_keeps_disjoint_candidates_only() {
        // Every candidate carries the same severity, specificity, and
        // confidence, so the maximum achievable count (5, the same count
        // `try_accept`'s equivalent case kept) dominates the total weight,
        // and only the narrowness tier — summed span width, the lowest
        // weight tier above per-candidate order — distinguishes between the
        // several 5-candidate disjoint sets this input admits. Optimal
        // selection picks the narrowest one rather than whichever a
        // greedy, order-dependent walk would have reached first.
        let candidates = vec![
            synthetic(2, Specificity::Provider, Confidence::High, 10, 20, 0, 0),
            synthetic(2, Specificity::Provider, Confidence::High, 30, 40, 0, 1),
            synthetic(2, Specificity::Provider, Confidence::High, 15, 35, 0, 2),
            synthetic(2, Specificity::Provider, Confidence::High, 5, 11, 0, 3),
            synthetic(2, Specificity::Provider, Confidence::High, 19, 25, 0, 4),
            synthetic(2, Specificity::Provider, Confidence::High, 0, 100, 0, 5),
            synthetic(2, Specificity::Provider, Confidence::High, 12, 13, 0, 6),
            synthetic(2, Specificity::Provider, Confidence::High, 20, 30, 0, 7),
            synthetic(2, Specificity::Provider, Confidence::High, 0, 10, 0, 8),
            synthetic(2, Specificity::Provider, Confidence::High, 40, 41, 0, 9),
        ];
        let selected = select_optimal_disjoint_set(candidates);

        // Pairwise disjoint: the defining property `try_accept` also had to
        // hold.
        let mut ranges: Vec<(usize, usize)> = selected
            .iter()
            .map(|candidate| (candidate.range.start(), candidate.range.end()))
            .collect();
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            assert!(pair[0].1 <= pair[1].0, "{ranges:?} has an overlap");
        }

        // No disjoint combination of these ranges can seat more than 5.
        assert_eq!(ranges.len(), 5);

        // Among every 5-candidate disjoint set, this is the one with the
        // least total covered width (24 bytes: 6 + 1 + 6 + 10 + 1), so it
        // is the one with the greatest total narrowness weight.
        assert_eq!(
            ranges,
            vec![(5, 11), (12, 13), (19, 25), (30, 40), (40, 41)]
        );
    }

    #[test]
    fn select_optimal_disjoint_set_prefers_a_higher_weight_single_candidate_when_no_combination_beats_it()
     {
        // A single Redact-severity, Provider-specificity candidate spans two
        // lower-weight, mutually disjoint Warn-severity candidates it
        // overlaps. No disjoint combination available anywhere in this
        // input beats the wide candidate's own weight, so it wins, matching
        // `RankedCandidate::priority`'s pairwise call on each pair.
        let wide = synthetic(2, Specificity::Provider, Confidence::High, 0, 100, 0, 0);
        let left = synthetic(1, Specificity::Contextual, Confidence::Low, 0, 40, 1, 0);
        let right = synthetic(1, Specificity::Contextual, Confidence::Low, 60, 100, 1, 1);
        assert_eq!(wide.priority(&left), Ordering::Less);
        assert_eq!(wide.priority(&right), Ordering::Less);

        let selected = select_optimal_disjoint_set(vec![wide, left, right]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].range, ByteRange::new(0, 100).unwrap());
    }

    #[test]
    fn select_optimal_disjoint_set_prefers_two_disjoint_candidates_over_one_higher_priority_overlapper()
     {
        // The shape greedy gets wrong: a single candidate individually
        // outranks each of two mutually disjoint candidates it overlaps
        // (so greedy, walking in priority order, accepts it and discards
        // both), but the pair's combined resolved-action severity — the
        // dominant weight tier (`decision-resolve-overlap-precedence-by-resolved-action-severity`)
        // — exceeds the single candidate's alone. Optimal selection must
        // keep the pair instead.
        let single = synthetic(2, Specificity::Provider, Confidence::High, 0, 100, 0, 0);
        let left = synthetic(2, Specificity::Contextual, Confidence::Low, 0, 40, 1, 0);
        let right = synthetic(2, Specificity::Contextual, Confidence::Low, 60, 100, 1, 1);
        // `single` individually outranks each of `left` and `right` — this
        // is exactly what makes greedy pick it and discard the pair.
        assert_eq!(single.priority(&left), Ordering::Less);
        assert_eq!(single.priority(&right), Ordering::Less);

        let mut selected: Vec<(usize, usize)> =
            select_optimal_disjoint_set(vec![single, left, right])
                .iter()
                .map(|candidate| (candidate.range.start(), candidate.range.end()))
                .collect();
        selected.sort_unstable();
        assert_eq!(selected, vec![(0, 40), (60, 100)]);
    }

    #[test]
    fn select_optimal_disjoint_set_keeps_every_disjoint_preferred_pair_at_a_large_candidate_count()
    {
        // The same shape as
        // `select_optimal_disjoint_set_prefers_two_disjoint_candidates_over_one_higher_priority_overlapper`,
        // tiled across many independent, non-adjacent groups. A candidate
        // count no small fixture reaches, so a future regression that only
        // gets the tiny cases right (for example an off-by-one in the
        // predecessor binary search that happens to not matter at n < 10)
        // has somewhere to show up.
        const GROUPS: usize = 5_000;
        let mut candidates = Vec::with_capacity(GROUPS * 3);
        for i in 0..GROUPS {
            let start = i * 6;
            // The wide overlapper: higher specificity and confidence than
            // either half of the pair, so it individually outranks each of
            // them under `RankedCandidate::priority` alone.
            candidates.push(synthetic(
                2,
                Specificity::Provider,
                Confidence::High,
                start,
                start + 5,
                0,
                i,
            ));
            // The disjoint pair it overlaps, tied with it on resolved
            // severity so their combined weight outranks the single
            // overlapper's.
            candidates.push(synthetic(
                2,
                Specificity::Contextual,
                Confidence::Low,
                start,
                start + 2,
                1,
                2 * i,
            ));
            candidates.push(synthetic(
                2,
                Specificity::Contextual,
                Confidence::Low,
                start + 3,
                start + 5,
                1,
                2 * i + 1,
            ));
        }

        let mut selected: Vec<(usize, usize)> = select_optimal_disjoint_set(candidates)
            .iter()
            .map(|candidate| (candidate.range.start(), candidate.range.end()))
            .collect();
        selected.sort_unstable();

        // Every group keeps its disjoint pair, never the wide overlapper:
        // exactly 2 selected candidates per group.
        assert_eq!(selected.len(), GROUPS * 2);
        for (i, pair) in selected.chunks(2).enumerate() {
            let start = i * 6;
            assert_eq!(pair, [(start, start + 2), (start + 3, start + 5)]);
        }
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

    const GOOGLE_API_KEY: &str = "AIzaSYNTHETIC_REVOKED_GOOGLE_API_KEY012";

    fn firebase_client_config_javascript() -> String {
        format!(
            "const firebaseConfig = {{\n  apiKey: \"{GOOGLE_API_KEY}\",\n  authDomain: \"synthetic-revoked.firebaseapp.com\",\n  databaseURL: \"https://synthetic-revoked-default-rtdb.firebaseio.com\",\n  projectId: \"synthetic-revoked\",\n  storageBucket: \"synthetic-revoked.firebasestorage.app\",\n  messagingSenderId: \"000000000000\",\n  appId: \"1:000000000000:web:synthetic0revoked1fixture2\",\n  measurementId: \"G-SYNTHETIC0\"\n}};"
        )
    }

    fn firebase_client_config_json() -> String {
        format!(
            "{{\"apiKey\": \"{GOOGLE_API_KEY}\", \"authDomain\": \"synthetic-revoked.firebaseapp.com\", \"databaseURL\": \"https://synthetic-revoked-default-rtdb.firebaseio.com\", \"projectId\": \"synthetic-revoked\", \"storageBucket\": \"synthetic-revoked.firebasestorage.app\", \"messagingSenderId\": \"000000000000\", \"appId\": \"1:000000000000:web:synthetic0revoked1fixture2\", \"measurementId\": \"G-SYNTHETIC0\"}}"
        )
    }

    fn firebase_client_config_env() -> String {
        format!(
            "NEXT_PUBLIC_FIREBASE_API_KEY={GOOGLE_API_KEY}\nNEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=synthetic-revoked.firebaseapp.com\nNEXT_PUBLIC_FIREBASE_PROJECT_ID=synthetic-revoked\nNEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=synthetic-revoked.firebasestorage.app\nNEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=000000000000\nNEXT_PUBLIC_FIREBASE_APP_ID=1:000000000000:web:synthetic0revoked1fixture2\nNEXT_PUBLIC_FIREBASE_MEASUREMENT_ID=G-SYNTHETIC0\n"
        )
    }

    /// Asserts `input` yields exactly one finding: the `AIza` key's own
    /// span, as `google_api_key`. The neighbouring config fields
    /// (`projectId`, `authDomain`, `appId`, `messagingSenderId`, ...) stay
    /// unflagged.
    fn assert_only_the_google_api_key_is_reported(input: &str) {
        let registry = built_in_registry();
        let findings = run_detector_pipeline(input, &registry).unwrap();
        let start = input.find(GOOGLE_API_KEY).unwrap();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].type_name(), "google_api_key");
        assert_eq!(findings[0].range().start(), start);
        assert_eq!(findings[0].range().end(), start + GOOGLE_API_KEY.len());
    }

    // #749 reversed #520 (B3a): a Firebase Web SDK client config is no
    // longer evidence that its `apiKey` is restricted, so the key is
    // reported like any other `AIza` value.
    #[test]
    fn a_full_firebase_client_config_in_javascript_reports_only_the_api_key() {
        assert_only_the_google_api_key_is_reported(&firebase_client_config_javascript());
    }

    #[test]
    fn a_full_firebase_client_config_in_json_reports_only_the_api_key() {
        assert_only_the_google_api_key_is_reported(&firebase_client_config_json());
    }

    #[test]
    fn an_env_injected_firebase_client_config_reports_only_the_api_key() {
        assert_only_the_google_api_key_is_reported(&firebase_client_config_env());
    }

    #[test]
    fn a_minimal_firebase_client_config_reports_only_the_api_key() {
        assert_only_the_google_api_key_is_reported(&format!(
            "const firebaseConfig = {{\n  apiKey: \"{GOOGLE_API_KEY}\",\n  authDomain: \"synthetic-revoked.firebaseapp.com\",\n  projectId: \"synthetic-revoked\",\n}};\n"
        ));
    }

    #[test]
    fn a_google_api_key_used_as_a_privileged_server_key_variable_is_still_detected() {
        // Grounded in a documented real-world FCM-takeover pattern: an
        // `AIza`-shaped key stored under a privileged `server_key`-style
        // variable name, not the public client config, carries none of the
        // config's sibling fields and must not be suppressed.
        let registry = built_in_registry();
        let input = format!("const server_key = \"{GOOGLE_API_KEY}\";");
        let findings = run_detector_pipeline(&input, &registry).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].type_name(), "google_api_key");
    }

    #[test]
    fn a_bare_google_api_key_far_from_any_firebase_config_is_still_detected() {
        let registry = built_in_registry();
        let input = format!("GEMINI_API_KEY={GOOGLE_API_KEY}");
        let findings = run_detector_pipeline(&input, &registry).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].type_name(), "google_api_key");
    }
}
