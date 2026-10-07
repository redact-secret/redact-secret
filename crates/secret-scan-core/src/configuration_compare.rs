//! Comparing detection configurations over one input
//! (`decision-define-the-artifact-manifest-and-configuration-data-contracts`,
//! section 7, `configuration-comparison/v1`; issue #1254).
//!
//! [`compare_configurations`] is the other half of
//! [`compare_action_policies`](crate::compare_action_policies). That function
//! changes only the action over **one** detection pass. This one is for a
//! change that may alter detection (the detector selection, the PII selection,
//! a ruleset, the limits): it runs one **independent** pass per side, each over
//! its own registry, and then says how the sides' finalized findings
//! correspond. Both are observations of one input; neither is enforcement.
//!
//! # What a comparison is not
//!
//! - It is **not a handle** and holds nothing. The caller builds each side's
//!   registry (a temporary one, for example from a [`ConfigSnapshot`]) and the
//!   function reads them; no owner changes and no registry is retained.
//! - It covers **finalized findings only**. An overlap loser, a candidate a
//!   gate removed and a suppressed PII alternative are never inputs, so the
//!   result makes no claim about them. The detection that "removing a
//!   provider exposes a contextual detector on the same span" is visible only
//!   as the finalized finding that now holds that span.
//! - It is **about this input only** (`scope: "input"`). A side with no
//!   finding, or a pair with no difference, says nothing about absence of
//!   risk, about other input, or that a rule is ineffective.
//! - It carries **no plaintext**: ranges, fixed identifiers, counts and
//!   digests of configuration only. Findings carry no per-scan id here,
//!   because that id is not a stable identity across scans.
//!
//! # Correspondence
//!
//! Findings of different passes have no stable identity, so correspondence is
//! derived from the byte ranges every side reports over the same input (a
//! binding converts to its range unit only when it reports, so Unicode never
//! changes which findings correspond). Findings are grouped into **clusters**:
//! maximal sets joined by overlapping ranges, across both sides. Per cluster,
//! the base side (side 0) against another side:
//!
//! | base | other | outcome |
//! | --- | --- | --- |
//! | 0 | n | [`DifferenceKind::Added`], one per finding |
//! | n | 0 | [`DifferenceKind::Removed`], one per finding |
//! | 1 | 1, same range | the same finding; a difference only when an attribute changed ([`Correspondence::Exact`]) |
//! | 1 | 1, other range | [`DifferenceKind::Changed`] with the range among the changes ([`Correspondence::Overlap`]) |
//! | 1 | n > 1 | [`DifferenceKind::Split`] |
//! | n > 1 | 1 | [`DifferenceKind::Merged`] |
//! | n > 1 | m > 1 | [`DifferenceKind::Regrouped`] |
//!
//! A split, merge or regrouping is [`Correspondence::Ambiguous`]: it names all
//! members and does not pair them or claim an attribute changed. An unchanged
//! pair is counted, not listed.
//!
//! # Failed sides
//!
//! A side that cannot be scanned is reported with a fixed code and a
//! [`SideStatus`] (`limited` for a limit, `unsupported` for something its
//! artifact cannot do, `error` otherwise), never as an empty side. A
//! difference is reported only between two scanned sides; against a failed
//! side (or a failed base) there is none, so a failure is never read as
//! equivalence or as "found nothing".
//!
//! # Callbacks
//!
//! A [`ComparedPolicy::Callback`] side may have side effects and has no stable
//! identity. Sides run one at a time in the order supplied, each callback once
//! per finalized finding of its own side in finding order (the call sequence
//! `scan` gives it). A callback failure fails the whole comparison with no
//! partial result, as it does for `compare_action_policies`.

use crate::compare::{
    ActionComparison, ComparedFinding, ComparedPolicy, MAX_COMPARED_POLICIES, PolicyBinding,
    binding_of, compare_action_policies_with_limits,
};
use crate::config::ConfigSnapshot;
use crate::error::{SecretScanError, SecretScanErrorCode};
use crate::limits::WholeInputLimits;
use crate::registry::DetectorRegistry;

/// One configuration taking part in a comparison: a registry (or the reason it
/// could not be built), the policy evaluated over its findings, its limits and
/// the identity digests of the configuration it was built from.
#[derive(Clone, Copy, Debug)]
pub struct ConfigurationSide<'a> {
    registry: Result<&'a DetectorRegistry, &'static str>,
    policy: ComparedPolicy<'a>,
    limits: WholeInputLimits,
    digests: Option<(&'a str, &'a str)>,
}

impl<'a> ConfigurationSide<'a> {
    /// A side scanned over `registry` and judged by `policy`, under the
    /// default limits.
    #[must_use]
    pub fn new(registry: &'a DetectorRegistry, policy: ComparedPolicy<'a>) -> Self {
        Self {
            registry: Ok(registry),
            policy,
            limits: WholeInputLimits::default(),
            digests: None,
        }
    }

    /// A side that could not be built, with the fixed code that says why (a
    /// configuration diagnostic code or an error code). It is reported as
    /// failed and is never scanned.
    #[must_use]
    pub fn failed(code: &'static str, policy: ComparedPolicy<'a>) -> Self {
        Self {
            registry: Err(code),
            policy,
            limits: WholeInputLimits::default(),
            digests: None,
        }
    }

    /// Replaces the side's whole-input limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: WholeInputLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Names the configuration this side was built from, by the snapshot
    /// digest and the detection digest. Equal detection digests mean the same
    /// detection; a different ruleset or selection always differs here, whatever
    /// the policy bytes are.
    #[must_use]
    pub fn with_snapshot(mut self, snapshot: &'a ConfigSnapshot) -> Self {
        self.digests = Some((snapshot.digest(), snapshot.detection_digest()));
        self
    }
}

/// Whether a side produced findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SideStatus {
    /// The pass ran and the side holds its finalized findings (possibly none).
    Scanned,
    /// A whole-input limit stopped the pass.
    Limited,
    /// The side asked for something its artifact cannot do.
    Unsupported,
    /// The configuration was invalid or the pass failed.
    Error,
}

impl SideStatus {
    /// The fixed wire name: `"scanned"`, `"limited"`, `"unsupported"` or
    /// `"error"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scanned => "scanned",
            Self::Limited => "limited",
            Self::Unsupported => "unsupported",
            Self::Error => "error",
        }
    }

    fn of(code: &str) -> Self {
        match code {
            "INPUT_LIMIT_EXCEEDED" | "FINDING_LIMIT_EXCEEDED" => Self::Limited,
            "DETECTION_SELECTION_UNSUPPORTED"
            | "PII_SELECTOR_UNSUPPORTED"
            | "PII_SELECTOR_UNAVAILABLE" => Self::Unsupported,
            _ => Self::Error,
        }
    }
}

/// One side of a [`ConfigurationComparison`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationResult {
    digests: Option<(String, String)>,
    binding: PolicyBinding,
    scan: Result<ActionComparison, &'static str>,
}

impl ConfigurationResult {
    /// The side's policy binding: the document digest of a declarative
    /// policy, and for a callback nothing (the library keeps no identity of a
    /// callback, and it may have side effects).
    #[must_use]
    pub const fn policy(&self) -> &PolicyBinding {
        &self.binding
    }

    /// The snapshot digest of the configuration, when the side named one.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        self.digests.as_ref().map(|pair| pair.0.as_str())
    }

    /// The detection digest of the configuration, when the side named one.
    #[must_use]
    pub fn detection_digest(&self) -> Option<&str> {
        self.digests.as_ref().map(|pair| pair.1.as_str())
    }

    /// Whether the side was scanned, and if not, why not.
    #[must_use]
    pub fn status(&self) -> SideStatus {
        self.scan
            .as_ref()
            .err()
            .map_or(SideStatus::Scanned, |code| SideStatus::of(code))
    }

    /// The fixed code of a failed side.
    #[must_use]
    pub fn failure(&self) -> Option<&'static str> {
        self.scan.as_ref().err().copied()
    }

    /// The side's policy and detection facts, for a scanned side.
    #[must_use]
    pub fn scan(&self) -> Option<&ActionComparison> {
        self.scan.as_ref().ok()
    }

    /// The side's finalized findings in input order, with the side's own
    /// decision as the only entry of each finding's decisions. Empty for a
    /// failed side, which is not the same as "found nothing": check
    /// [`Self::status`].
    #[must_use]
    pub fn findings(&self) -> &[ComparedFinding] {
        self.scan.as_ref().map_or(&[], ActionComparison::findings)
    }
}

/// How one entry of a difference list relates the two sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DifferenceKind {
    /// A finding only the other side has.
    Added,
    /// A finding only the base side has.
    Removed,
    /// One finding on each side over overlapping ranges, with at least one
    /// attribute changed.
    Changed,
    /// One base finding against several of the other side.
    Split,
    /// Several base findings against one of the other side.
    Merged,
    /// Several against several.
    Regrouped,
}

impl DifferenceKind {
    /// The fixed wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Changed => "changed",
            Self::Split => "split",
            Self::Merged => "merged",
            Self::Regrouped => "regrouped",
        }
    }
}

/// How sure the pairing of an entry's findings is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Correspondence {
    /// The same range on both sides.
    Exact,
    /// One finding each over overlapping, different ranges.
    Overlap,
    /// Several findings share the overlap; none is paired with another.
    Ambiguous,
}

impl Correspondence {
    /// The fixed wire name: `"exact"`, `"overlap"` or `"ambiguous"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Overlap => "overlap",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// The attributes a [`DifferenceKind::Changed`] entry names, in bit order.
const CHANGE_NAMES: [&str; 6] = [
    "range",
    "type",
    "detector",
    "confidence",
    "action",
    "reason",
];

/// One difference between the base side and another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationDifference {
    kind: DifferenceKind,
    base: Vec<usize>,
    other: Vec<usize>,
    changes: u8,
}

impl ConfigurationDifference {
    /// The kind of difference.
    #[must_use]
    pub const fn kind(&self) -> DifferenceKind {
        self.kind
    }

    /// The positions, among the base side's findings, of the findings involved.
    #[must_use]
    pub fn base(&self) -> &[usize] {
        &self.base
    }

    /// The positions, among the other side's findings, of the findings
    /// involved.
    #[must_use]
    pub fn other(&self) -> &[usize] {
        &self.other
    }

    /// How the findings are paired; `None` for an added or removed finding.
    #[must_use]
    pub const fn correspondence(&self) -> Option<Correspondence> {
        match self.kind {
            DifferenceKind::Added | DifferenceKind::Removed => None,
            DifferenceKind::Changed if self.changes & 1 == 0 => Some(Correspondence::Exact),
            DifferenceKind::Changed => Some(Correspondence::Overlap),
            _ => Some(Correspondence::Ambiguous),
        }
    }

    /// The changed attributes as a bit set: bit 0 is `range`, then `type`, `detector`, `confidence`, `action` and `reason`.
    #[must_use]
    pub const fn change_bits(&self) -> u8 {
        self.changes
    }

    /// The attributes that changed, (in the order `range`, `type`, `detector`, `confidence`, `action`, `reason`); empty unless the
    /// kind is [`DifferenceKind::Changed`].
    pub fn changes(&self) -> impl Iterator<Item = &'static str> + '_ {
        CHANGE_NAMES
            .iter()
            .enumerate()
            .filter(|(bit, _)| self.changes >> bit & 1 == 1)
            .map(|(_, name)| *name)
    }
}

/// The differences of one side against the base side, on this input only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationDifferences {
    entries: Vec<ConfigurationDifference>,
    unchanged: usize,
}

impl ConfigurationDifferences {
    /// The differences, in input order.
    #[must_use]
    pub fn entries(&self) -> &[ConfigurationDifference] {
        &self.entries
    }

    /// How many findings correspond exactly and are identical in every
    /// attribute.
    #[must_use]
    pub const fn unchanged(&self) -> usize {
        self.unchanged
    }
}

/// The result of [`compare_configurations`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationComparison {
    sides: Vec<ConfigurationResult>,
    differences: Vec<Option<ConfigurationDifferences>>,
}

impl ConfigurationComparison {
    /// The sides, in the order supplied.
    #[must_use]
    pub fn sides(&self) -> &[ConfigurationResult] {
        &self.sides
    }

    /// One entry per side: `None` for the base side itself, and for a side
    /// where either it or the base failed.
    #[must_use]
    pub fn differences(&self) -> &[Option<ConfigurationDifferences>] {
        &self.differences
    }
}

/// Runs one independent detection pass per side over `input` and relates every
/// side to the first. See the [module documentation](self).
///
/// # Examples
///
/// ```
/// use redact_secret::{
///     ComparedPolicy, ConfigurationSide, DetectionSelection, DetectorRegistry,
///     compare_configurations,
/// };
///
/// let all = DetectorRegistry::with_built_in([])?;
/// let jwt_only = DetectorRegistry::with_built_in([])?
///     .with_detection(&DetectionSelection::include(["jwt"]))?;
/// let comparison = compare_configurations(
///     "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000",
///     &[
///         ConfigurationSide::new(&all, ComparedPolicy::Default),
///         ConfigurationSide::new(&jwt_only, ComparedPolicy::Default),
///     ],
/// )?;
/// assert_eq!(comparison.differences()[1].as_ref().unwrap().entries().len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// [`SecretScanErrorCode::InvalidOptions`] when `sides` is empty or holds more
/// than [`MAX_COMPARED_POLICIES`]; [`SecretScanErrorCode::PolicyFailure`] or
/// [`SecretScanErrorCode::InvalidPolicyAction`] when a callback fails, with no
/// partial result. Every other failure is a failed side, not an error.
pub fn compare_configurations(
    input: &str,
    sides: &[ConfigurationSide<'_>],
) -> Result<ConfigurationComparison, SecretScanError> {
    if sides.is_empty() || sides.len() > MAX_COMPARED_POLICIES {
        return Err(SecretScanErrorCode::InvalidOptions.into());
    }
    let mut results = Vec::with_capacity(sides.len());
    for side in sides {
        let scan = match side.registry {
            Err(code) => Err(code),
            Ok(registry) => {
                match compare_action_policies_with_limits(
                    input,
                    registry,
                    &[side.policy],
                    &side.limits,
                ) {
                    Ok(comparison) => Ok(comparison),
                    Err(error) => match error.code() {
                        SecretScanErrorCode::PolicyFailure
                        | SecretScanErrorCode::InvalidPolicyAction => return Err(error),
                        code => Err(code.as_str()),
                    },
                }
            }
        };
        results.push(ConfigurationResult {
            binding: binding_of(&side.policy),
            digests: side
                .digests
                .map(|(digest, detection)| (digest.to_owned(), detection.to_owned())),
            scan,
        });
    }
    let differences = results
        .iter()
        .enumerate()
        .map(|(index, side)| {
            (index > 0 && side.scan.is_ok() && results[0].scan.is_ok())
                .then(|| relate(results[0].findings(), side.findings()))
        })
        .collect();
    Ok(ConfigurationComparison {
        sides: results,
        differences,
    })
}

/// Groups both sides' findings into overlap clusters and relates each.
fn relate(base: &[ComparedFinding], other: &[ComparedFinding]) -> ConfigurationDifferences {
    // (start, end, is-other, position)
    let mut spans: Vec<(usize, usize, bool, usize)> = Vec::with_capacity(base.len() + other.len());
    for (is_other, side) in [(false, base), (true, other)] {
        for (position, compared) in side.iter().enumerate() {
            let range = compared.finding().range();
            spans.push((range.start(), range.end(), is_other, position));
        }
    }
    spans.sort_unstable();

    let mut entries = Vec::new();
    let mut unchanged = 0;
    let mut start = 0;
    while start < spans.len() {
        let mut end = spans[start].1;
        let mut stop = start + 1;
        while stop < spans.len() && spans[stop].0 < end {
            end = end.max(spans[stop].1);
            stop += 1;
        }
        let (mut left, mut right) = (Vec::new(), Vec::new());
        for &(_, _, is_other, position) in &spans[start..stop] {
            if is_other { &mut right } else { &mut left }.push(position);
        }
        start = stop;

        let kind = match (left.len(), right.len()) {
            (0, _) => DifferenceKind::Added,
            (_, 0) => DifferenceKind::Removed,
            (1, 1) => DifferenceKind::Changed,
            (1, _) => DifferenceKind::Split,
            (_, 1) => DifferenceKind::Merged,
            _ => DifferenceKind::Regrouped,
        };
        let changes = if kind == DifferenceKind::Changed {
            changed(&base[left[0]], &other[right[0]])
        } else {
            0
        };
        if kind == DifferenceKind::Changed && changes == 0 {
            unchanged += 1;
            continue;
        }
        // An added or removed cluster holds one finding per entry.
        let single = matches!(kind, DifferenceKind::Added | DifferenceKind::Removed);
        let members = if kind == DifferenceKind::Added {
            &right
        } else {
            &left
        };
        if single {
            for &position in members {
                let (base, other) = match kind {
                    DifferenceKind::Added => (vec![], vec![position]),
                    _ => (vec![position], vec![]),
                };
                entries.push(ConfigurationDifference {
                    kind,
                    base,
                    other,
                    changes,
                });
            }
        } else {
            entries.push(ConfigurationDifference {
                kind,
                base: left,
                other: right,
                changes,
            });
        }
    }
    ConfigurationDifferences { entries, unchanged }
}

/// The attribute bits (see [`CHANGE_NAMES`]) in which two findings differ.
fn changed(base: &ComparedFinding, other: &ComparedFinding) -> u8 {
    let (a, b) = (base.finding(), other.finding());
    let (x, y) = (&base.decisions()[0], &other.decisions()[0]);
    [
        a.range() != b.range(),
        a.type_name() != b.type_name(),
        a.detector() != b.detector(),
        a.confidence() != b.confidence(),
        x.action() != y.action(),
        x.basis() != y.basis(),
    ]
    .iter()
    .enumerate()
    .fold(0, |bits, (bit, differs)| bits | u8::from(*differs) << bit)
}
