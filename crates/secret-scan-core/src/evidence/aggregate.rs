//! Grouped evidence aggregation with correlated-signal protection (issue
//! #770, `decision-freeze-the-shadow-evidence-score-and-confidence-contract`
//! sections 2 to 6).
//!
//! An [`AggregationModel`] is plain data: five evidence groups, each with a
//! list of [`SignalRule`]s, a [`GroupRule`] and a cap, plus integer band
//! thresholds. [`SHADOW_MODEL`] is the reviewed shadow configuration the
//! benchmark calibration selected (redact-secret-benchmarks#255). Its
//! invariants are checked at compile time ([`AggregationModel::violation`]),
//! so a model that breaks the contract does not build.
//!
//! [`shadow_evidence`] is the entry point: it never consults statistics for
//! a `private-key`, `provider` or `structural` candidate (ADR section 5), and
//! otherwise extracts the features of the value, evaluates every group and
//! returns the band with an [`EvidenceExplanation`] of how it was reached.
//!
//! Everything is integer arithmetic that saturates instead of wrapping and
//! rounds division toward zero (ADR section 7). Nothing here stores any part
//! of the value: the explanation carries identifiers from closed static sets
//! and integers only (ADR section 8). Nothing here changes a finding,
//! `Confidence`, overlap weight or action (ADR section 2); the functions take
//! the candidate by shared reference and return a separate value.

use super::context::{ContextClass, context_class_of};
use super::exclusion::{ExclusionGrammar, exclusion_grammar};
use super::features::{
    EvidenceFeatures, FEATURE_COUNT, FEATURE_NAMES, FEATURE_SCHEMA_VERSION, extract_features,
};
use crate::types::{Candidate, Confidence, Specificity};

/// An evidence group (ADR section 3). Every signal belongs to exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum EvidenceGroup {
    /// Shannon entropy, min-entropy, repetition and similar measurements.
    Randomness = 0,
    /// Length, alphabet and class distribution, shape.
    Lexical = 1,
    /// Credential-bearing name, header or surrounding syntax.
    Contextual = 2,
    /// Checksum, parser or known structural validation.
    Validation = 3,
    /// Whole-value exclusion grammars; subtracted.
    Negative = 4,
}

/// Number of [`EvidenceGroup`] variants.
pub(crate) const GROUP_COUNT: usize = 5;

impl EvidenceGroup {
    /// Every group, in [`AggregationModel::groups`] order.
    pub(crate) const ALL: [Self; GROUP_COUNT] = [
        Self::Randomness,
        Self::Lexical,
        Self::Contextual,
        Self::Validation,
        Self::Negative,
    ];

    /// The contract's name for the group.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Randomness => "randomness",
            Self::Lexical => "lexical",
            Self::Contextual => "contextual",
            Self::Validation => "validation",
            Self::Negative => "negative",
        }
    }

    /// Whether the group's contribution is subtracted.
    #[must_use]
    pub(crate) const fn is_negative(self) -> bool {
        matches!(self, Self::Negative)
    }
}

/// How one signal turns a candidate's evidence into non-negative integer
/// points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignalRule {
    /// An integer ramp over feature `feature` of [`EvidenceFeatures::to_vector`]:
    /// `0` when the feature is at most `lo`, `max` when it is at least `hi`,
    /// otherwise `floor(max * (x - lo) / (hi - lo))`.
    FeatureRamp {
        /// Index into [`FEATURE_NAMES`].
        feature: usize,
        /// The feature value at and below which the signal gives `0`.
        lo: u32,
        /// The feature value at and above which the signal gives `max`.
        hi: u32,
        /// The signal's largest contribution.
        max: u32,
    },
    /// `points` when the candidate's context class is one of `classes`,
    /// otherwise `0`.
    Context {
        /// The credential-bearing classes.
        classes: &'static [ContextClass],
        /// The contribution when the class matches.
        points: u32,
    },
    /// `points` when the whole value matches one of the strict exclusion
    /// grammars ([`exclusion_grammar`]), otherwise `0`.
    StrictExclusion {
        /// The contribution when a grammar matches.
        points: u32,
    },
}

impl SignalRule {
    /// The signal's identifier, from a closed static set: a feature name,
    /// `credential-context` or `strict-exclusion`.
    #[must_use]
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::FeatureRamp { feature, .. } => FEATURE_NAMES[feature],
            Self::Context { .. } => "credential-context",
            Self::StrictExclusion { .. } => "strict-exclusion",
        }
    }

    /// The signal's points for `inputs`.
    #[must_use]
    fn points(self, inputs: &ShadowInputs) -> u32 {
        match self {
            Self::FeatureRamp {
                feature,
                lo,
                hi,
                max,
            } => ramp(inputs.features.to_vector()[feature].1, lo, hi, max),
            Self::Context { classes, points } => {
                if contains_class(classes, inputs.context) {
                    points
                } else {
                    0
                }
            }
            Self::StrictExclusion { points } => {
                if inputs.exclusion.is_some() {
                    points
                } else {
                    0
                }
            }
        }
    }
}

/// `0` at or below `lo`, `max` at or above `hi`, otherwise
/// `floor(max * (x - lo) / (hi - lo))`. `u64` intermediates cannot overflow.
#[must_use]
pub(crate) fn ramp(x: u32, lo: u32, hi: u32, max: u32) -> u32 {
    if x <= lo {
        0
    } else if x >= hi {
        max
    } else {
        let scaled = u64::from(max) * u64::from(x - lo) / u64::from(hi - lo);
        // `scaled < max` because `x < hi`, so it always fits.
        u32::try_from(scaled).unwrap_or(max)
    }
}

const fn contains_class(classes: &[ContextClass], class: ContextClass) -> bool {
    let mut index = 0;
    while index < classes.len() {
        if classes[index] as u8 == class as u8 {
            return true;
        }
        index += 1;
    }
    false
}

/// How a group combines its signals. The contract has one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupRule {
    /// ADR section 3: sort the contributions in descending order and take
    /// `min(cap, c1 + (c2 >> 1) + (c3 >> 2) + ...)`, saturating.
    HalvingDiminishingReturns,
}

/// The most signals one group may hold, so an explanation fits in a
/// fixed-size array.
pub(crate) const MAX_GROUP_SIGNALS: usize = 4;

/// One group of an [`AggregationModel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GroupConfig {
    /// Which group this is.
    pub(crate) group: EvidenceGroup,
    /// How the signals combine.
    pub(crate) rule: GroupRule,
    /// The group's largest contribution.
    pub(crate) cap: u32,
    /// The group's signals, at most [`MAX_GROUP_SIGNALS`].
    pub(crate) signals: &'static [SignalRule],
}

/// Integer band cut-offs: `none < low <= ... < medium <= ... < high`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BandThresholds {
    /// The smallest evidence total that is `low`.
    pub(crate) low: u32,
    /// The smallest evidence total that is `medium`.
    pub(crate) medium: u32,
    /// The smallest evidence total that is `high`.
    pub(crate) high: u32,
}

/// A complete aggregation configuration. Every value is an integer or a
/// closed identifier, so the model can be recorded verbatim in a reviewed
/// scoring artifact (#798).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AggregationModel {
    /// Identity of these groups, signals, caps and thresholds (ADR section
    /// 10). Changing any value is a new identity.
    pub(crate) id: &'static str,
    /// The feature schema the [`SignalRule::FeatureRamp`] indices refer to.
    pub(crate) feature_schema: &'static str,
    /// One entry per [`EvidenceGroup`], in [`EvidenceGroup::ALL`] order.
    pub(crate) groups: [GroupConfig; GROUP_COUNT],
    /// Band cut-offs.
    pub(crate) bands: BandThresholds,
}

/// Index of `shannon_entropy_q16` in [`FEATURE_NAMES`].
pub(crate) const SHANNON_ENTROPY_FEATURE: usize = 5;

const PRODUCT_RANDOMNESS: [SignalRule; 1] = [SignalRule::FeatureRamp {
    feature: SHANNON_ENTROPY_FEATURE,
    lo: 254_345,
    hi: 313_536,
    max: 60,
}];

const CREDENTIAL_CONTEXT_CLASSES: [ContextClass; 3] = [
    ContextClass::CredentialName,
    ContextClass::AuthorizationHeader,
    ContextClass::UrlUserinfo,
];

const PRODUCT_CONTEXTUAL: [SignalRule; 1] = [SignalRule::Context {
    classes: &CREDENTIAL_CONTEXT_CLASSES,
    points: 40,
}];

const PRODUCT_NEGATIVE: [SignalRule; 1] = [SignalRule::StrictExclusion { points: 140 }];

/// The reviewed shadow configuration, as selected by the benchmark
/// calibration (redact-secret-benchmarks#255, merged at `101f674`). The
/// `validation` cap is a placeholder: no validation signal exists yet, so it
/// contributes `0` and was not fitted. None of these values is secret, and
/// security does not depend on them being unknown
/// (`docs/specs/engine.md`, "Shadow evidence aggregation").
pub(crate) const SHADOW_MODEL: AggregationModel = AggregationModel {
    id: "evidence-aggregation/v1",
    feature_schema: FEATURE_SCHEMA_VERSION,
    groups: [
        GroupConfig {
            group: EvidenceGroup::Randomness,
            rule: GroupRule::HalvingDiminishingReturns,
            cap: 60,
            signals: &PRODUCT_RANDOMNESS,
        },
        GroupConfig {
            group: EvidenceGroup::Lexical,
            rule: GroupRule::HalvingDiminishingReturns,
            cap: 0,
            signals: &[],
        },
        GroupConfig {
            group: EvidenceGroup::Contextual,
            rule: GroupRule::HalvingDiminishingReturns,
            cap: 40,
            signals: &PRODUCT_CONTEXTUAL,
        },
        GroupConfig {
            group: EvidenceGroup::Validation,
            rule: GroupRule::HalvingDiminishingReturns,
            cap: 40,
            signals: &[],
        },
        GroupConfig {
            group: EvidenceGroup::Negative,
            rule: GroupRule::HalvingDiminishingReturns,
            cap: 140,
            signals: &PRODUCT_NEGATIVE,
        },
    ],
    bands: BandThresholds {
        low: 7,
        medium: 43,
        high: 61,
    },
};

// ADR sections 2 and 3, checked when the crate compiles: a model that breaks
// one of them does not build.
const _: () = assert!(SHADOW_MODEL.violation().is_none());

impl AggregationModel {
    /// The first contract invariant this model breaks, or `None`:
    ///
    /// - `0 < t_low < t_medium < t_high`;
    /// - groups appear once each, in [`EvidenceGroup::ALL`] order;
    /// - every positive group's cap is below `t_high`;
    /// - `cap_randomness + cap_lexical < t_high`;
    /// - the negative group's cap is at least the sum of the positive caps,
    ///   so a strict exclusion match floors the total at `0`;
    /// - a group has at most [`MAX_GROUP_SIGNALS`] signals;
    /// - [`SignalRule::StrictExclusion`] appears in the negative group only,
    ///   and the negative group holds nothing else (ADR section 6);
    /// - [`SignalRule::Context`] appears in the contextual group only;
    /// - every ramp names a real feature and has `lo < hi`.
    #[must_use]
    pub(crate) const fn violation(&self) -> Option<&'static str> {
        let bands = self.bands;
        if !(0 < bands.low && bands.low < bands.medium && bands.medium < bands.high) {
            return Some("band thresholds must satisfy 0 < low < medium < high");
        }
        let mut positive_caps: u32 = 0;
        let mut index = 0;
        while index < GROUP_COUNT {
            let config = self.groups[index];
            if config.group as usize != index {
                return Some("groups must appear once each, in EvidenceGroup::ALL order");
            }
            if !config.group.is_negative() {
                if config.cap >= bands.high {
                    return Some("every positive group cap must be below t_high");
                }
                positive_caps = positive_caps.saturating_add(config.cap);
            }
            if config.signals.len() > MAX_GROUP_SIGNALS {
                return Some("a group has more than MAX_GROUP_SIGNALS signals");
            }
            let mut signal = 0;
            while signal < config.signals.len() {
                match config.signals[signal] {
                    SignalRule::FeatureRamp {
                        feature, lo, hi, ..
                    } => {
                        if feature >= FEATURE_COUNT || lo >= hi {
                            return Some("a feature ramp needs a real feature and lo < hi");
                        }
                        if config.group.is_negative() {
                            return Some("the negative group holds strict exclusion only");
                        }
                    }
                    SignalRule::Context { .. } => {
                        if config.group as usize != EvidenceGroup::Contextual as usize {
                            return Some("context signals belong to the contextual group");
                        }
                    }
                    SignalRule::StrictExclusion { .. } => {
                        if !config.group.is_negative() {
                            return Some("strict exclusion belongs to the negative group");
                        }
                    }
                }
                signal += 1;
            }
            index += 1;
        }
        let randomness = self.groups[EvidenceGroup::Randomness as usize].cap;
        let lexical = self.groups[EvidenceGroup::Lexical as usize].cap;
        if randomness.saturating_add(lexical) >= bands.high {
            return Some("cap_randomness + cap_lexical must be below t_high");
        }
        if self.groups[EvidenceGroup::Negative as usize].cap < positive_caps {
            return Some("the negative cap must cover every positive cap");
        }
        None
    }

    /// The band of an evidence total. A non-decreasing step function.
    #[must_use]
    pub(crate) const fn band(&self, total: u32) -> ShadowBand {
        if total >= self.bands.high {
            ShadowBand::High
        } else if total >= self.bands.medium {
            ShadowBand::Medium
        } else if total >= self.bands.low {
            ShadowBand::Low
        } else {
            ShadowBand::None
        }
    }
}

/// ADR section 3's within-group rule over `contributions` (reordered in
/// place): sorted descending, the `k`-th contribution (from `0`) counts
/// `c_k >> k`, the sum saturates and is capped at `cap`.
#[must_use]
pub(crate) fn halving_sum(contributions: &mut [u32], cap: u32) -> u32 {
    contributions.sort_unstable_by(|a, b| b.cmp(a));
    let mut total: u32 = 0;
    for (k, &contribution) in contributions.iter().enumerate() {
        let shifted = u32::try_from(k)
            .ok()
            .and_then(|k| contribution.checked_shr(k))
            .unwrap_or(0);
        total = total.saturating_add(shifted);
    }
    total.min(cap)
}

/// The proposed `Confidence` of the shadow scorer (ADR section 2). A
/// separate type from [`Confidence`], so it cannot reach a `Finding`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ShadowBand {
    /// Below `t_low`.
    None,
    /// At least `t_low`.
    Low,
    /// At least `t_medium`.
    Medium,
    /// At least `t_high`.
    High,
}

impl ShadowBand {
    /// The band a deterministic candidate records: its legacy `Confidence`.
    #[must_use]
    pub(crate) const fn of_confidence(confidence: Confidence) -> Self {
        match confidence {
            Confidence::Low => Self::Low,
            Confidence::Medium => Self::Medium,
            Confidence::High => Self::High,
        }
    }
}

/// Who decided the band (ADR section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ShadowAuthority {
    /// `private-key`, `provider` or `structural`: the scorer was not
    /// consulted and the band is the legacy `Confidence`.
    Deterministic,
    /// `contextual`, `entropy` or unset: the band comes from the evidence
    /// groups.
    Statistical,
}

/// Everything the scorer reads from one candidate. None of it is plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShadowInputs {
    /// The value's statistical features.
    pub(crate) features: EvidenceFeatures,
    /// The candidate's context class.
    pub(crate) context: ContextClass,
    /// The exclusion grammar the whole value matches, if any.
    pub(crate) exclusion: Option<ExclusionGrammar>,
}

impl ShadowInputs {
    /// Extracts the inputs from one candidate value and its context class.
    #[must_use]
    pub(crate) fn of_value(value: &str, context: ContextClass) -> Self {
        Self {
            features: extract_features(value),
            context,
            exclusion: exclusion_grammar(value),
        }
    }
}

/// One signal's points in an explanation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct SignalContribution {
    /// [`SignalRule::id`].
    pub(crate) signal: &'static str,
    /// The signal's points before the group rule.
    pub(crate) points: u32,
}

/// One group's part of an explanation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GroupContribution {
    /// Which group.
    pub(crate) group: EvidenceGroup,
    /// Every signal's points, in the model's signal order; the first
    /// `signal_count` entries are meaningful.
    pub(crate) signals: [SignalContribution; MAX_GROUP_SIGNALS],
    /// Number of meaningful entries in `signals`.
    pub(crate) signal_count: usize,
    /// The halving sum before the cap.
    pub(crate) uncapped: u32,
    /// The group's contribution after the cap.
    pub(crate) contribution: u32,
}

impl GroupContribution {
    /// The meaningful signal entries.
    #[must_use]
    pub(crate) fn signals(&self) -> &[SignalContribution] {
        &self.signals[..self.signal_count]
    }

    /// Whether the cap reduced the group's contribution.
    #[must_use]
    pub(crate) const fn is_capped(&self) -> bool {
        self.uncapped > self.contribution
    }
}

/// How a statistical shadow band was reached, for maintainers (ADR section
/// 8). Group and signal identifiers, integers, the context class and the
/// exclusion grammar; never any part of the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EvidenceExplanation {
    /// [`AggregationModel::id`].
    pub(crate) model: &'static str,
    /// One entry per group, in [`EvidenceGroup::ALL`] order.
    pub(crate) groups: [GroupContribution; GROUP_COUNT],
    /// The context class the contextual group read.
    pub(crate) context: ContextClass,
    /// The exclusion grammar the negative group read.
    pub(crate) exclusion: Option<ExclusionGrammar>,
    /// Sum of the positive group contributions, saturating.
    pub(crate) positive: u32,
    /// The negative group's contribution.
    pub(crate) negative: u32,
    /// The evidence score: `max(0, positive - negative)`. Ordinal and
    /// unitless, never a probability (ADR section 1).
    pub(crate) score: u32,
    /// `model.band(score)`.
    pub(crate) band: ShadowBand,
}

impl EvidenceExplanation {
    /// The groups whose contribution is non-zero.
    pub(crate) fn contributing_groups(&self) -> impl Iterator<Item = EvidenceGroup> + '_ {
        self.groups
            .iter()
            .filter(|group| group.contribution > 0)
            .map(|group| group.group)
    }
}

/// The shadow evidence result of one candidate (ADR section 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShadowEvidence {
    /// Who decided the band.
    pub(crate) authority: ShadowAuthority,
    /// The proposed `Confidence`. Recorded only; never applied in beta.9.
    pub(crate) band: ShadowBand,
    /// How a statistical band was reached; `None` for a deterministic one.
    pub(crate) explanation: Option<EvidenceExplanation>,
}

/// Evaluates every group of `model` on `inputs` (ADR sections 3 and 4).
#[must_use]
pub(crate) fn aggregate(model: &AggregationModel, inputs: &ShadowInputs) -> EvidenceExplanation {
    let empty = GroupContribution {
        group: EvidenceGroup::Randomness,
        signals: [SignalContribution::default(); MAX_GROUP_SIGNALS],
        signal_count: 0,
        uncapped: 0,
        contribution: 0,
    };
    let mut groups = [empty; GROUP_COUNT];
    let mut positive: u32 = 0;
    let mut negative: u32 = 0;
    for (slot, config) in groups.iter_mut().zip(model.groups) {
        let mut points = [0_u32; MAX_GROUP_SIGNALS];
        let mut explained = [SignalContribution::default(); MAX_GROUP_SIGNALS];
        let count = config.signals.len().min(MAX_GROUP_SIGNALS);
        for ((rule, point), entry) in config.signals[..count]
            .iter()
            .zip(points.iter_mut())
            .zip(explained.iter_mut())
        {
            *point = rule.points(inputs);
            *entry = SignalContribution {
                signal: rule.id(),
                points: *point,
            };
        }
        let uncapped = match config.rule {
            GroupRule::HalvingDiminishingReturns => halving_sum(&mut points[..count], u32::MAX),
        };
        let contribution = uncapped.min(config.cap);
        if config.group.is_negative() {
            negative = negative.saturating_add(contribution);
        } else {
            positive = positive.saturating_add(contribution);
        }
        *slot = GroupContribution {
            group: config.group,
            signals: explained,
            signal_count: count,
            uncapped,
            contribution,
        };
    }
    let score = positive.saturating_sub(negative);
    EvidenceExplanation {
        model: model.id,
        groups,
        context: inputs.context,
        exclusion: inputs.exclusion,
        positive,
        negative,
        score,
        band: model.band(score),
    }
}

/// The shadow evidence result of `candidate`, whose matched text is `value`
/// (ADR sections 2 and 5).
///
/// A `private-key`, `provider` or `structural` candidate is deterministic:
/// no feature of `value` is even extracted, and the band is the legacy
/// `Confidence`. Any other candidate is evaluated by `model`.
#[must_use]
pub(crate) fn shadow_evidence(
    model: &AggregationModel,
    candidate: &Candidate,
    value: &str,
) -> ShadowEvidence {
    match candidate.effective_specificity() {
        Specificity::PrivateKey | Specificity::Provider | Specificity::Structural => {
            ShadowEvidence {
                authority: ShadowAuthority::Deterministic,
                band: ShadowBand::of_confidence(candidate.confidence()),
                explanation: None,
            }
        }
        Specificity::Contextual | Specificity::Entropy => {
            let inputs = ShadowInputs::of_value(value, context_class_of(candidate));
            let explanation = aggregate(model, &inputs);
            ShadowEvidence {
                authority: ShadowAuthority::Statistical,
                band: explanation.band,
                explanation: Some(explanation),
            }
        }
    }
}

#[cfg(test)]
mod tests;
