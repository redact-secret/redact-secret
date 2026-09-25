//! Non-enforcing shadow comparison of the evidence scorer with the legacy
//! decision (issue #771,
//! `decision-freeze-the-shadow-evidence-score-and-confidence-contract`
//! sections 2, 5 and 8).
//!
//! The pipeline records one [`ShadowComparison`] per candidate that overlap
//! resolution selects, but only when a caller asks for it
//! (`crate::pipeline::detect`). Every public entry point asks for nothing, so
//! the scorer never runs on the public hot path and nothing here can reach a
//! `Finding`, an error, a placeholder, a policy input or a log. The legacy
//! `Confidence`, action, range and overlap weight are read, never written.
//!
//! [`shadow_evaluation_jsonl`] is the maintainer-local evaluation path: it
//! renders the comparisons of one input as JSON Lines for
//! `crates/secret-scan-core/examples/shadow_evaluation.rs`, which compiles
//! this source as its own crate (`docs/specs/engine.md`, "Maintainer-local
//! shadow evaluation"). A record holds identifiers from closed static sets,
//! integers, the detector id and candidate type, and the caller's record id.
//! It holds no part of the matched value, no substring, class run or hash of
//! it (ADR section 8).

use std::fmt::Write as _;

use super::aggregate::{
    EvidenceGroup, SHADOW_MODEL, ShadowAuthority, ShadowBand, ShadowEvidence, shadow_evidence,
};
use super::features::FEATURE_SCHEMA_VERSION;
use crate::error::SecretScanError;
use crate::limits::WholeInputLimits;
use crate::policy::default_action_for;
use crate::registry::DetectorRegistry;
use crate::types::{Action, ByteRange, Candidate, Confidence, Specificity};

/// Identity of the JSON Lines format [`shadow_evaluation_jsonl`] and
/// [`shadow_evaluation_header`] write. A change to a field, its meaning or a
/// reason code is a new identity.
pub(crate) const SHADOW_EVALUATION_FORMAT: &str = "redact-secret/shadow-evaluation/1";

/// Every reason code a comparison may carry, in the order a record lists
/// them. A closed static set (ADR section 8).
#[cfg(test)]
pub(crate) const REASON_CODES: [&str; 9] = [
    "deterministic-authority",
    "credential-context",
    "no-credential-context",
    "randomness-capped",
    "randomness-partial",
    "randomness-none",
    "strict-exclusion",
    "no-positive-evidence",
    "band-none",
];

/// What a hypothetical future promotion of the shadow band would do to the
/// legacy `Confidence`. Beta.9 applies none of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PromotionOutcome {
    /// The band is above the legacy `Confidence`.
    Promote,
    /// The band is below the legacy `Confidence` (`none` included).
    Demote,
    /// The band equals the legacy `Confidence`, or the scorer was not
    /// consulted.
    Preserve,
}

impl PromotionOutcome {
    /// The record's name for the outcome.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Demote => "demote",
            Self::Preserve => "preserve",
        }
    }

    /// The outcome of promoting `band` over `legacy`.
    #[must_use]
    pub(crate) fn of(band: ShadowBand, legacy: Confidence) -> Self {
        match band.cmp(&ShadowBand::of_confidence(legacy)) {
            std::cmp::Ordering::Greater => Self::Promote,
            std::cmp::Ordering::Less => Self::Demote,
            std::cmp::Ordering::Equal => Self::Preserve,
        }
    }
}

/// The name a record uses for a band.
#[must_use]
pub(crate) const fn band_name(band: ShadowBand) -> &'static str {
    match band {
        ShadowBand::None => "none",
        ShadowBand::Low => "low",
        ShadowBand::Medium => "medium",
        ShadowBand::High => "high",
    }
}

/// The name a record uses for an authority.
#[must_use]
const fn authority_name(authority: ShadowAuthority) -> &'static str {
    match authority {
        ShadowAuthority::Deterministic => "deterministic",
        ShadowAuthority::Statistical => "statistical",
    }
}

/// The legacy decision of one selected candidate next to its shadow evidence
/// result. Nothing here is applied to anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ShadowComparison {
    /// Zero-based index of the finding this candidate became, in the order
    /// the caller numbers findings (`finding-{index + 1}`).
    pub(crate) finding_index: usize,
    /// The finding's range, in UTF-8 bytes of the caller's input.
    pub(crate) range: ByteRange,
    /// The emitting detector's registered id.
    pub(crate) detector: String,
    /// The candidate's type.
    pub(crate) type_name: String,
    /// The candidate's effective specificity.
    pub(crate) specificity: Specificity,
    /// The legacy `Confidence`, as the finding carries it.
    pub(crate) legacy_confidence: Confidence,
    /// The default policy's action for the legacy finding.
    pub(crate) legacy_action: Action,
    /// The shadow evidence result.
    pub(crate) shadow: ShadowEvidence,
    /// What promoting `shadow.band` over the legacy `Confidence` would do.
    pub(crate) promotion: PromotionOutcome,
}

impl ShadowComparison {
    /// Evaluates `candidate`, whose matched text in the scan copy is `value`,
    /// under [`SHADOW_MODEL`]. `range` is where the finding lies in the
    /// caller's input.
    #[must_use]
    pub(crate) fn of(
        finding_index: usize,
        range: ByteRange,
        detector: &str,
        candidate: &Candidate,
        value: &str,
    ) -> Self {
        let shadow = shadow_evidence(&SHADOW_MODEL, candidate, value);
        let legacy_confidence = candidate.confidence();
        let promotion = match shadow.authority {
            ShadowAuthority::Deterministic => PromotionOutcome::Preserve,
            ShadowAuthority::Statistical => PromotionOutcome::of(shadow.band, legacy_confidence),
        };
        Self {
            finding_index,
            range,
            detector: detector.to_owned(),
            type_name: candidate.type_name().to_owned(),
            specificity: candidate.effective_specificity(),
            legacy_confidence,
            legacy_action: default_action_for(candidate.type_name(), legacy_confidence),
            shadow,
            promotion,
        }
    }

    /// Moves the comparison by `findings` findings and `bytes` bytes, for an
    /// incremental unit that starts after them.
    #[must_use]
    pub(crate) fn shifted(mut self, findings: usize, bytes: usize) -> Option<Self> {
        self.finding_index = self.finding_index.checked_add(findings)?;
        self.range = ByteRange::new(
            self.range.start().checked_add(bytes)?,
            self.range.end().checked_add(bytes)?,
        )?;
        Some(self)
    }

    /// The reason codes of this comparison: a subset of the closed set
    /// `REASON_CODES`, in that set's order.
    #[must_use]
    pub(crate) fn reasons(&self) -> Vec<&'static str> {
        let Some(explanation) = self.shadow.explanation else {
            return vec!["deterministic-authority"];
        };
        let group = |group: EvidenceGroup| explanation.groups[group as usize];
        let mut reasons = Vec::with_capacity(4);
        reasons.push(if group(EvidenceGroup::Contextual).contribution > 0 {
            "credential-context"
        } else {
            "no-credential-context"
        });
        let randomness = group(EvidenceGroup::Randomness);
        let randomness_cap = SHADOW_MODEL.groups[EvidenceGroup::Randomness as usize].cap;
        reasons.push(if randomness.contribution == 0 {
            "randomness-none"
        } else if randomness.contribution >= randomness_cap || randomness.is_capped() {
            "randomness-capped"
        } else {
            "randomness-partial"
        });
        if explanation.exclusion.is_some() {
            reasons.push("strict-exclusion");
        }
        if explanation.positive == 0 {
            reasons.push("no-positive-evidence");
        }
        if explanation.band == ShadowBand::None {
            reasons.push("band-none");
        }
        reasons
    }

    /// Appends this comparison as one JSON object and a newline, for the
    /// input the caller identifies as `input_id`. Fields are written in a
    /// fixed order, so equal comparisons render to equal bytes.
    pub(crate) fn write_jsonl(&self, input_id: &str, out: &mut String) {
        out.push_str("{\"record\":\"shadow-comparison\",\"input\":");
        push_json_string(out, input_id);
        let _ = write!(
            out,
            ",\"finding\":\"finding-{}\",\"start\":{},\"end\":{},\"byteLength\":{}",
            self.finding_index.saturating_add(1),
            self.range.start(),
            self.range.end(),
            self.range.len(),
        );
        out.push_str(",\"detector\":");
        push_json_string(out, &self.detector);
        out.push_str(",\"type\":");
        push_json_string(out, &self.type_name);
        let _ = write!(
            out,
            ",\"specificity\":\"{}\",\"legacyConfidence\":\"{}\",\"legacyAction\":\"{}\",\"authority\":\"{}\",\"model\":\"{}\",\"featureSchema\":\"{}\"",
            self.specificity.as_str(),
            self.legacy_confidence.as_str(),
            self.legacy_action.as_str(),
            authority_name(self.shadow.authority),
            SHADOW_MODEL.id,
            FEATURE_SCHEMA_VERSION,
        );
        match self.shadow.explanation {
            None => out.push_str(
                ",\"contextClass\":null,\"exclusion\":null,\"groups\":null,\"signals\":[],\"score\":null",
            ),
            Some(explanation) => {
                let _ = write!(
                    out,
                    ",\"contextClass\":\"{}\"",
                    explanation.context.as_str()
                );
                match explanation.exclusion {
                    Some(grammar) => {
                        let _ = write!(out, ",\"exclusion\":\"{}\"", grammar.as_str());
                    }
                    None => out.push_str(",\"exclusion\":null"),
                }
                out.push_str(",\"groups\":{");
                for (index, group) in explanation.groups.iter().enumerate() {
                    let separator = if index == 0 { "" } else { "," };
                    let _ = write!(
                        out,
                        "{separator}\"{}\":{}",
                        group.group.as_str(),
                        group.contribution
                    );
                }
                out.push_str("},\"signals\":[");
                let mut first = true;
                for group in &explanation.groups {
                    for signal in group.signals() {
                        let separator = if first { "" } else { "," };
                        first = false;
                        let _ = write!(
                            out,
                            "{separator}{{\"group\":\"{}\",\"signal\":\"{}\",\"points\":{}}}",
                            group.group.as_str(),
                            signal.signal,
                            signal.points
                        );
                    }
                }
                let _ = write!(
                    out,
                    "],\"positive\":{},\"negative\":{},\"score\":{}",
                    explanation.positive, explanation.negative, explanation.score
                );
            }
        }
        let _ = write!(
            out,
            ",\"band\":\"{}\",\"promotion\":\"{}\",\"reasons\":[",
            band_name(self.shadow.band),
            self.promotion.as_str()
        );
        for (index, reason) in self.reasons().iter().enumerate() {
            let separator = if index == 0 { "" } else { "," };
            let _ = write!(out, "{separator}\"{reason}\"");
        }
        out.push_str("]}\n");
    }
}

/// Appends `value` as a JSON string literal.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if u32::from(control) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// The first line of a maintainer-local evaluation: the format, product
/// version and scorer identities, the scoring artifact's `revision` and
/// `modelFingerprint` as the caller read them, and the detector profile.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "called only by examples/shadow_evaluation.rs, which compiles the core source as its own crate"
    )
)]
#[must_use]
pub(crate) fn shadow_evaluation_header(
    artifact_revision: u64,
    model_fingerprint: &str,
    profile: &str,
) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "{{\"record\":\"shadow-evaluation\",\"format\":\"{SHADOW_EVALUATION_FORMAT}\",\"productVersion\":\"{}\",\"model\":\"{}\",\"featureSchema\":\"{FEATURE_SCHEMA_VERSION}\",\"artifactRevision\":{artifact_revision},\"modelFingerprint\":",
        crate::VERSION,
        SHADOW_MODEL.id,
    );
    push_json_string(&mut out, model_fingerprint);
    out.push_str(",\"profile\":");
    push_json_string(&mut out, profile);
    out.push_str(",\"path\":\"whole-input\"}\n");
    out
}

/// The maintainer-local evaluation of one input (`docs/specs/engine.md`,
/// "Maintainer-local shadow evaluation").
///
/// Applies the default [`WholeInputLimits`] exactly as `crate::scan` does,
/// runs the same detection and overlap resolution, and returns one
/// `shadow-comparison` line per finding, ordered by input offset, or one
/// `shadow-error` line carrying only the sanitized error code. The legacy
/// findings are the ones `crate::scan` with `crate::DefaultPolicy` returns
/// for the same input and registry.
///
/// No public item reaches this function. Its only non-test caller is the
/// evaluation example, which compiles this source as its own crate, so the
/// core library's own build sees no caller.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "called only by examples/shadow_evaluation.rs, which compiles the core source as its own crate"
    )
)]
#[must_use]
pub(crate) fn shadow_evaluation_jsonl(
    input_id: &str,
    input: &str,
    registry: &DetectorRegistry,
) -> String {
    let mut out = String::new();
    match evaluate(input, registry) {
        Ok(comparisons) => {
            for comparison in &comparisons {
                comparison.write_jsonl(input_id, &mut out);
            }
        }
        Err(error) => {
            out.push_str("{\"record\":\"shadow-error\",\"input\":");
            push_json_string(&mut out, input_id);
            let _ = writeln!(out, ",\"code\":\"{}\"}}", error.code().as_str());
        }
    }
    out
}

/// The comparisons of `input` under the default whole-input limits.
fn evaluate(
    input: &str,
    registry: &DetectorRegistry,
) -> Result<Vec<ShadowComparison>, SecretScanError> {
    let limits = WholeInputLimits::default();
    limits.check_input(input)?;
    let mut comparisons = Vec::new();
    let detected = crate::pipeline::detect(input, registry, Some(&mut comparisons))?;
    limits.check_findings(detected.len())?;
    Ok(comparisons)
}

#[cfg(test)]
mod tests;
