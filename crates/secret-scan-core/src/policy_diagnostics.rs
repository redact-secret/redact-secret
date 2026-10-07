//! The optional diagnostic layer over an action policy document and the
//! resolved configuration (issue #1252, section 6 of
//! `decision-define-the-artifact-manifest-and-configuration-data-contracts`).
//!
//! # What this is, and is not
//!
//! The revision-1 parser ([`load_action_policy`](crate::load_action_policy))
//! is unchanged: it accepts any identifier as a `type` or `detector`, because
//! a custom, ruleset or future name is legitimate and a rule can only tighten
//! or loosen an action the base already protects. A typo therefore loads and
//! matches nothing. [`resolve_config`](crate::resolve_config) runs this layer
//! over a policy that loaded, with the artifact manifest and the resolved
//! enabled set, and reports what it can prove as `config-diagnostics/v1`
//! items. Nothing here rejects a policy, scans, or reads input.
//!
//! # What each name is
//!
//! A rule's `detector` is one of: enabled (silent), included but disabled
//! (`ACTION_POLICY_RULE_ON_UNENABLED_DETECTOR`), a `full` built-in this
//! artifact does not include (`ACTION_POLICY_RULE_ON_NOT_INCLUDED_DETECTOR`),
//! a supplied ruleset's detector (silent), or unknown
//! (`ACTION_POLICY_UNKNOWN_DETECTOR`). A rule's `type` is declared by an
//! enabled detector (silent), declared only by a disabled one (the
//! unenabled-detector code, naming that detector), undeclared
//! (`ACTION_POLICY_UNKNOWN_TYPE`), or undeclared while a ruleset or PII
//! selection could emit it, which is reported as uncertain
//! (`ACTION_POLICY_ANALYSIS_UNCERTAIN`, `info`) and never as a typo. A
//! detector's declared types are its reviewed list, not a closed vocabulary.
//!
//! Strictness exists only where the caller declares a closed vocabulary
//! ([`ConfigRequest::closed_types`](crate::ConfigRequest::closed_types),
//! [`closed_detectors`](crate::ConfigRequest::closed_detectors)): then an
//! unknown name is an error. A callback policy cannot be read, so it is
//! reported as uncertain.
//!
//! # What "shadowed" means
//!
//! A rule matches when every key it has holds (AND across keys), a key holds
//! when the finding's value is a member of its set (OR within a set), the
//! first matching rule decides, and `default` is a decision too: it stops
//! evaluation at that rule and returns the base. So rule `j` is
//! **shadowed** by an earlier rule `i` exactly when every finding rule `j`
//! matches, rule `i` also matches. That is provable from the two documents
//! alone when, key by key, `i` has no such key or `j` has it with a subset of
//! `i`'s members (a bit subset for `confidence` and `obfuscation`). The test
//! compares the documents' own strings and masks, so it holds under an open
//! vocabulary: an unknown or custom name is just a string that both rules
//! either list or do not. A rule that needs a key the earlier one lacks, a
//! partial overlap, a disjoint pair and a union of several earlier rules are
//! never reported. Only a single earlier rule is considered, so some real
//! shadowing is missed and no rule that can match is called unreachable.
//!
//! The analysis says nothing about whether a finding of a rule's type can
//! occur, so it never claims missed detection or coverage. Sample behavior is
//! kept apart in [`SampleRuleHits`]: a rule no sample hit is **not** dead, and
//! a hit does not make a rule reachable in general.

use crate::action_policy::{ActionPolicy, Rule};
use crate::compare::DecisionBasis;
use crate::config::{ConfigSeverity, Diagnostics};
use crate::manifest::ArtifactManifest;
use crate::selection::PII_ADAPTER_ID;

pub(crate) const UNKNOWN_TYPE: &str = "ACTION_POLICY_UNKNOWN_TYPE";
pub(crate) const UNKNOWN_DETECTOR: &str = "ACTION_POLICY_UNKNOWN_DETECTOR";
pub(crate) const UNENABLED_DETECTOR: &str = "ACTION_POLICY_RULE_ON_UNENABLED_DETECTOR";
pub(crate) const NOT_INCLUDED_DETECTOR: &str = "ACTION_POLICY_RULE_ON_NOT_INCLUDED_DETECTOR";
pub(crate) const SHADOWED_RULE: &str = "ACTION_POLICY_SHADOWED_RULE";
pub(crate) const UNCERTAIN: &str = "ACTION_POLICY_ANALYSIS_UNCERTAIN";

/// What the analysis needs to know about the resolved configuration.
pub(crate) struct Context<'a> {
    pub(crate) manifest: &'a ArtifactManifest,
    /// The enabled built-in ids.
    pub(crate) enabled: &'a [&'a str],
    /// The supplied ruleset's detector ids.
    pub(crate) ruleset_ids: &'a [String],
    pub(crate) ruleset_present: bool,
    pub(crate) pii_active: bool,
    pub(crate) closed_types: Option<&'a [&'a str]>,
    pub(crate) closed_detectors: Option<&'a [&'a str]>,
}

/// Reports every finding about `policy` into `out`, in document order.
pub(crate) fn analyze(policy: &ActionPolicy, context: &Context<'_>, out: &mut Diagnostics) {
    let rules = policy.rules();
    // Sorted views make each containment check linear in the two sets.
    let sorted: Vec<[Vec<&str>; 2]> = rules
        .iter()
        .map(|rule| [sorted_set(&rule.types), sorted_set(&rule.detectors)])
        .collect();
    for (index, rule) in rules.iter().enumerate() {
        for (position, name) in rule.types.iter().enumerate() {
            check_type(index, position, name, context, out);
        }
        for (position, name) in rule.detectors.iter().enumerate() {
            check_detector(index, position, name, context, out);
        }
        if let Some(earlier) =
            (0..index).find(|&i| shadows(&rules[i], rule, &sorted[i], &sorted[index]))
        {
            out.push_item(
                ConfigSeverity::Warning,
                SHADOWED_RULE,
                &format!("actionPolicy.rules[{index}]"),
                Some(&rule.id),
                Some(&format!("actionPolicy.rules[{earlier}]")),
            );
        }
    }
}

fn sorted_set(set: &[Box<str>]) -> Vec<&str> {
    let mut members: Vec<&str> = set.iter().map(|member| &**member).collect();
    members.sort_unstable();
    members.dedup();
    members
}

/// Whether every member of sorted `subset` is in sorted `superset`.
fn is_subset(subset: &[&str], superset: &[&str]) -> bool {
    let mut candidates = superset.iter();
    subset
        .iter()
        .all(|member| candidates.any(|candidate| candidate == member))
}

/// Whether `earlier` matches everything `later` matches. Each key of
/// `earlier` must be absent or hold a superset of `later`'s set; a key
/// `later` lacks matches every value, so `earlier` cannot cover it.
fn shadows(
    earlier: &Rule,
    later: &Rule,
    earlier_sets: &[Vec<&str>; 2],
    later_sets: &[Vec<&str>; 2],
) -> bool {
    let sets = [
        (earlier.types.is_empty(), later.types.is_empty(), 0),
        (earlier.detectors.is_empty(), later.detectors.is_empty(), 1),
    ];
    let masks = [
        (earlier.confidences, later.confidences),
        (earlier.obfuscations, later.obfuscations),
    ];
    sets.iter().all(|&(open, later_open, key)| {
        open || (!later_open && is_subset(&later_sets[key], &earlier_sets[key]))
    }) && masks
        .iter()
        .all(|&(outer, inner)| outer == 0 || (inner != 0 && inner & !outer == 0))
}

fn path(index: usize, key: &str, position: usize) -> String {
    format!("actionPolicy.rules[{index}].match.{key}[{position}]")
}

fn check_type(
    index: usize,
    position: usize,
    name: &str,
    context: &Context<'_>,
    out: &mut Diagnostics,
) {
    let declared_by = |wanted: bool| {
        context
            .manifest
            .declared_types()
            .find(|(id, types)| context.enabled.contains(id) == wanted && types.contains(&name))
            .map(|(id, _)| id)
    };
    if declared_by(true).is_some() {
        return;
    }
    let at = path(index, "type", position);
    if let Some(id) = declared_by(false) {
        out.push_item(
            ConfigSeverity::Warning,
            UNENABLED_DETECTOR,
            &at,
            Some(id),
            None,
        );
    } else if let Some(closed) = context.closed_types {
        if !closed.contains(&name) {
            out.push_item(ConfigSeverity::Error, UNKNOWN_TYPE, &at, None, None);
        }
    } else if context.ruleset_present || context.pii_active {
        // A ruleset or the PII adapter emits types no list names.
        out.push_item(ConfigSeverity::Info, UNCERTAIN, &at, None, None);
    } else {
        out.push_item(ConfigSeverity::Warning, UNKNOWN_TYPE, &at, None, None);
    }
}

fn check_detector(
    index: usize,
    position: usize,
    name: &str,
    context: &Context<'_>,
    out: &mut Diagnostics,
) {
    let at = path(index, "detector", position);
    let manifest = context.manifest;
    if context.enabled.contains(&name) || context.ruleset_ids.iter().any(|id| id == name) {
        return;
    }
    if let Some(id) = manifest.detector_ids().find(|id| *id == name) {
        out.push_item(
            ConfigSeverity::Warning,
            UNENABLED_DETECTOR,
            &at,
            Some(id),
            None,
        );
    } else if let Some(id) = manifest.not_included_ids().find(|id| *id == name) {
        out.push_item(
            ConfigSeverity::Warning,
            NOT_INCLUDED_DETECTOR,
            &at,
            Some(id),
            None,
        );
    } else if name == PII_ADAPTER_ID {
        if !context.pii_active {
            out.push_item(ConfigSeverity::Warning, UNENABLED_DETECTOR, &at, None, None);
        }
    } else if let Some(closed) = context.closed_detectors {
        if !closed.contains(&name) {
            out.push_item(ConfigSeverity::Error, UNKNOWN_DETECTOR, &at, None, None);
        }
    } else {
        out.push_item(ConfigSeverity::Warning, UNKNOWN_DETECTOR, &at, None, None);
    }
}

/// How often each rule of one policy was the deciding rule across a set of
/// sample findings.
///
/// This is evidence about **those samples**, kept apart from the static
/// analysis: a rule with no hit is not unreachable and not redundant, and a
/// rule with hits is not thereby proven reachable for other input. It holds
/// only counts, never a finding, range or value.
///
/// ```
/// use redact_secret::{DecisionBasis, SampleRuleHits, load_action_policy};
///
/// let policy = load_action_policy(
///     br#"{"actionPolicyRevision":1,"base":"default","rules":[
///         {"id":"a","match":{"type":["jwt"]},"action":"warn"}]}"#,
/// )?;
/// let mut hits = SampleRuleHits::for_policy(&policy);
/// hits.record(&DecisionBasis::NoRuleMatched);
/// assert_eq!(hits.rule_hits(), &[0]);
/// assert_eq!(hits.no_rule_matched(), 1);
/// assert_eq!(hits.unhit_rules().collect::<Vec<_>>(), vec![0]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampleRuleHits {
    counts: Vec<usize>,
    no_rule: usize,
}

impl SampleRuleHits {
    /// Zero hits for every rule of `policy`.
    #[must_use]
    pub fn for_policy(policy: &ActionPolicy) -> Self {
        Self {
            counts: vec![0; policy.rule_count()],
            no_rule: 0,
        }
    }

    /// Records the basis of one sample decision (from a comparison): a rule
    /// or rule-default decision counts for that rule, `NoRuleMatched` for the
    /// base; every other basis, and an index this policy does not have, is
    /// ignored.
    pub fn record(&mut self, basis: &DecisionBasis) {
        match basis {
            DecisionBasis::Rule { rule_index, .. }
            | DecisionBasis::RuleDefault { rule_index, .. } => {
                if let Some(count) = self.counts.get_mut(*rule_index) {
                    *count = count.saturating_add(1);
                }
            }
            DecisionBasis::NoRuleMatched => self.no_rule = self.no_rule.saturating_add(1),
            _ => {}
        }
    }

    /// Hits per rule, in document order.
    #[must_use]
    pub fn rule_hits(&self) -> &[usize] {
        &self.counts
    }

    /// Samples no rule matched, so the base decided.
    #[must_use]
    pub const fn no_rule_matched(&self) -> usize {
        self.no_rule
    }

    /// The indexes of rules no sample hit. Not a statement about reachability.
    pub fn unhit_rules(&self) -> impl Iterator<Item = usize> + '_ {
        self.counts
            .iter()
            .enumerate()
            .filter(|(_, count)| **count == 0)
            .map(|(index, _)| index)
    }
}

#[cfg(test)]
mod tests;
