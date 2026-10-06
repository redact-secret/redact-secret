//! Explaining and comparing action policies over one detection pass
//! (`decision-explain-and-compare-action-policies-over-one-detection-pass`).
//!
//! [`compare_action_policies`] runs detection **once**, with the registry's
//! own configuration, and then evaluates every supplied policy on the same
//! finalized findings. It is an observation: it never edits the input, never
//! produces placeholders, and takes no part in enforcement. The result says,
//! per finalized finding and per policy, which [`Action`] the policy chooses
//! and why ([`DecisionBasis`]), and names each policy's revision binding
//! ([`PolicyBinding`]) and the detection configuration ([`DetectionIdentity`])
//! as two separate facts.
//!
//! # What a comparison is not
//!
//! - It covers **finalized findings only**: the findings `scan` would return
//!   for this input and registry. An overlap loser, a candidate that never
//!   survived and a PII alternative the resolver suppressed are never inputs,
//!   so the result makes no claim about them and no claim of coverage.
//! - It is **not a rerun of detection per policy**. A policy cannot add,
//!   remove or reorder a finding, so one pass is exact for every policy.
//! - It is **not enforcement**. The enforcement path (`scan`, `redact`,
//!   `scan_and_redact`, an incremental session) is untouched.
//! - It carries **no plaintext**: no input byte, no matched value, no hash of
//!   either, no snippet, and no score. Every field is a fixed identifier, a
//!   count, a range, or a digest of the *policy document*.
//!
//! # Evaluation order and callbacks
//!
//! Policies are evaluated one side at a time, in the order supplied, each over
//! the findings in input order. A [`ComparedPolicy::Callback`] therefore sees
//! exactly the call sequence `scan` would give it: once per finalized finding,
//! in finding order, with the same [`PolicyContext`]. If a callback fails, the
//! whole comparison fails with [`SecretScanErrorCode::PolicyFailure`] at that
//! finding: no partial result is returned and no later finding or side is
//! evaluated. A declarative [`ActionPolicy`] and the [`ComparedPolicy::Default`]
//! side cannot fail.
//!
//! # Bounds
//!
//! The whole-input limits apply as they do for `scan`: the input byte bound is
//! checked before detection and the finding bound after it, each failing the
//! call with its existing code. At most [`MAX_COMPARED_POLICIES`] policies may
//! be compared, so a result holds at most `max_findings * 4` decisions.

use crate::action_policy::ActionPolicy;
use crate::error::{SecretScanError, SecretScanErrorCode};
use crate::limits::WholeInputLimits;
use crate::pipeline::detect_finalized;
use crate::policy::default_action_for;
use crate::registry::{BuiltInRegistry, DetectorRegistry, DetectorSet, Profile};
use crate::types::{Action, DetectedFinding, Policy, PolicyContext};

/// The most policies one comparison accepts (a baseline and three candidates).
pub const MAX_COMPARED_POLICIES: usize = 4;

/// One policy taking part in a comparison.
///
/// A callback is accepted so a caller can compare a legacy policy against a
/// declarative one; it is called exactly once per finalized finding, in
/// finding order, the way `scan` calls it, and its failure fails the whole
/// comparison. A declarative policy explains itself ([`DecisionBasis`]); a
/// callback cannot, because the library calls the supplied object and keeps no
/// revision of it.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum ComparedPolicy<'a> {
    /// The running artifact's default evaluation, with no document.
    Default,
    /// A loaded declarative action policy.
    ActionPolicy(&'a ActionPolicy),
    /// A legacy callback policy.
    Callback(&'a dyn Policy),
}

impl std::fmt::Debug for ComparedPolicy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Default => "ComparedPolicy::Default",
            Self::ActionPolicy(_) => "ComparedPolicy::ActionPolicy",
            Self::Callback(_) => "ComparedPolicy::Callback",
        })
    }
}

/// Why a policy chose an action for one finding.
///
/// Every field is a fixed identifier or an index: a rule id is the caller's
/// own identifier from the policy document (at most 64 bytes), never a byte of
/// the input.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecisionBasis {
    /// A rule matched and its fixed action decided.
    Rule {
        /// The matched rule's id.
        rule_id: String,
        /// The matched rule's zero-based position in the document.
        rule_index: usize,
    },
    /// A rule matched and its action is `default`: the action is the base
    /// (the running artifact's default) and evaluation stopped at this rule.
    RuleDefault {
        /// The matched rule's id.
        rule_id: String,
        /// The matched rule's zero-based position in the document.
        rule_index: usize,
    },
    /// No rule matched, so the action is the base (the running artifact's
    /// default evaluation).
    NoRuleMatched,
    /// The side is [`ComparedPolicy::Default`]: the default evaluation, with
    /// no document.
    DefaultPolicy,
    /// The side is a callback: the action is its return value and nothing
    /// more is known.
    Callback,
}

impl DecisionBasis {
    /// The fixed wire name: `"rule"`, `"rule-default"`, `"no-rule-matched"`,
    /// `"default-policy"` or `"callback"`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rule { .. } => "rule",
            Self::RuleDefault { .. } => "rule-default",
            Self::NoRuleMatched => "no-rule-matched",
            Self::DefaultPolicy => "default-policy",
            Self::Callback => "callback",
        }
    }

    /// The matched rule's id, for [`Self::Rule`] and [`Self::RuleDefault`].
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Self::Rule { rule_id, .. } | Self::RuleDefault { rule_id, .. } => Some(rule_id),
            _ => None,
        }
    }

    /// The matched rule's zero-based index, for [`Self::Rule`] and
    /// [`Self::RuleDefault`].
    #[must_use]
    pub const fn rule_index(&self) -> Option<usize> {
        match self {
            Self::Rule { rule_index, .. } | Self::RuleDefault { rule_index, .. } => {
                Some(*rule_index)
            }
            _ => None,
        }
    }
}

/// One policy's decision for one finding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ActionDecision {
    action: Action,
    basis: DecisionBasis,
}

impl ActionDecision {
    /// The action the policy chose.
    #[must_use]
    pub const fn action(&self) -> Action {
        self.action
    }

    /// Why the policy chose it.
    #[must_use]
    pub const fn basis(&self) -> &DecisionBasis {
        &self.basis
    }
}

/// What identifies a compared policy: the revision binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PolicyBinding {
    /// The default evaluation. It has no document; it evolves with the
    /// artifact, so a caller keying evidence to it records
    /// [`VERSION`](crate::VERSION) as well.
    Default,
    /// A declarative action policy, bound to the SHA-256 of its exact
    /// document bytes ([`ActionPolicy::document_sha256`]).
    ActionPolicy {
        /// The document digest.
        document_sha256: [u8; 32],
    },
    /// A callback. The library keeps no identity, hash or version of a
    /// callback, so none is reported.
    Callback,
}

impl PolicyBinding {
    /// The fixed wire name: `"default"`, `"action-policy"` or `"callback"`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ActionPolicy { .. } => "action-policy",
            Self::Callback => "callback",
        }
    }

    /// The document digest of a declarative policy.
    #[must_use]
    pub const fn document_sha256(&self) -> Option<[u8; 32]> {
        match self {
            Self::ActionPolicy { document_sha256 } => Some(*document_sha256),
            _ => None,
        }
    }

    /// [`Self::document_sha256`] as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn document_sha256_hex(&self) -> Option<String> {
        self.document_sha256()
            .map(|digest| crate::sha256::to_hex(&digest))
    }
}

/// How many findings a policy assigned to each action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ActionCounts {
    redact: usize,
    block: usize,
    warn: usize,
    allow: usize,
}

impl ActionCounts {
    /// The number of findings assigned `action`.
    #[must_use]
    pub const fn get(&self, action: Action) -> usize {
        match action {
            Action::Redact => self.redact,
            Action::Block => self.block,
            Action::Warn => self.warn,
            Action::Allow => self.allow,
        }
    }

    /// The number of findings assigned `redact`.
    #[must_use]
    pub const fn redact(&self) -> usize {
        self.redact
    }

    /// The number of findings assigned `block`.
    #[must_use]
    pub const fn block(&self) -> usize {
        self.block
    }

    /// The number of findings assigned `warn`.
    #[must_use]
    pub const fn warn(&self) -> usize {
        self.warn
    }

    /// The number of findings assigned `allow`.
    #[must_use]
    pub const fn allow(&self) -> usize {
        self.allow
    }

    fn add(&mut self, action: Action) {
        match action {
            Action::Redact => self.redact += 1,
            Action::Block => self.block += 1,
            Action::Warn => self.warn += 1,
            Action::Allow => self.allow += 1,
        }
    }
}

/// One compared policy: its revision binding and its action totals.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ComparedSide {
    binding: PolicyBinding,
    counts: ActionCounts,
}

impl ComparedSide {
    /// The policy's revision binding.
    #[must_use]
    pub const fn binding(&self) -> &PolicyBinding {
        &self.binding
    }

    /// How many findings the policy assigned to each action.
    #[must_use]
    pub const fn counts(&self) -> ActionCounts {
        self.counts
    }
}

/// The detection configuration the single pass ran under, identified apart
/// from every policy.
///
/// It names the registry's activation (profile and PII selection), not a
/// custom detector set: a caller who loaded a ruleset or registered detectors
/// keys that to its own identity (for a ruleset, a digest of its bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionIdentity {
    activation_identity: String,
    profile: Option<Profile>,
    detector_count: usize,
}

impl DetectionIdentity {
    /// The registry's canonical credentials/PII activation identity; empty for
    /// a registry assembled without a built-in profile.
    #[must_use]
    pub fn activation_identity(&self) -> &str {
        &self.activation_identity
    }

    /// The built-in profile, when the registry carries one.
    #[must_use]
    pub const fn profile(&self) -> Option<Profile> {
        self.profile
    }

    /// How many detectors the registry held.
    #[must_use]
    pub const fn detector_count(&self) -> usize {
        self.detector_count
    }
}

/// One finalized finding and every compared policy's decision for it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ComparedFinding {
    finding: DetectedFinding,
    decisions: Vec<ActionDecision>,
}

impl ComparedFinding {
    /// The finalized finding's safe metadata (the same value `scan` hands a
    /// policy). It carries no matched value.
    #[must_use]
    pub const fn finding(&self) -> &DetectedFinding {
        &self.finding
    }

    /// One decision per compared policy, in the order the policies were
    /// supplied.
    #[must_use]
    pub fn decisions(&self) -> &[ActionDecision] {
        &self.decisions
    }

    /// `true` when the compared policies do not all choose the same action.
    /// A different rule reaching the same action is not a difference.
    #[must_use]
    pub fn differs(&self) -> bool {
        self.decisions
            .windows(2)
            .any(|pair| pair[0].action != pair[1].action)
    }
}

/// The result of [`compare_action_policies`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionComparison {
    detection: DetectionIdentity,
    sides: Vec<ComparedSide>,
    findings: Vec<ComparedFinding>,
}

impl ActionComparison {
    /// The detection configuration of the single pass.
    #[must_use]
    pub const fn detection(&self) -> &DetectionIdentity {
        &self.detection
    }

    /// The compared policies, in the order supplied.
    #[must_use]
    pub fn sides(&self) -> &[ComparedSide] {
        &self.sides
    }

    /// The finalized findings in input order, each with its decisions.
    #[must_use]
    pub fn findings(&self) -> &[ComparedFinding] {
        &self.findings
    }

    /// How many findings the compared policies disagree on.
    #[must_use]
    pub fn changed_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.differs())
            .count()
    }
}

/// Runs detection once over `input` and evaluates every policy in `policies`
/// on the same finalized findings, under the default [`WholeInputLimits`].
///
/// See the [module documentation](self) for what a comparison covers and what
/// it does not.
///
/// # Examples
///
/// ```
/// use redact_secret::{
///     Action, ComparedPolicy, DetectorRegistry, compare_action_policies, load_action_policy,
/// };
///
/// let relaxed = load_action_policy(
///     br#"{"actionPolicyRevision":1,"base":"default","rules":[
///         {"id":"allow-github","match":{"type":["github_token"]},"action":"allow"}]}"#,
/// )?;
/// let registry = DetectorRegistry::with_built_in([])?;
/// let comparison = compare_action_policies(
///     "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000",
///     &registry,
///     &[ComparedPolicy::Default, ComparedPolicy::ActionPolicy(&relaxed)],
/// )?;
///
/// let finding = &comparison.findings()[0];
/// assert_eq!(finding.decisions()[0].action(), Action::Redact);
/// assert_eq!(finding.decisions()[1].action(), Action::Allow);
/// assert_eq!(finding.decisions()[1].basis().rule_id(), Some("allow-github"));
/// assert!(finding.differs());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// [`SecretScanErrorCode::InvalidOptions`] when `policies` is empty or holds
/// more than [`MAX_COMPARED_POLICIES`]; the detection errors `scan` reports;
/// [`SecretScanErrorCode::InputLimitExceeded`] and
/// [`SecretScanErrorCode::FindingLimitExceeded`] against the default limits;
/// and [`SecretScanErrorCode::PolicyFailure`] when a callback fails, with no
/// partial result.
pub fn compare_action_policies(
    input: &str,
    registry: &DetectorRegistry,
    policies: &[ComparedPolicy<'_>],
) -> Result<ActionComparison, SecretScanError> {
    compare_action_policies_with_limits(input, registry, policies, &WholeInputLimits::default())
}

/// Same as [`compare_action_policies`], against `limits` instead of the
/// default [`WholeInputLimits`].
///
/// # Errors
///
/// Every [`compare_action_policies`] error, checked against `limits`.
pub fn compare_action_policies_with_limits(
    input: &str,
    registry: &DetectorRegistry,
    policies: &[ComparedPolicy<'_>],
    limits: &WholeInputLimits,
) -> Result<ActionComparison, SecretScanError> {
    let detection = DetectionIdentity {
        activation_identity: registry.activation_identity().to_owned(),
        profile: registry.profile(),
        detector_count: registry.len(),
    };
    compare_in(input, registry, detection, policies, limits)
}

impl BuiltInRegistry {
    /// [`compare_action_policies`] over this registry.
    ///
    /// # Errors
    ///
    /// The errors [`compare_action_policies`] reports.
    pub fn compare_action_policies(
        &self,
        input: &str,
        policies: &[ComparedPolicy<'_>],
    ) -> Result<ActionComparison, SecretScanError> {
        self.compare_action_policies_with_limits(input, policies, &WholeInputLimits::default())
    }

    /// [`compare_action_policies_with_limits`] over this registry.
    ///
    /// # Errors
    ///
    /// The errors [`compare_action_policies_with_limits`] reports.
    pub fn compare_action_policies_with_limits(
        &self,
        input: &str,
        policies: &[ComparedPolicy<'_>],
        limits: &WholeInputLimits,
    ) -> Result<ActionComparison, SecretScanError> {
        let detection = DetectionIdentity {
            activation_identity: self.activation_identity().to_owned(),
            profile: Some(self.profile()),
            detector_count: self.len(),
        };
        compare_in(input, self, detection, policies, limits)
    }
}

/// One side's decision for one finding. The only place a side is evaluated, so
/// the comparison and the enforcement path share the action computation: a
/// declarative policy goes through [`ActionPolicy::explain`], the same function
/// its [`Policy`] implementation calls.
fn decide(
    policy: &ComparedPolicy<'_>,
    finding: &DetectedFinding,
    context: &PolicyContext,
) -> Result<ActionDecision, SecretScanError> {
    Ok(match policy {
        ComparedPolicy::Default => ActionDecision {
            action: default_action_for(finding.type_name(), finding.confidence()),
            basis: DecisionBasis::DefaultPolicy,
        },
        ComparedPolicy::ActionPolicy(document) => {
            let (action, basis) = document.explain(finding);
            ActionDecision { action, basis }
        }
        ComparedPolicy::Callback(callback) => ActionDecision {
            action: callback
                .evaluate(finding, context)
                .map_err(|_| SecretScanError::new(SecretScanErrorCode::PolicyFailure))?,
            basis: DecisionBasis::Callback,
        },
    })
}

fn binding_of(policy: &ComparedPolicy<'_>) -> PolicyBinding {
    match policy {
        ComparedPolicy::Default => PolicyBinding::Default,
        ComparedPolicy::ActionPolicy(document) => PolicyBinding::ActionPolicy {
            document_sha256: document.document_sha256(),
        },
        ComparedPolicy::Callback(_) => PolicyBinding::Callback,
    }
}

/// [`compare_action_policies_with_limits`] over any detector set; the one
/// implementation behind the [`DetectorRegistry`] function and the
/// [`BuiltInRegistry`] method.
pub(crate) fn compare_in<R: DetectorSet + ?Sized>(
    input: &str,
    registry: &R,
    detection: DetectionIdentity,
    policies: &[ComparedPolicy<'_>],
    limits: &WholeInputLimits,
) -> Result<ActionComparison, SecretScanError> {
    if policies.is_empty() || policies.len() > MAX_COMPARED_POLICIES {
        return Err(SecretScanError::new(SecretScanErrorCode::InvalidOptions));
    }
    let detected = detect_finalized(input, registry, limits)?;
    let finding_count = detected.len();

    // One side at a time, each over the findings in order: a callback sees the
    // exact call sequence `scan` gives it, and stops at its first failure.
    let mut sides = Vec::with_capacity(policies.len());
    let mut columns: Vec<std::vec::IntoIter<ActionDecision>> = Vec::with_capacity(policies.len());
    for policy in policies {
        let mut counts = ActionCounts::default();
        let mut column = Vec::with_capacity(finding_count);
        for (finding_index, finding) in detected.iter().enumerate() {
            let context = PolicyContext::new(finding_index, finding_count);
            let decision = decide(policy, finding, &context)?;
            counts.add(decision.action);
            column.push(decision);
        }
        sides.push(ComparedSide {
            binding: binding_of(policy),
            counts,
        });
        columns.push(column.into_iter());
    }

    let findings = detected
        .into_iter()
        .map(|finding| ComparedFinding {
            decisions: columns.iter_mut().filter_map(Iterator::next).collect(),
            finding,
        })
        .collect();
    Ok(ActionComparison {
        detection,
        sides,
        findings,
    })
}
