//! A user policy sees only the finalized overlap winner (issue #1218).
//!
//! `decision-resolve-overlap-precedence-by-resolved-action-severity` ranks
//! overlapping candidates with the crate's fixed default classification and
//! applies the caller's policy only to the surviving findings. These tests
//! pin that scope ("option A") with a user policy that gives the overlap
//! *loser* a stricter action than the winner, and with the inverse policy,
//! across whole-input and incremental runs and many partitions.
//!
//! Two layers:
//!
//! - Whole input, synthetic detectors: equal-range, containment (both
//!   orientations) and partial-overlap shapes, in both registration orders.
//!   An incremental session cannot take a custom detector, so this layer is
//!   whole-input only.
//! - Whole input and incremental, built-in detectors: the committed
//!   `newrelic Authorization: Bearer <value>` shape, where `bearer_token`
//!   (default `Redact`) beats `new_relic_license_key` (default `Warn`).
//!
//! Every input is synthetic; no test embeds a credential-shaped value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::cell::RefCell;
use std::rc::Rc;

use redact_secret::{
    Action, ByteRange, Candidate, Confidence, DefaultPolicy, DetectedFinding, Detector,
    DetectorContext, DetectorFailure, DetectorRegistry, IncrementalPolicy,
    IncrementalPolicyContext, IncrementalSanitizer, Policy, PolicyContext, PolicyFailure,
    SecretScanErrorCode, SessionState, Specificity, WholeInputLimits,
    default_placeholder_formatter, scan, scan_and_redact, scan_with_limits,
};

// ---------------------------------------------------------------------------
// synthetic equal-range / containment / partial-overlap shapes
// ---------------------------------------------------------------------------

/// The anchor both synthetic detectors key on. Unmistakably synthetic.
const ANCHOR: &str = "SYNTHETIC_REVOKED_OVERLAP_ANCHOR";
const WINNER: &str = "overlap_winner";
const LOSER: &str = "overlap_loser";

/// Reports one candidate at `[from, to)` relative to the anchor.
struct Shaped {
    id: &'static str,
    type_name: &'static str,
    confidence: Confidence,
    specificity: Specificity,
    from: usize,
    to: usize,
}

impl Detector for Shaped {
    fn id(&self) -> &str {
        self.id
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(input
            .match_indices(ANCHOR)
            .filter_map(|(start, _)| {
                ByteRange::new(start + self.from, start + self.to).map(|range| {
                    Candidate::new(self.type_name, self.confidence, range)
                        .with_specificity(self.specificity)
                })
            })
            .collect())
    }
}

/// One overlap shape: the winner's and loser's relative spans.
struct Shape {
    label: &'static str,
    winner: (usize, usize),
    loser: (usize, usize),
}

fn shapes() -> Vec<Shape> {
    let n = ANCHOR.len();
    vec![
        Shape {
            label: "equal range",
            winner: (0, n),
            loser: (0, n),
        },
        Shape {
            label: "winner contains loser",
            winner: (0, n),
            loser: (6, n - 6),
        },
        Shape {
            label: "loser contains winner",
            winner: (6, n - 6),
            loser: (0, n),
        },
        Shape {
            label: "partial overlap, winner first",
            winner: (0, 20),
            loser: (10, n),
        },
        Shape {
            label: "partial overlap, loser first",
            winner: (10, n),
            loser: (0, 20),
        },
    ]
}

/// The winner is `High` confidence (default `Redact`); the loser is `Medium`
/// (default `Warn`) but `Provider` specific, so only the fixed
/// resolved-action-severity key can make the winner win.
fn registry(shape: &Shape, winner_registered_first: bool) -> DetectorRegistry {
    let winner = Shaped {
        id: "winner-detector",
        type_name: WINNER,
        confidence: Confidence::High,
        specificity: Specificity::Contextual,
        from: shape.winner.0,
        to: shape.winner.1,
    };
    let loser = Shaped {
        id: "loser-detector",
        type_name: LOSER,
        confidence: Confidence::Medium,
        specificity: Specificity::Provider,
        from: shape.loser.0,
        to: shape.loser.1,
    };
    let mut registry = DetectorRegistry::new();
    if winner_registered_first {
        registry.register(Box::new(winner)).unwrap();
        registry.register(Box::new(loser)).unwrap();
    } else {
        registry.register(Box::new(loser)).unwrap();
        registry.register(Box::new(winner)).unwrap();
    }
    registry
}

/// Everything a recording policy was handed, in call order.
type Calls = Rc<RefCell<Vec<(String, usize, usize)>>>;

/// A user policy keyed on type: `winner_action` for [`WINNER`],
/// `loser_action` for [`LOSER`]. Records every call.
fn recording_policy(
    calls: &Calls,
    winner_action: Action,
    loser_action: Action,
) -> impl Fn(&DetectedFinding, &PolicyContext) -> Result<Action, PolicyFailure> + use<> {
    let calls = Rc::clone(calls);
    move |finding, context| {
        calls.borrow_mut().push((
            finding.type_name().to_string(),
            context.finding_index(),
            context.finding_count(),
        ));
        Ok(if finding.type_name() == WINNER {
            winner_action
        } else {
            loser_action
        })
    }
}

#[test]
fn a_user_policy_never_changes_which_overlap_candidate_wins() {
    let input = format!("prefix {ANCHOR} suffix");
    let offset = "prefix ".len();
    // (winner action, loser action): the loser is stricter in the first two
    // rows, the winner stricter in the last two.
    let policies = [
        (Action::Allow, Action::Block),
        (Action::Warn, Action::Redact),
        (Action::Block, Action::Allow),
        (Action::Redact, Action::Warn),
    ];
    for shape in shapes() {
        for winner_first in [true, false] {
            let registry = registry(&shape, winner_first);
            let label = format!("{} (winner registered first: {winner_first})", shape.label);

            let default = scan(&input, &registry, &DefaultPolicy).unwrap();
            assert_eq!(default.len(), 1, "{label}: default findings {default:?}");
            assert_eq!(default[0].type_name(), WINNER, "{label}: default winner");
            let winner_range = ByteRange::new(offset + shape.winner.0, offset + shape.winner.1)
                .expect("winner span");
            assert_eq!(default[0].range(), winner_range, "{label}: winner range");
            assert_eq!(default[0].action(), Action::Redact, "{label}");

            for (winner_action, loser_action) in policies {
                let calls: Calls = Rc::default();
                let policy = recording_policy(&calls, winner_action, loser_action);
                let found = scan(&input, &registry, &policy).unwrap();

                // Same winner and range as under the default policy.
                assert_eq!(found.len(), 1, "{label}: {found:?}");
                assert_eq!(found[0].type_name(), WINNER, "{label}: winner");
                assert_eq!(found[0].range(), winner_range, "{label}: range");
                // The winner takes the winner's action, even when the loser
                // would have been stricter.
                assert_eq!(found[0].action(), winner_action, "{label}: action");
                // The callback saw exactly the finalized winner, once, with
                // the finalized count, and never the loser.
                assert_eq!(
                    *calls.borrow(),
                    vec![(WINNER.to_string(), 0, 1)],
                    "{label}: policy calls"
                );
            }
        }
    }
}

#[test]
fn the_loser_remainder_is_not_redacted_when_the_winner_is_allowed() {
    // Policy `Allow` on the winner and `Block` on the loser: nothing is
    // enforced, and the text is returned unchanged. This is the documented
    // scope limit: the stricter loser rule never fires.
    let input = format!("prefix {ANCHOR} suffix");
    for shape in shapes() {
        let registry = registry(&shape, true);
        let calls: Calls = Rc::default();
        let policy = recording_policy(&calls, Action::Allow, Action::Block);
        let result =
            scan_and_redact(&input, &registry, &policy, &default_placeholder_formatter).unwrap();
        assert_eq!(result.text(), input, "{}: allowed text", shape.label);
        assert_eq!(result.findings().len(), 1, "{}", shape.label);
    }
}

#[test]
fn only_the_winner_range_is_replaced_when_the_winner_blocks_and_the_loser_is_allowed() {
    let input = format!("prefix {ANCHOR} suffix");
    let offset = "prefix ".len();
    for shape in shapes() {
        let registry = registry(&shape, true);
        let calls: Calls = Rc::default();
        let policy = recording_policy(&calls, Action::Block, Action::Allow);
        let result =
            scan_and_redact(&input, &registry, &policy, &default_placeholder_formatter).unwrap();
        let expected = format!(
            "{}<SECRET_1>{}",
            &input[..offset + shape.winner.0],
            &input[offset + shape.winner.1..],
        );
        assert_eq!(result.text(), expected, "{}: replaced text", shape.label);
        assert_eq!(result.findings()[0].action(), Action::Block);
    }
}

#[test]
fn a_policy_that_fails_only_on_the_loser_type_never_fails() {
    // The loser never reaches the callback, so a policy that errors on its
    // type is unobservable. A policy that errors on the winner type does fail.
    let input = format!("prefix {ANCHOR} suffix");
    let registry = registry(&shapes()[3], true);
    let fail_on = |type_name: &'static str| {
        move |finding: &DetectedFinding, _: &PolicyContext| {
            if finding.type_name() == type_name {
                Err(PolicyFailure)
            } else {
                Ok(Action::Redact)
            }
        }
    };
    assert!(scan(&input, &registry, &fail_on(LOSER)).is_ok());
    let error = scan(&input, &registry, &fail_on(WINNER)).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::PolicyFailure);
}

#[test]
fn a_registry_holding_only_the_loser_detector_reports_it_independently() {
    // The supported way to enforce the loser's rule today: scan the same
    // input with a registry that does not contain the winner. Each scan is
    // its own arbitration, so the two finding sets overlap by design and the
    // host merges them.
    let input = format!("prefix {ANCHOR} suffix");
    let shape = &shapes()[3];
    let mut loser_only = DetectorRegistry::new();
    loser_only
        .register(Box::new(Shaped {
            id: "loser-detector",
            type_name: LOSER,
            confidence: Confidence::Medium,
            specificity: Specificity::Provider,
            from: shape.loser.0,
            to: shape.loser.1,
        }))
        .unwrap();
    let calls: Calls = Rc::default();
    let policy = recording_policy(&calls, Action::Allow, Action::Block);
    let found = scan(&input, &loser_only, &policy).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].type_name(), LOSER);
    assert_eq!(found[0].action(), Action::Block);
    assert_eq!(*calls.borrow(), vec![(LOSER.to_string(), 0, 1)]);

    // The full registry still reports only the winner for the same input.
    let both = registry(shape, true);
    let merged = scan(&input, &both, &policy).unwrap();
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].type_name(), WINNER);
}

#[test]
fn the_finding_limit_counts_finalized_findings_not_overlap_candidates() {
    // Two candidates overlap into one finding; a limit of one finding holds.
    let input = format!("prefix {ANCHOR} suffix");
    let registry = registry(&shapes()[3], true);
    let limits = WholeInputLimits::new(1024, 1).unwrap();
    let found = scan_with_limits(&input, &registry, &DefaultPolicy, &limits).unwrap();
    assert_eq!(found.len(), 1);

    // Two separate clusters are two findings and exceed it, before any
    // policy call.
    let two = format!("{input}\n{input}");
    let calls: Calls = Rc::default();
    let policy = recording_policy(&calls, Action::Redact, Action::Redact);
    let error = scan_with_limits(&two, &registry, &policy, &limits).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::FindingLimitExceeded);
    assert!(
        calls.borrow().is_empty(),
        "the limit is checked before the policy runs"
    );
}

#[test]
fn policy_calls_follow_finalized_order_across_clusters() {
    let input = format!("{ANCHOR}\n{ANCHOR}\n{ANCHOR}");
    let registry = registry(&shapes()[4], false);
    let calls: Calls = Rc::default();
    let policy = recording_policy(&calls, Action::Allow, Action::Block);
    let found = scan(&input, &registry, &policy).unwrap();
    assert_eq!(found.len(), 3);
    assert_eq!(
        *calls.borrow(),
        vec![
            (WINNER.to_string(), 0, 3),
            (WINNER.to_string(), 1, 3),
            (WINNER.to_string(), 2, 3),
        ],
    );
    assert!(
        found
            .windows(2)
            .all(|pair| { pair[0].range().end() <= pair[1].range().start() })
    );
}

// ---------------------------------------------------------------------------
// built-in overlap, whole input and incremental
// ---------------------------------------------------------------------------

/// `bearer_token` (default `Redact`) beats `new_relic_license_key` (default
/// `Warn`) here; see `bearer_token_overlap_winner_redacts_the_new_relic_
/// license_key_shape` in `detectors_conformance.rs`.
const BEARER_OVER_NEW_RELIC: &str =
    "newrelic Authorization: Bearer 0123456789abcdef0123456789abcdef01234567";
const BEARER_VALUE: &str = "0123456789abcdef0123456789abcdef01234567";
const BEARER: &str = "bearer_token";
const NEW_RELIC: &str = "new_relic_license_key";

/// One user policy for both APIs, keyed on type, recording `(type, index)`.
#[derive(Clone)]
struct UserPolicy {
    bearer: Action,
    new_relic: Action,
    calls: Rc<RefCell<Vec<(String, usize)>>>,
}

impl UserPolicy {
    fn new(bearer: Action, new_relic: Action) -> Self {
        Self {
            bearer,
            new_relic,
            calls: Rc::default(),
        }
    }

    fn choose(&self, finding: &DetectedFinding, index: usize) -> Action {
        self.calls
            .borrow_mut()
            .push((finding.type_name().to_string(), index));
        if finding.type_name() == BEARER {
            self.bearer
        } else {
            self.new_relic
        }
    }
}

impl Policy for UserPolicy {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        Ok(self.choose(finding, context.finding_index()))
    }
}

impl IncrementalPolicy for UserPolicy {
    fn evaluate(
        &self,
        finding: &DetectedFinding,
        context: &IncrementalPolicyContext,
    ) -> Result<Action, PolicyFailure> {
        Ok(self.choose(finding, context.finding_index()))
    }
}

/// Runs one incremental session over `chunks`; returns the concatenated text
/// and findings.
fn incremental(chunks: &[&str], policy: &UserPolicy) -> (String, Vec<redact_secret::Finding>) {
    let mut sanitizer = IncrementalSanitizer::with_policy_and_formatter(
        support::generous_limits(),
        Box::new(policy.clone()),
        Box::new(default_placeholder_formatter),
    )
    .unwrap();
    let mut text = String::new();
    let mut findings = Vec::new();
    for chunk in chunks {
        let (part, found) = sanitizer.append(chunk).unwrap().into_parts();
        text.push_str(&part);
        findings.extend(found);
    }
    let (part, found) = sanitizer.finalize().unwrap().into_parts();
    text.push_str(&part);
    findings.extend(found);
    assert_eq!(sanitizer.state(), SessionState::Finalized);
    (text, findings)
}

fn whole(input: &str, policy: &UserPolicy) -> (String, Vec<redact_secret::Finding>) {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    scan_and_redact(input, &registry, policy, &default_placeholder_formatter)
        .unwrap()
        .into_parts()
}

/// Both orientations of the user policy: the loser stricter, then the winner
/// stricter.
fn policy_cases() -> [(Action, Action, &'static str); 2] {
    [
        (Action::Allow, Action::Block, "loser stricter"),
        (Action::Block, Action::Allow, "winner stricter"),
    ]
}

#[test]
fn whole_input_policy_sees_only_the_bearer_winner_and_enforces_its_action() {
    for (bearer, new_relic, label) in policy_cases() {
        let policy = UserPolicy::new(bearer, new_relic);
        let (text, findings) = whole(BEARER_OVER_NEW_RELIC, &policy);

        assert_eq!(findings.len(), 1, "{label}");
        assert_eq!(findings[0].type_name(), BEARER, "{label}");
        assert_eq!(findings[0].action(), bearer, "{label}");
        assert_eq!(*policy.calls.borrow(), [(BEARER.to_string(), 0)], "{label}");
        if bearer == Action::Allow {
            // The stricter loser rule never fires: the value stays in clear.
            assert_eq!(text, BEARER_OVER_NEW_RELIC, "{label}");
            assert!(text.contains(BEARER_VALUE));
        } else {
            assert_eq!(text, "newrelic Authorization: Bearer <SECRET_1>", "{label}");
        }
    }
}

#[test]
fn every_two_chunk_utf8_partition_matches_whole_input_under_a_user_policy() {
    for (bearer, new_relic, label) in policy_cases() {
        let reference_policy = UserPolicy::new(bearer, new_relic);
        let (expected_text, expected) = whole(BEARER_OVER_NEW_RELIC, &reference_policy);

        let mut partitions = 0;
        for split in 0..=BEARER_OVER_NEW_RELIC.len() {
            let (head, tail) = BEARER_OVER_NEW_RELIC.split_at(split);
            let policy = UserPolicy::new(bearer, new_relic);
            let (text, findings) = incremental(&[head, tail], &policy);
            let at = format!("{label}, split {split}");

            assert_eq!(text, expected_text, "{at}: text");
            assert_eq!(findings, expected, "{at}: findings");
            // Exactly once, after final, and only the winner.
            assert_eq!(
                *policy.calls.borrow(),
                [(BEARER.to_string(), 0)],
                "{at}: policy calls"
            );
            partitions += 1;
        }
        assert_eq!(partitions, BEARER_OVER_NEW_RELIC.len() + 1);
    }
}

#[test]
fn a_one_byte_per_chunk_session_matches_whole_input_under_a_user_policy() {
    for (bearer, new_relic, label) in policy_cases() {
        let (expected_text, expected) =
            whole(BEARER_OVER_NEW_RELIC, &UserPolicy::new(bearer, new_relic));
        let bytes: Vec<String> = BEARER_OVER_NEW_RELIC.chars().map(String::from).collect();
        let chunks: Vec<&str> = bytes.iter().map(String::as_str).collect();
        let policy = UserPolicy::new(bearer, new_relic);
        let (text, findings) = incremental(&chunks, &policy);
        assert_eq!(text, expected_text, "{label}: text");
        assert_eq!(findings, expected, "{label}: findings");
        assert_eq!(*policy.calls.borrow(), [(BEARER.to_string(), 0)], "{label}");
    }
}

#[test]
fn multi_cluster_input_calls_the_incremental_policy_once_per_winner_in_order() {
    let input = format!("{BEARER_OVER_NEW_RELIC}\n{BEARER_OVER_NEW_RELIC}\n");
    for (bearer, new_relic, label) in policy_cases() {
        let reference = UserPolicy::new(bearer, new_relic);
        let (expected_text, expected) = whole(&input, &reference);
        assert_eq!(expected.len(), 2, "{label}");
        assert_eq!(
            *reference.calls.borrow(),
            [(BEARER.to_string(), 0), (BEARER.to_string(), 1)],
            "{label}: whole-input calls"
        );

        // Splits at every byte, plus a three-way split around the boundary.
        let mut splits: Vec<Vec<&str>> = (0..=input.len())
            .map(|at| {
                let (head, tail) = input.split_at(at);
                vec![head, tail]
            })
            .collect();
        let middle = BEARER_OVER_NEW_RELIC.len();
        splits.push(vec![
            &input[..middle - 3],
            &input[middle - 3..middle + 4],
            &input[middle + 4..],
        ]);
        for chunks in splits {
            let policy = UserPolicy::new(bearer, new_relic);
            let (text, findings) = incremental(&chunks, &policy);
            assert_eq!(text, expected_text, "{label}: text for {chunks:?}");
            assert_eq!(findings, expected, "{label}: findings for {chunks:?}");
            assert_eq!(
                *policy.calls.borrow(),
                [(BEARER.to_string(), 0), (BEARER.to_string(), 1)],
                "{label}: calls for {chunks:?}"
            );
        }
    }
}

#[test]
fn an_incremental_policy_failure_on_the_loser_type_is_unobservable_and_on_the_winner_fails() {
    let run = |failing: &'static str| {
        let policy = move |finding: &DetectedFinding,
                           _: &IncrementalPolicyContext|
              -> Result<Action, PolicyFailure> {
            if finding.type_name() == failing {
                Err(PolicyFailure)
            } else {
                Ok(Action::Redact)
            }
        };
        let mut sanitizer = IncrementalSanitizer::with_policy_and_formatter(
            support::generous_limits(),
            Box::new(policy),
            Box::new(default_placeholder_formatter),
        )
        .unwrap();
        let appended = sanitizer.append(BEARER_OVER_NEW_RELIC);
        let outcome = match appended {
            Ok(_) => sanitizer.finalize().map(|_| ()),
            Err(error) => Err(error),
        };
        (outcome, sanitizer.state())
    };

    let (outcome, state) = run(NEW_RELIC);
    assert!(outcome.is_ok());
    assert_eq!(state, SessionState::Finalized);

    let (outcome, state) = run(BEARER);
    assert_eq!(
        outcome.unwrap_err().code(),
        SecretScanErrorCode::PolicyFailure
    );
    assert_eq!(state, SessionState::Failed);
}
