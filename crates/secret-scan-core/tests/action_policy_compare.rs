//! Asserts the Rust core's explain-and-compare primitive (issue #1220,
//! `decision-explain-and-compare-action-policies-over-one-detection-pass`)
//! against the shared fixture `conformance/fixtures/action-policy-compare-v1.json`
//! and against the enforcement path.
//!
//! Beyond the fixture this file pins the properties the decision rests on:
//!
//! - **parity**: for every declarative side the compared action equals the
//!   action `scan` yields with that policy for the same finding;
//! - **detect once, finalized only**: the compared findings are exactly the
//!   findings `scan` returns, in order, and a loser never appears;
//! - **preview is not enforcement**: scan and redaction output is byte-identical
//!   before and after a comparison, and comparing never changes a callback's
//!   call count, order or the context it receives;
//! - **no plaintext**: no rendering of the result contains an input byte;
//! - **bounds** and **determinism**.
//!
//! Every document, input and finding is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;

use redact_secret::{
    Action, ActionPolicy, BuiltInRegistry, ComparedPolicy, DecisionBasis, DefaultPolicy,
    DetectedFinding, DetectorRegistry, Finding, MAX_COMPARED_POLICIES, PolicyBinding,
    PolicyContext, PolicyFailure, SecretScanErrorCode, WholeInputLimits, compare_action_policies,
    compare_action_policies_with_limits, default_placeholder_formatter, load_action_policy,
    load_ruleset, scan, scan_and_redact,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../conformance/fixtures/action-policy-compare-v1.json");

const GITHUB: &str = "ghp_SYNTHETICREVOKED00000000000000000000";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("action-policy-compare-v1.json must be valid JSON")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("expected string field {key:?}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("expected array field {key:?}"))
}

fn unsigned(value: &Value, key: &str) -> usize {
    usize::try_from(value[key].as_u64().unwrap_or_else(|| panic!("{key:?}"))).unwrap()
}

fn action(name: &str) -> Action {
    Action::from_name(name).unwrap_or_else(|| panic!("unknown action {name:?}"))
}

/// A scripted callback policy: returns `returns[finding_index]`, fails at
/// `fail_at`, and logs every call as `<label><index>` plus the context it saw.
struct Scripted<'a> {
    label: String,
    returns: Vec<Action>,
    fail_at: Option<usize>,
    log: &'a RefCell<Vec<String>>,
    contexts: &'a RefCell<Vec<(usize, usize)>>,
}

impl redact_secret::Policy for Scripted<'_> {
    fn evaluate(
        &self,
        _finding: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        let index = context.finding_index();
        self.log.borrow_mut().push(format!("{}{index}", self.label));
        self.contexts
            .borrow_mut()
            .push((context.finding_index(), context.finding_count()));
        if self.fail_at == Some(index) {
            return Err(PolicyFailure);
        }
        Ok(self.returns[index])
    }
}

struct Prepared {
    policies: Vec<(String, ActionPolicy)>,
}

impl Prepared {
    fn new(fixture: &Value) -> Self {
        let policies = array(fixture, "policies")
            .iter()
            .map(|entry| {
                (
                    text(entry, "id").to_owned(),
                    load_action_policy(text(entry, "documentText").as_bytes()).unwrap(),
                )
            })
            .collect();
        Self { policies }
    }

    fn policy(&self, id: &str) -> &ActionPolicy {
        &self
            .policies
            .iter()
            .find(|(name, _)| name == id)
            .unwrap_or_else(|| panic!("unknown policy {id:?}"))
            .1
    }
}

fn registry_for(fixture: &Value, case: &Value) -> DetectorRegistry {
    let custom = if case.get("useRuleset").and_then(Value::as_bool) == Some(true) {
        load_ruleset(text(fixture, "ruleset").as_bytes()).unwrap()
    } else {
        Vec::new()
    };
    DetectorRegistry::with_built_in(custom).unwrap()
}

fn code_name(code: SecretScanErrorCode) -> &'static str {
    code.as_str()
}

/// Builds the compared sides for a fixture entry, wiring scripted callbacks to
/// the shared logs.
fn run_case(
    fixture: &Value,
    prepared: &Prepared,
    case: &Value,
    log: &RefCell<Vec<String>>,
    contexts: &RefCell<Vec<(usize, usize)>>,
) -> Result<redact_secret::ActionComparison, redact_secret::SecretScanError> {
    let registry = registry_for(fixture, case);
    let scripted: Vec<Option<Scripted<'_>>> = array(case, "sides")
        .iter()
        .map(|side| {
            (text(side, "kind") == "callback").then(|| Scripted {
                label: text(side, "label").to_owned(),
                returns: array(side, "returns")
                    .iter()
                    .map(|name| action(name.as_str().unwrap()))
                    .collect(),
                fail_at: side
                    .get("failAtFindingIndex")
                    .and_then(Value::as_u64)
                    .map(|index| usize::try_from(index).unwrap()),
                log,
                contexts,
            })
        })
        .collect();
    let sides: Vec<ComparedPolicy<'_>> = array(case, "sides")
        .iter()
        .zip(&scripted)
        .map(|(side, script)| match text(side, "kind") {
            "default" => ComparedPolicy::Default,
            "policy" => ComparedPolicy::ActionPolicy(prepared.policy(text(side, "policy"))),
            "callback" => ComparedPolicy::Callback(script.as_ref().unwrap()),
            other => panic!("unknown side kind {other:?}"),
        })
        .collect();
    let input = text(case, "input");
    match case.get("limits") {
        Some(limits) => {
            let limits = WholeInputLimits::new(
                unsigned(limits, "maxInputBytes"),
                unsigned(limits, "maxFindings"),
            )
            .unwrap();
            compare_action_policies_with_limits(input, &registry, &sides, &limits)
        }
        None => compare_action_policies(input, &registry, &sides),
    }
}

/// The action an expected decision names, resolving the `base` sentinel to the
/// core's own default evaluation of the same finding.
fn expected_action(name: &str, finding: &DetectedFinding) -> Action {
    if name == "base" {
        DefaultPolicy_evaluate(finding)
    } else {
        action(name)
    }
}

#[allow(non_snake_case)]
fn DefaultPolicy_evaluate(finding: &DetectedFinding) -> Action {
    redact_secret::Policy::evaluate(&DefaultPolicy, finding, &PolicyContext::new(0, 1)).unwrap()
}

#[test]
fn every_fixture_case_matches() {
    let fixture = fixture();
    let prepared = Prepared::new(&fixture);
    let cases = array(&fixture, "cases");
    assert!(cases.len() >= 8);

    for case in cases {
        let id = text(case, "id");
        let log = RefCell::new(Vec::new());
        let contexts = RefCell::new(Vec::new());
        let comparison = run_case(&fixture, &prepared, case, &log, &contexts)
            .unwrap_or_else(|error| panic!("{id}: {error}"));

        let expected = array(case, "expectedFindings");
        assert_eq!(comparison.findings().len(), expected.len(), "{id}: count");
        let sides = array(case, "sides");
        assert_eq!(comparison.sides().len(), sides.len(), "{id}: sides");

        for (position, (compared, want)) in comparison.findings().iter().zip(expected).enumerate() {
            let finding = compared.finding();
            let label = format!("{id}[{position}]");
            assert_eq!(finding.type_name(), text(want, "type"), "{label}");
            assert_eq!(finding.detector(), text(want, "detector"), "{label}");
            assert_eq!(
                finding.confidence().as_str(),
                text(want, "confidence"),
                "{label}"
            );
            assert_eq!(
                finding.obfuscation().as_str(),
                text(want, "obfuscation"),
                "{label}"
            );
            assert_eq!(finding.range().start(), unsigned(want, "start"), "{label}");
            assert_eq!(finding.range().end(), unsigned(want, "end"), "{label}");
            assert_eq!(
                compared.differs(),
                want["expectedDiffers"],
                "{label}: differs"
            );

            let decisions = array(want, "expectedDecisions");
            assert_eq!(compared.decisions().len(), decisions.len(), "{label}");
            for (side, (got, want)) in compared.decisions().iter().zip(decisions).enumerate() {
                let label = format!("{label} side {side}");
                assert_eq!(
                    got.action(),
                    expected_action(text(want, "action"), finding),
                    "{label}"
                );
                assert_eq!(got.basis().as_str(), text(want, "basis"), "{label}");
                assert_eq!(
                    got.basis().rule_id(),
                    want["ruleId"].as_str(),
                    "{label}: rule id"
                );
                assert_eq!(
                    got.basis().rule_index(),
                    want["ruleIndex"]
                        .as_u64()
                        .map(|index| usize::try_from(index).unwrap()),
                    "{label}: rule index"
                );
            }
        }

        assert_eq!(
            comparison.changed_count(),
            unsigned(case, "expectedChangedCount"),
            "{id}: changed"
        );

        // Per-side counts derive from the decisions.
        for (side_index, side) in comparison.sides().iter().enumerate() {
            for probe in [Action::Redact, Action::Block, Action::Warn, Action::Allow] {
                let expected = comparison
                    .findings()
                    .iter()
                    .filter(|finding| finding.decisions()[side_index].action() == probe)
                    .count();
                assert_eq!(side.counts().get(probe), expected, "{id}: counts");
            }
        }

        if let Some(sequence) = case.get("expectedCallSequence") {
            let want: Vec<&str> = sequence
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            let got = log.borrow();
            assert_eq!(
                got.iter().map(String::as_str).collect::<Vec<_>>(),
                want,
                "{id}"
            );
            // Every callback sees the same context `scan` would give it.
            let count = comparison.findings().len();
            for (index, seen_count) in contexts.borrow().iter() {
                assert!(*index < count && *seen_count == count, "{id}: context");
            }
        }
    }
}

#[test]
fn every_fixture_error_is_a_fixed_code_with_no_partial_result() {
    let fixture = fixture();
    let prepared = Prepared::new(&fixture);
    let errors = array(&fixture, "errors");
    assert!(errors.len() >= 7);

    for case in errors {
        let id = text(case, "id");
        let log = RefCell::new(Vec::new());
        let contexts = RefCell::new(Vec::new());
        let error = run_case(&fixture, &prepared, case, &log, &contexts)
            .expect_err(&format!("{id}: must fail"));
        assert_eq!(code_name(error.code()), text(case, "expectedCode"), "{id}");
        let want: Vec<&str> = array(case, "expectedCallSequence")
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(
            log.borrow().iter().map(String::as_str).collect::<Vec<_>>(),
            want,
            "{id}: call sequence"
        );
        // The message is the code's fixed message: no input, no document.
        assert_eq!(error.message(), error.code().message(), "{id}");
    }
}

#[test]
fn the_digest_is_the_sha256_of_the_exact_document_bytes() {
    let fixture = fixture();
    let prepared = Prepared::new(&fixture);
    for entry in array(&fixture, "digests") {
        let policy = prepared.policy(text(entry, "policy"));
        assert_eq!(policy.document_sha256_hex(), text(entry, "documentSha256"));
        let side = [ComparedPolicy::ActionPolicy(policy)];
        let registry = DetectorRegistry::with_built_in([]).unwrap();
        let comparison = compare_action_policies("x", &registry, &side).unwrap();
        let binding = comparison.sides()[0].binding();
        assert_eq!(binding.kind(), "action-policy");
        assert_eq!(binding.document_sha256(), Some(policy.document_sha256()));
        assert_eq!(
            binding.document_sha256_hex().as_deref(),
            Some(text(entry, "documentSha256"))
        );
    }
    // Insignificant whitespace is part of the bytes: same meaning, new binding.
    assert_ne!(
        prepared.policy("empty-rules").document_sha256(),
        prepared.policy("empty-rules-spaced").document_sha256()
    );
    // A clone shares the document and therefore the binding.
    let policy = prepared.policy("four-actions");
    assert_eq!(policy.clone().document_sha256(), policy.document_sha256());
}

/// Every declarative side's action equals what enforcement (`scan`) produces
/// for the same finding, across every fixture policy and input.
#[test]
fn compared_actions_equal_the_enforcement_path_for_every_policy_and_input() {
    let fixture = fixture();
    let prepared = Prepared::new(&fixture);
    let registry = {
        let custom = load_ruleset(text(&fixture, "ruleset").as_bytes()).unwrap();
        DetectorRegistry::with_built_in(custom).unwrap()
    };
    let inputs: Vec<String> = array(&fixture, "cases")
        .iter()
        .map(|case| text(case, "input").to_owned())
        .chain([
            format!("token {GITHUB} and again {GITHUB}\n"),
            String::new(),
        ])
        .collect();

    for input in &inputs {
        for chunk in prepared.policies.chunks(MAX_COMPARED_POLICIES - 1) {
            let sides: Vec<ComparedPolicy<'_>> = std::iter::once(ComparedPolicy::Default)
                .chain(chunk.iter().map(|(_, p)| ComparedPolicy::ActionPolicy(p)))
                .collect();
            let comparison = compare_action_policies(input, &registry, &sides).unwrap();
            let baseline = scan(input, &registry, &DefaultPolicy).unwrap();
            assert_eq!(comparison.findings().len(), baseline.len());
            for (side_index, side) in sides.iter().enumerate() {
                let enforced = match side {
                    ComparedPolicy::Default => scan(input, &registry, &DefaultPolicy).unwrap(),
                    ComparedPolicy::ActionPolicy(policy) => {
                        scan(input, &registry, *policy).unwrap()
                    }
                    _ => unreachable!(),
                };
                for (compared, enforced) in comparison.findings().iter().zip(&enforced) {
                    // The same finalized finding...
                    assert_eq!(compared.finding().id(), enforced.id());
                    assert_eq!(compared.finding().type_name(), enforced.type_name());
                    assert_eq!(compared.finding().detector(), enforced.detector());
                    assert_eq!(compared.finding().confidence(), enforced.confidence());
                    assert_eq!(compared.finding().range(), enforced.range());
                    assert_eq!(compared.finding().obfuscation(), enforced.obfuscation());
                    // ...and the same action.
                    assert_eq!(
                        compared.decisions()[side_index].action(),
                        enforced.action(),
                        "parity, side {side_index}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_legacy_callback_compares_to_what_scan_gives_it() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = format!("A={GITHUB}\nB={GITHUB}\n");
    let by_index = |_: &DetectedFinding, context: &PolicyContext| {
        Ok(if context.finding_index() == 0 {
            Action::Allow
        } else {
            Action::Block
        })
    };
    let enforced = scan(&input, &registry, &by_index).unwrap();
    let comparison =
        compare_action_policies(&input, &registry, &[ComparedPolicy::Callback(&by_index)]).unwrap();
    let compared: Vec<Action> = comparison
        .findings()
        .iter()
        .map(|finding| finding.decisions()[0].action())
        .collect();
    assert_eq!(
        compared,
        enforced.iter().map(Finding::action).collect::<Vec<_>>()
    );
    assert_eq!(compared, [Action::Allow, Action::Block]);
    assert_eq!(comparison.sides()[0].binding(), &PolicyBinding::Callback);
    assert_eq!(comparison.sides()[0].binding().document_sha256(), None);
}

#[test]
fn comparing_does_not_change_enforcement_output_or_callback_behaviour() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = format!("A={GITHUB}\nB={GITHUB}\nplain\n");
    let allow_second = load_action_policy(
        br#"{"actionPolicyRevision":1,"base":"default","rules":[
            {"id":"allow-github","match":{"type":["github_token"]},"action":"allow"}]}"#,
    )
    .unwrap();

    // The enforcement callback, observed before and after a comparison.
    let observe = |label: &str| {
        let calls = RefCell::new(Vec::new());
        let callback = |finding: &DetectedFinding, context: &PolicyContext| {
            calls.borrow_mut().push((
                finding.id().to_owned(),
                context.finding_index(),
                context.finding_count(),
            ));
            Ok(Action::Redact)
        };
        let result = scan_and_redact(&input, &registry, &callback, &default_placeholder_formatter)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        (result.text().to_owned(), calls.into_inner())
    };

    let before = observe("before");
    let _ = compare_action_policies(
        &input,
        &registry,
        &[
            ComparedPolicy::Default,
            ComparedPolicy::ActionPolicy(&allow_second),
        ],
    )
    .unwrap();
    let after = observe("after");

    assert_eq!(before, after);
    assert_eq!(before.0, "A=<SECRET_1>\nB=<SECRET_2>\nplain\n");
    assert_eq!(before.1.len(), 2);
    assert_eq!(
        before.1.iter().map(|call| call.1).collect::<Vec<_>>(),
        [0, 1]
    );

    // The shared registry and policy are untouched: a policy scan is identical.
    let one = scan(&input, &registry, &allow_second).unwrap();
    let _ = compare_action_policies(&input, &registry, &[ComparedPolicy::Default]).unwrap();
    assert_eq!(scan(&input, &registry, &allow_second).unwrap(), one);
}

#[test]
fn the_comparison_callback_count_equals_the_enforcement_callback_count() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = format!("A={GITHUB}\nB={GITHUB}\nC={GITHUB}\n");
    let count = RefCell::new(0_usize);
    let callback = |_: &DetectedFinding, _: &PolicyContext| {
        *count.borrow_mut() += 1;
        Ok(Action::Warn)
    };
    scan(&input, &registry, &callback).unwrap();
    let enforced = count.replace(0);
    compare_action_policies(&input, &registry, &[ComparedPolicy::Callback(&callback)]).unwrap();
    assert_eq!(count.replace(0), enforced);
    assert_eq!(enforced, 3);
}

#[test]
fn a_comparison_equals_its_own_repeat_and_is_independent_of_other_sides() {
    let fixture = fixture();
    let prepared = Prepared::new(&fixture);
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = format!("A={GITHUB}\n");
    let one = prepared.policy("four-actions");
    let other = prepared.policy("block-high");

    let both = compare_action_policies(
        &input,
        &registry,
        &[
            ComparedPolicy::ActionPolicy(one),
            ComparedPolicy::ActionPolicy(other),
        ],
    )
    .unwrap();
    assert_eq!(
        both,
        compare_action_policies(
            &input,
            &registry,
            &[
                ComparedPolicy::ActionPolicy(one),
                ComparedPolicy::ActionPolicy(other),
            ],
        )
        .unwrap()
    );
    let alone =
        compare_action_policies(&input, &registry, &[ComparedPolicy::ActionPolicy(one)]).unwrap();
    assert_eq!(
        both.findings()[0].decisions()[0],
        alone.findings()[0].decisions()[0],
        "a side's decision does not depend on its neighbours"
    );
}

#[test]
fn the_detection_configuration_is_named_apart_from_every_policy() {
    let full = DetectorRegistry::with_built_in([]).unwrap();
    let common = DetectorRegistry::with_common_built_in([]).unwrap();
    let one = [ComparedPolicy::Default];

    let on_full = compare_action_policies("x", &full, &one).unwrap();
    let on_common = compare_action_policies("x", &common, &one).unwrap();
    assert_eq!(
        on_full.detection().activation_identity(),
        full.activation_identity()
    );
    assert_eq!(on_full.detection().profile(), full.profile());
    assert_eq!(on_full.detection().detector_count(), full.len());
    assert_ne!(on_full.detection(), on_common.detection());

    // The same policies under another detection configuration: only the
    // detection identity (and what it finds) changes, never a policy binding.
    let policy =
        load_action_policy(br#"{"actionPolicyRevision":1,"base":"default","rules":[]}"#).unwrap();
    let side = [ComparedPolicy::ActionPolicy(&policy)];
    assert_eq!(
        compare_action_policies("x", &full, &side).unwrap().sides()[0].binding(),
        compare_action_policies("x", &common, &side)
            .unwrap()
            .sides()[0]
            .binding()
    );
}

#[test]
fn a_built_in_registry_compares_like_a_detector_registry() {
    let built_in = BuiltInRegistry::with_built_in().unwrap();
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = format!("A={GITHUB}\n");
    let sides = [ComparedPolicy::Default];
    let a = built_in.compare_action_policies(&input, &sides).unwrap();
    let b = compare_action_policies(&input, &registry, &sides).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.detection().profile(), Some(built_in.profile()));
    let with_limits = built_in
        .compare_action_policies_with_limits(&input, &sides, &WholeInputLimits::default())
        .unwrap();
    assert_eq!(with_limits, a);
}

#[test]
fn the_result_is_bounded_by_the_findings_and_the_side_count() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let mut input = String::new();
    for index in 0..30 {
        input.push_str(&index.to_string());
        input.push('=');
        input.push_str(GITHUB);
        input.push('\n');
    }
    let sides = vec![ComparedPolicy::Default; MAX_COMPARED_POLICIES];
    let comparison = compare_action_policies(&input, &registry, &sides).unwrap();
    assert_eq!(comparison.findings().len(), 30);
    assert!(
        comparison
            .findings()
            .iter()
            .all(|finding| finding.decisions().len() == MAX_COMPARED_POLICIES)
    );

    // Exactly at and one over the finding bound.
    let at = WholeInputLimits::new(1 << 20, 30).unwrap();
    assert!(compare_action_policies_with_limits(&input, &registry, &sides, &at).is_ok());
    let over = WholeInputLimits::new(1 << 20, 29).unwrap();
    assert_eq!(
        compare_action_policies_with_limits(&input, &registry, &sides, &over)
            .unwrap_err()
            .code(),
        SecretScanErrorCode::FindingLimitExceeded
    );
    let small = WholeInputLimits::new(input.len() - 1, 100).unwrap();
    assert_eq!(
        compare_action_policies_with_limits(&input, &registry, &sides, &small)
            .unwrap_err()
            .code(),
        SecretScanErrorCode::InputLimitExceeded
    );
    assert_eq!(MAX_COMPARED_POLICIES, 4);
    assert_eq!(
        compare_action_policies(&input, &registry, &[])
            .unwrap_err()
            .code(),
        SecretScanErrorCode::InvalidOptions
    );
}

#[test]
fn nothing_in_the_result_carries_plaintext_or_a_score() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let secret_tail = "SYNTHETICREVOKED00000000000000000000";
    let input = format!("API_KEY={GITHUB} user note\n");
    let policy = load_action_policy(
        br#"{"actionPolicyRevision":1,"base":"default","rules":[
            {"id":"warn-github","match":{"type":["github_token"]},"action":"warn"}]}"#,
    )
    .unwrap();
    let comparison = compare_action_policies(
        &input,
        &registry,
        &[
            ComparedPolicy::Default,
            ComparedPolicy::ActionPolicy(&policy),
        ],
    )
    .unwrap();

    let rendered = format!("{comparison:?}");
    for forbidden in [GITHUB, secret_tail, "user note", "API_KEY"] {
        assert!(!rendered.contains(forbidden), "result leaks {forbidden:?}");
    }
    let lower = rendered.to_ascii_lowercase();
    for word in ["score", "entropy", "probability"] {
        assert!(!lower.contains(word), "result mentions {word}");
    }
    // The finding is the same safe value a policy callback receives.
    let finding = comparison.findings()[0].finding();
    assert_eq!(finding.id(), "finding-1");
    assert_eq!(finding.range().start(), 8);
    assert_eq!(finding.range().end(), 8 + GITHUB.len());
}

#[test]
fn a_loser_and_a_suppressed_alternative_are_never_reported() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = concat!(
        "twilio Authorization: Bear",
        "er fedcba9876543210fedcba9876543210"
    );
    let comparison = compare_action_policies(input, &registry, &[ComparedPolicy::Default]).unwrap();
    let enforced = scan(input, &registry, &DefaultPolicy).unwrap();
    assert_eq!(comparison.findings().len(), enforced.len());
    assert_eq!(comparison.findings().len(), 1);
    assert_eq!(
        comparison.findings()[0].finding().type_name(),
        "bearer_token"
    );
}

#[test]
fn every_basis_has_a_fixed_name_and_exposes_only_its_rule_fields() {
    let rule = DecisionBasis::Rule {
        rule_id: "r".to_owned(),
        rule_index: 3,
    };
    let carve = DecisionBasis::RuleDefault {
        rule_id: "d".to_owned(),
        rule_index: 0,
    };
    assert_eq!(
        [
            rule.as_str(),
            carve.as_str(),
            DecisionBasis::NoRuleMatched.as_str(),
            DecisionBasis::DefaultPolicy.as_str(),
            DecisionBasis::Callback.as_str(),
        ],
        [
            "rule",
            "rule-default",
            "no-rule-matched",
            "default-policy",
            "callback"
        ]
    );
    assert_eq!((rule.rule_id(), rule.rule_index()), (Some("r"), Some(3)));
    assert_eq!((carve.rule_id(), carve.rule_index()), (Some("d"), Some(0)));
    for basis in [
        DecisionBasis::NoRuleMatched,
        DecisionBasis::DefaultPolicy,
        DecisionBasis::Callback,
    ] {
        assert_eq!((basis.rule_id(), basis.rule_index()), (None, None));
    }
}

#[test]
fn the_fixture_names_the_basis_and_side_vocabularies_it_uses() {
    let fixture = fixture();
    let names: Vec<&str> = array(&fixture, "basisNames")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "rule",
            "rule-default",
            "no-rule-matched",
            "default-policy",
            "callback"
        ]
    );
    assert_eq!(
        unsigned(&fixture["limits"], "maxPolicies"),
        MAX_COMPARED_POLICIES
    );
    assert_eq!(
        unsigned(&fixture["limits"], "defaultMaxFindings"),
        redact_secret::DEFAULT_MAX_FINDINGS
    );
    assert_eq!(
        unsigned(&fixture["limits"], "defaultMaxInputBytes"),
        redact_secret::DEFAULT_MAX_INPUT_BYTES
    );
}
