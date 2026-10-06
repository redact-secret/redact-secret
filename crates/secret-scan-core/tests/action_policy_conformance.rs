//! Asserts the Rust core against the shared action policy conformance fixture
//! (`conformance/fixtures/action-policy-v1.json`, issue #1219,
//! `decision-define-the-versioned-declarative-action-policy-and-default-overlay`).
//!
//! The Rust core runs the fixture for semantics: every evaluation, every
//! rejection with its exact class and rule index, every accepted edge
//! document, the end-to-end cases (whole input and, where the case allows,
//! incremental sessions under several partitions), and the host obligations
//! that apply to a core with no callback boundary.
//!
//! `base` in the fixture is a sentinel. This runner resolves it by asking the
//! core's own default evaluation (`DefaultPolicy`) of the same finding or the
//! same input, and never carries a copy of the default table.
//!
//! The core does not expose which rule matched (that is #1220's explain
//! output), so `expectedRule` is checked against an independent, deliberately
//! naive reference evaluator over the fixture's own JSON in this file; the
//! core's returned *action* is checked against the same expectation.
//!
//! Every document, finding and input is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use redact_secret::{
    Action, ActionPolicy, ActionPolicyErrorClass, ByteRange, Confidence, DefaultPolicy,
    DetectedFinding, DetectorRegistry, Finding, IncrementalLimits, IncrementalPolicy,
    IncrementalPolicyContext, IncrementalSanitizer, MAX_ACTION_POLICY_BYTES, Obfuscation, Policy,
    PolicyContext, PolicyFailure, SecretScanErrorCode, default_placeholder_formatter,
    load_action_policy, load_ruleset, scan, scan_and_redact,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../conformance/fixtures/action-policy-v1.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("action-policy-v1.json must be valid JSON")
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
    usize::try_from(
        value
            .get(key)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("expected integer field {key:?}")),
    )
    .unwrap()
}

/// The bytes a host hands the core for a fixture entry: raw text, a compact
/// serialization of a JSON document, or a synthesized one at a bound.
fn document_bytes(entry: &Value) -> Vec<u8> {
    if let Some(raw) = entry.get("documentText").and_then(Value::as_str) {
        return raw.as_bytes().to_vec();
    }
    if let Some(document) = entry.get("document") {
        return serde_json::to_vec(document).unwrap();
    }
    let synthesis = entry
        .get("synthesis")
        .unwrap_or_else(|| panic!("entry has no document"));
    match text(synthesis, "kind") {
        "padded" => {
            let mut bytes = text(synthesis, "base").as_bytes().to_vec();
            let total = unsigned(synthesis, "totalBytes");
            assert!(bytes.len() <= total);
            bytes.resize(total, b' ');
            bytes
        }
        "rule-count" => {
            let rules: Vec<String> = (0..unsigned(synthesis, "count"))
                .map(|index| {
                    format!(r#"{{"id":"r{index}","match":{{"type":["jwt"]}},"action":"warn"}}"#)
                })
                .collect();
            format!(
                r#"{{"actionPolicyRevision":1,"base":"default","rules":[{}]}}"#,
                rules.join(",")
            )
            .into_bytes()
        }
        "set-size" => {
            let members: Vec<String> = (0..unsigned(synthesis, "count"))
                .map(|index| format!(r#""t{index}""#))
                .collect();
            format!(
                r#"{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"r","match":{{"type":[{}]}},"action":"warn"}}]}}"#,
                members.join(",")
            )
            .into_bytes()
        }
        other => panic!("unknown synthesis kind {other:?}"),
    }
}

fn named_policy<'a>(fixture: &'a Value, id: &str) -> &'a Value {
    array(fixture, "policies")
        .iter()
        .find(|policy| text(policy, "id") == id)
        .unwrap_or_else(|| panic!("fixture has no policy {id:?}"))
}

fn policy_bytes(fixture: &Value, reference: &Value) -> Vec<u8> {
    match reference {
        Value::String(id) => document_bytes(named_policy(fixture, id)),
        document => serde_json::to_vec(document).unwrap(),
    }
}

fn policy_document<'a>(fixture: &'a Value, reference: &'a Value) -> &'a Value {
    match reference {
        Value::String(id) => &named_policy(fixture, id)["document"],
        document => document,
    }
}

fn action(name: &str) -> Action {
    Action::from_name(name).unwrap_or_else(|| panic!("unknown action {name:?}"))
}

fn detected(fixture: &Value, id: &str) -> DetectedFinding {
    let finding = &fixture["findings"][id];
    DetectedFinding::new(
        "finding-1",
        text(finding, "type"),
        text(finding, "detector"),
        Confidence::from_name(text(finding, "confidence")).unwrap(),
        ByteRange::new(0, 1).unwrap(),
    )
    .unwrap()
    .with_obfuscation(Obfuscation::from_name(text(finding, "obfuscation")).unwrap())
}

fn default_action(finding: &DetectedFinding) -> Action {
    Policy::evaluate(&DefaultPolicy, finding, &PolicyContext::new(0, 1)).unwrap()
}

/// The core's action for `finding`, asserted equal through both policy traits.
fn core_action(policy: &ActionPolicy, finding: &DetectedFinding) -> Action {
    let whole = Policy::evaluate(policy, finding, &PolicyContext::new(0, 1)).unwrap();
    let incremental =
        IncrementalPolicy::evaluate(policy, finding, &IncrementalPolicyContext::new(0)).unwrap();
    assert_eq!(whole, incremental, "whole-input and incremental disagree");
    whole
}

/// An independent reference evaluator over the fixture's JSON: first matching
/// rule wins, keys `AND`ed, sets `OR`ed. Returns the matched rule id and the
/// action the document gives (`None` action means the base).
fn reference_evaluate(document: &Value, finding: &Value) -> (Option<String>, Option<Action>) {
    for rule in document["rules"].as_array().unwrap() {
        let matcher = rule["match"].as_object().unwrap();
        let holds = |key: &str, value: &str| {
            matcher.get(key).is_none_or(|set| {
                set.as_array()
                    .unwrap()
                    .iter()
                    .any(|member| member.as_str() == Some(value))
            })
        };
        if holds("type", text(finding, "type"))
            && holds("detector", text(finding, "detector"))
            && holds("confidence", text(finding, "confidence"))
            && holds("obfuscation", text(finding, "obfuscation"))
        {
            let name = text(rule, "action");
            let outcome = (name != "default").then(|| action(name));
            return (Some(text(rule, "id").to_owned()), outcome);
        }
    }
    (None, None)
}

// ---------------------------------------------------------------------------
// the fixture agrees with the core's own constants
// ---------------------------------------------------------------------------

#[test]
fn the_fixture_vocabulary_limits_and_error_match_the_core() {
    let fixture = fixture();
    assert_eq!(unsigned(&fixture, "revision"), 1);
    assert_eq!(
        unsigned(&fixture["limits"], "maxDocumentBytes"),
        MAX_ACTION_POLICY_BYTES
    );
    assert_eq!(unsigned(&fixture["limits"], "maxRules"), 128);
    assert_eq!(unsigned(&fixture["limits"], "maxSetMembers"), 256);
    assert_eq!(
        text(&fixture, "errorCode"),
        SecretScanErrorCode::InvalidActionPolicy.as_str()
    );
    assert_eq!(
        text(&fixture, "errorMessage"),
        SecretScanErrorCode::InvalidActionPolicy.message()
    );

    let names = |key: &str| -> Vec<&str> {
        array(&fixture["vocabulary"], key)
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect()
    };
    for name in names("actions") {
        assert!(Action::from_name(name).is_some(), "{name}");
    }
    assert_eq!(names("actions").len(), 4);
    let mut rule_actions = names("ruleActions");
    assert_eq!(rule_actions.pop(), Some("default"));
    assert_eq!(rule_actions, names("actions"));
    assert_eq!(names("confidence").len(), 3);
    for name in names("confidence") {
        assert!(Confidence::from_name(name).is_some(), "{name}");
    }
    assert_eq!(names("obfuscation").len(), 2);
    for name in names("obfuscation") {
        assert!(Obfuscation::from_name(name).is_some(), "{name}");
    }
    assert_eq!(
        names("matchKeys"),
        ["type", "detector", "confidence", "obfuscation"]
    );
}

#[test]
fn the_core_error_code_set_grows_to_twenty_three() {
    assert_eq!(SecretScanErrorCode::ALL.len(), 23);
    assert_eq!(
        SecretScanErrorCode::ALL.last().copied(),
        Some(SecretScanErrorCode::InvalidActionPolicy)
    );
}

// ---------------------------------------------------------------------------
// base anchors, evaluations
// ---------------------------------------------------------------------------

#[test]
fn the_base_anchors_resolve_through_the_core_default() {
    let fixture = fixture();
    let empty = load_action_policy(&policy_bytes(&fixture, &Value::from("empty-rules"))).unwrap();
    for case in array(&fixture["baseAnchors"], "cases") {
        let finding = detected(&fixture, text(case, "finding"));
        let expected = action(text(case, "expectedAction"));
        assert_eq!(default_action(&finding), expected, "{case}");
        assert_eq!(core_action(&empty, &finding), expected, "{case}");
    }
}

#[test]
fn every_evaluation_matches_the_truth_table() {
    let fixture = fixture();
    let evaluations = array(&fixture, "evaluations");
    assert_eq!(evaluations.len(), 37);
    let mut groups = BTreeSet::new();
    for case in evaluations {
        let id = text(case, "id");
        groups.insert(text(case, "group").to_owned());
        let policy = load_action_policy(&document_bytes(named_policy(
            &fixture,
            text(case, "policy"),
        )))
        .unwrap_or_else(|error| panic!("{id}: policy must load: {error:?}"));
        let finding = detected(&fixture, text(case, "finding"));

        let expected = match text(case, "expectedAction") {
            "base" => default_action(&finding),
            other => action(other),
        };
        assert_eq!(core_action(&policy, &finding), expected, "{id}");

        // The reference evaluator agrees with the fixture's expectedRule and
        // with its action, so a fixture row and the core cannot drift apart
        // silently.
        let (rule, outcome) = reference_evaluate(
            &named_policy(&fixture, text(case, "policy"))["document"],
            &fixture["findings"][text(case, "finding")],
        );
        assert_eq!(rule.as_deref(), case["expectedRule"].as_str(), "{id}");
        assert_eq!(
            outcome.unwrap_or_else(|| default_action(&finding)),
            expected,
            "{id}"
        );
    }
    for group in [
        "unmatched-fallback",
        "unknown-type",
        "four-actions",
        "default-action",
        "matched-rule",
        "set-membership",
        "ordering",
    ] {
        assert!(groups.contains(group), "no evaluation in group {group}");
    }
}

// ---------------------------------------------------------------------------
// accepted and rejected documents
// ---------------------------------------------------------------------------

#[test]
fn every_named_policy_and_accepted_document_loads() {
    let fixture = fixture();
    for policy in array(&fixture, "policies") {
        load_action_policy(&document_bytes(policy))
            .unwrap_or_else(|error| panic!("{}: {error:?}", text(policy, "id")));
    }
    let accepted = array(&fixture, "acceptedDocuments");
    assert_eq!(accepted.len(), 7);
    for document in accepted {
        let bytes = document_bytes(document);
        load_action_policy(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error:?}", text(document, "id")));
    }
    // The byte-bound documents really are at the bound.
    let at_limit = accepted
        .iter()
        .find(|document| text(document, "id") == "document-at-byte-limit")
        .unwrap();
    assert_eq!(document_bytes(at_limit).len(), MAX_ACTION_POLICY_BYTES);
}

#[test]
fn every_rejection_reports_its_exact_class_and_rule_index() {
    let fixture = fixture();
    let first = array(&fixture, "rejections");
    let additional = array(&fixture, "additionalRejections");
    assert_eq!(first.len(), 17);
    assert_eq!(additional.len(), 41);

    // One first rejection per class, and the 17 are exactly the core's 17.
    let covered: BTreeSet<&str> = first.iter().map(|case| text(case, "class")).collect();
    let all: BTreeSet<&str> = ActionPolicyErrorClass::ALL
        .iter()
        .map(|class| class.as_str())
        .collect();
    assert_eq!(covered, all);

    for case in first.iter().chain(additional) {
        let id = text(case, "id");
        let error = load_action_policy(&document_bytes(case))
            .expect_err(&format!("{id}: the document must be rejected"));
        assert_eq!(error.class().as_str(), text(case, "class"), "{id}");
        assert_eq!(
            error.rule_index(),
            case["ruleIndex"]
                .as_u64()
                .map(|index| usize::try_from(index).unwrap()),
            "{id}"
        );
        assert_eq!(
            error.code(),
            SecretScanErrorCode::InvalidActionPolicy,
            "{id}"
        );
        assert_eq!(error.message(), text(&fixture, "errorMessage"), "{id}");
        assert_eq!(error.to_string(), text(&fixture, "errorMessage"), "{id}");
    }
}

// ---------------------------------------------------------------------------
// end to end
// ---------------------------------------------------------------------------

fn limits() -> IncrementalLimits {
    IncrementalLimits::new(
        1 << 20,
        IncrementalLimits::minimum_buffered_bytes(1 << 16, 1 << 16),
        1 << 16,
        1 << 16,
    )
    .unwrap()
}

/// The expected sanitized text for `input` given findings in input order:
/// `redact` and `block` spans become numbered placeholders, `warn` and `allow`
/// spans are untouched and take no number.
fn expected_text(input: &str, findings: &[(usize, usize, Action)]) -> String {
    let mut out = String::new();
    let mut cursor = 0;
    let mut number = 0;
    for &(start, end, action) in findings {
        if action.replaces_text() {
            number += 1;
            out.push_str(&input[cursor..start]);
            out.push_str("<SECRET_");
            out.push_str(&number.to_string());
            out.push('>');
            cursor = end;
        }
    }
    out.push_str(&input[cursor..]);
    out
}

/// Feeds `partition` to a session that bound `policy` at construction and
/// returns the concatenated sanitized text and every finding it reported.
fn run_incremental(policy: &ActionPolicy, partition: &[String]) -> (String, Vec<Finding>) {
    let mut session = IncrementalSanitizer::with_policy_and_formatter(
        limits(),
        Box::new(policy.clone()),
        Box::new(default_placeholder_formatter),
    )
    .unwrap();
    let mut out = String::new();
    let mut found = Vec::new();
    for chunk in partition {
        let result = session.append(chunk).unwrap();
        out.push_str(result.text());
        found.extend(result.findings().iter().cloned());
    }
    let result = session.finalize().unwrap();
    out.push_str(result.text());
    found.extend(result.findings().iter().cloned());
    (out, found)
}

#[test]
fn every_end_to_end_case_matches_whole_input_and_incremental() {
    let fixture = fixture();
    let end_to_end = &fixture["endToEnd"];
    let cases = array(end_to_end, "cases");
    assert_eq!(cases.len(), 5);

    for case in cases {
        let id = text(case, "id");
        let input = text(case, "input");
        let policy = load_action_policy(&policy_bytes(&fixture, &case["policy"])).unwrap();
        let uses_ruleset = case.get("useRuleset").and_then(Value::as_bool) == Some(true);
        let custom = if uses_ruleset {
            load_ruleset(text(end_to_end, "ruleset").as_bytes()).unwrap()
        } else {
            Vec::new()
        };
        let registry = DetectorRegistry::with_built_in(custom).unwrap();

        // `base` resolves to what the same input yields with no policy at all.
        let unpoliced = scan(input, &registry, &DefaultPolicy).unwrap();
        let findings = scan(input, &registry, &policy).unwrap();
        let expected = array(case, "expectedFindings");
        assert_eq!(findings.len(), expected.len(), "{id}");
        assert_eq!(unpoliced.len(), expected.len(), "{id}");

        let mut spans = Vec::new();
        for (index, want) in expected.iter().enumerate() {
            let got = &findings[index];
            assert_eq!(got.type_name(), text(want, "type"), "{id}");
            assert_eq!(got.detector(), text(want, "detector"), "{id}");
            assert_eq!(got.confidence().as_str(), text(want, "confidence"), "{id}");
            assert_eq!(
                got.obfuscation().as_str(),
                text(want, "obfuscation"),
                "{id}"
            );
            assert_eq!(got.range().start(), unsigned(want, "start"), "{id}");
            assert_eq!(got.range().end(), unsigned(want, "end"), "{id}");
            let want_action = match text(want, "expectedAction") {
                "base" => unpoliced[index].action(),
                other => action(other),
            };
            assert_eq!(got.action(), want_action, "{id}");
            spans.push((got.range().start(), got.range().end(), got.action()));

            let (rule, _) = reference_evaluate(
                policy_document(&fixture, &case["policy"]),
                &serde_json::json!({
                    "type": got.type_name(),
                    "detector": got.detector(),
                    "confidence": got.confidence().as_str(),
                    "obfuscation": got.obfuscation().as_str(),
                }),
            );
            assert_eq!(rule.as_deref(), want["expectedRule"].as_str(), "{id}");
        }

        let whole =
            scan_and_redact(input, &registry, &policy, &default_placeholder_formatter).unwrap();
        let sanitized = expected_text(input, &spans);
        assert_eq!(whole.text(), sanitized, "{id}");
        // The default overlay changes nothing for a document with no rules:
        // existing no-policy results stay identical.
        let plain = scan_and_redact(
            input,
            &registry,
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap();
        let empty =
            load_action_policy(br#"{"actionPolicyRevision":1,"base":"default","rules":[]}"#)
                .unwrap();
        let with_empty =
            scan_and_redact(input, &registry, &empty, &default_placeholder_formatter).unwrap();
        assert_eq!(with_empty.text(), plain.text(), "{id}");
        assert_eq!(with_empty.findings(), plain.findings(), "{id}");

        if case.get("alsoIncremental").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        // The same policy, bound at construction, over several partitions.
        let mut partitions: Vec<Vec<String>> = vec![
            vec![input.to_owned()],
            input.chars().map(String::from).collect(),
        ];
        if input.is_ascii() {
            partitions.push(
                input
                    .as_bytes()
                    .chunks(7)
                    .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
                    .collect(),
            );
        }
        for partition in partitions {
            let (out, found) = run_incremental(&policy, &partition);
            assert_eq!(out, sanitized, "{id}: incremental text");
            assert_eq!(found.len(), expected.len(), "{id}: incremental findings");
            for (got, want) in found.iter().zip(&findings) {
                assert_eq!(got.range(), want.range(), "{id}");
                assert_eq!(got.action(), want.action(), "{id}");
                assert_eq!(got.type_name(), want.type_name(), "{id}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// host obligations that apply to the core
// ---------------------------------------------------------------------------

#[test]
fn the_host_obligations_that_apply_to_a_core_with_no_callback_boundary_hold() {
    let fixture = fixture();
    let obligations = array(&fixture, "hostObligations");
    assert_eq!(obligations.len(), 7);
    let ids: BTreeSet<&str> = obligations.iter().map(|each| text(each, "id")).collect();
    for id in [
        "legacy-callback-replaces-the-default",
        "legacy-callback-throws",
        "legacy-callback-invalid-action",
        "callback-and-action-policy-together",
        "invalid-document-fails-before-scanning",
        "session-binds-policy-at-construction",
        "no-process-global-policy-slot",
    ] {
        assert!(ids.contains(id), "{id}");
    }
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";

    // legacy-callback-replaces-the-default: a closure is the whole decision.
    let allow_all = |_: &DetectedFinding, _: &PolicyContext| Ok(Action::Allow);
    assert_eq!(
        scan(input, &registry, &allow_all).unwrap()[0].action(),
        Action::Allow
    );

    // legacy-callback-throws: the existing fixed code, with no overlay.
    let throws = |_: &DetectedFinding, _: &PolicyContext| Err(PolicyFailure);
    assert_eq!(
        scan(input, &registry, &throws).unwrap_err().code(),
        SecretScanErrorCode::PolicyFailure
    );

    // legacy-callback-invalid-action and callback-and-action-policy-together
    // have no Rust shape: `Action` is closed, and a call takes exactly one
    // `&dyn Policy`, so a callback and a document cannot both be supplied. The
    // bindings carry those two obligations.

    // invalid-document-fails-before-scanning: loading returns the whole policy
    // or the fixed code, never a partial policy.
    let rejected = load_action_policy(b"{").unwrap_err();
    assert_eq!(rejected.code().as_str(), text(&fixture, "errorCode"));

    // session-binds-policy-at-construction: a session keeps the policy it was
    // built with, whatever is built afterwards.
    let block_github = load_action_policy(
        br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"b","match":{"type":["github_token"]},"action":"block"}]}"#,
    )
    .unwrap();
    let allow_github = load_action_policy(
        br#"{"actionPolicyRevision":1,"base":"default","rules":[{"id":"a","match":{"type":["github_token"]},"action":"allow"}]}"#,
    )
    .unwrap();
    let mut session = IncrementalSanitizer::with_policy_and_formatter(
        limits(),
        Box::new(block_github.clone()),
        Box::new(default_placeholder_formatter),
    )
    .unwrap();
    let _later = allow_github.clone();
    let mut out = session.append(input).unwrap().text().to_owned();
    out.push_str(session.finalize().unwrap().text());
    assert_eq!(out, "API_KEY=<SECRET_1>");

    // no-process-global-policy-slot: two live policies, either construction
    // order, evaluate independently.
    for swap in [false, true] {
        let (first, second) = if swap {
            (allow_github.clone(), block_github.clone())
        } else {
            (block_github.clone(), allow_github.clone())
        };
        let a = scan(input, &registry, &first).unwrap()[0].action();
        let b = scan(input, &registry, &second).unwrap()[0].action();
        let (want_a, want_b) = if swap {
            (Action::Allow, Action::Block)
        } else {
            (Action::Block, Action::Allow)
        };
        assert_eq!((a, b), (want_a, want_b));
    }
}
