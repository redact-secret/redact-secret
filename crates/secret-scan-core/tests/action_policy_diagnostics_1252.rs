//! The action policy diagnostic layer (issue #1252): `resolve_config` reports
//! what a revision-1 policy leaves silent, without changing how the policy
//! loads, and says "uncertain" where it cannot prove anything.
//!
//! The shared cases (typo, unavailable versus unknown, shadowing, partial
//! overlap, callback) live in `conformance/fixtures/runtime-config-v1.json` and
//! run on every surface. This file also covers the Rust builder vocabulary,
//! sample hits and the bounds. Every document is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    ArtifactKind, ArtifactManifest, ConfigDiagnostic, ConfigRequest, ConfigResolution,
    DecisionBasis, MAX_ACTION_POLICY_BYTES, SampleRuleHits, load_action_policy, resolve_config,
};
use serde_json::Value;

fn manifest(profile: &str) -> ArtifactManifest {
    match profile {
        "full" => ArtifactManifest::full(ArtifactKind::RustRegistry, true, None).unwrap(),
        _ => ArtifactManifest::common(ArtifactKind::RustRegistry, true, None).unwrap(),
    }
}

fn policy(rules: &[&str]) -> String {
    format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{}]}}"#,
        rules.join(",")
    )
}

fn resolve(profile: &str, config: Option<&str>, policy: &str) -> ConfigResolution {
    let mut request = ConfigRequest::new().action_policy(policy.as_bytes());
    if let Some(config) = config {
        request = request.runtime_config(config);
    }
    resolve_config(&manifest(profile), &request)
}

fn codes(resolution: &ConfigResolution) -> Vec<&str> {
    resolution
        .diagnostics()
        .iter()
        .map(ConfigDiagnostic::code)
        .collect()
}

#[test]
fn a_typo_loads_unchanged_and_is_reported_only_by_the_diagnostic_layer() {
    let document = policy(&[r#"{"id":"tighten","match":{"type":["jwt_tokne"]},"action":"block"}"#]);
    // Revision 1 still accepts the unknown name: the parser is unchanged.
    assert!(load_action_policy(document.as_bytes()).is_ok());

    let resolution = resolve("full", None, &document);
    assert!(resolution.is_ok());
    assert_eq!(codes(&resolution), ["ACTION_POLICY_UNKNOWN_TYPE"]);
    let item = &resolution.diagnostics()[0];
    assert_eq!(item.severity().as_str(), "warning");
    assert_eq!(item.path(), "actionPolicy.rules[0].match.type[0]");
    assert_eq!(item.id(), None);
    // The name the user typed is never echoed, only its position.
    assert!(!resolution.as_json().contains("jwt_tokne"));
    // The policy identity is the digest of the bytes a call would load.
    let snapshot: Value = serde_json::from_str(resolution.snapshot().unwrap().as_json()).unwrap();
    assert_eq!(snapshot["actionPolicy"]["ruleCount"], 1);
}

#[test]
fn unavailable_and_unknown_detectors_are_distinct() {
    let rule = |name: &str| {
        policy(&[&format!(
            r#"{{"id":"r","match":{{"detector":["{name}"]}},"action":"block"}}"#
        )])
    };
    // Compiled but disabled: the id is the catalog's own.
    let disabled = resolve(
        "full",
        Some(r#"{"detection":{"exclude":["github-token"]}}"#),
        &rule("github-token"),
    );
    let item = disabled
        .diagnostics()
        .iter()
        .find(|item| item.code() == "ACTION_POLICY_RULE_ON_UNENABLED_DETECTOR")
        .expect("a disabled detector is reported");
    assert_eq!(item.id(), Some("github-token"));
    assert_eq!(item.path(), "actionPolicy.rules[0].match.detector[0]");

    // Known to the catalog but not compiled into this artifact.
    let common = manifest("common");
    assert!(common.not_included_ids().any(|id| id == "github-token"));
    let absent = resolve("common", None, &rule("github-token"));
    assert_eq!(
        codes(&absent),
        ["ACTION_POLICY_RULE_ON_NOT_INCLUDED_DETECTOR"]
    );
    assert_eq!(absent.diagnostics()[0].id(), Some("github-token"));

    // Not known at all: no catalog id is attached, and nothing is echoed.
    let unknown = resolve("full", None, &rule("github-tokne"));
    assert_eq!(codes(&unknown), ["ACTION_POLICY_UNKNOWN_DETECTOR"]);
    assert_eq!(unknown.diagnostics()[0].id(), None);
    assert!(!unknown.as_json().contains("github-tokne"));

    // An enabled detector is silent.
    assert!(codes(&resolve("full", None, &rule("github-token"))).is_empty());
}

#[test]
fn a_type_only_a_disabled_detector_declares_is_reported_as_that_detector() {
    let document = policy(&[r#"{"id":"r","match":{"type":["jwt"]},"action":"block"}"#]);
    let resolution = resolve(
        "full",
        Some(r#"{"detection":{"exclude":["jwt"]}}"#),
        &document,
    );
    let item = resolution
        .diagnostics()
        .iter()
        .find(|item| item.code() == "ACTION_POLICY_RULE_ON_UNENABLED_DETECTOR")
        .unwrap();
    assert_eq!(item.id(), Some("jwt"));
    assert_eq!(item.path(), "actionPolicy.rules[0].match.type[0]");
}

#[test]
fn a_shadowed_rule_names_its_own_id_and_the_earlier_rule() {
    let document = policy(&[
        r#"{"id":"broad","match":{"type":["jwt"]},"action":"default"}"#,
        r#"{"id":"narrow","match":{"type":["jwt"],"confidence":["high"]},"action":"block"}"#,
    ]);
    let resolution = resolve("full", None, &document);
    assert_eq!(codes(&resolution), ["ACTION_POLICY_SHADOWED_RULE"]);
    let item = &resolution.diagnostics()[0];
    assert_eq!(item.path(), "actionPolicy.rules[1]");
    assert_eq!(item.id(), Some("narrow"));
    assert_eq!(item.related(), Some("actionPolicy.rules[0]"));
    let envelope: Value = serde_json::from_str(resolution.as_json()).unwrap();
    let wire = &envelope["diagnostics"]["items"][0];
    assert_eq!(wire["id"], "narrow");
    assert_eq!(wire["related"], "actionPolicy.rules[0]");
    // Other diagnostics carry no `related` member.
    let typo = resolve(
        "full",
        None,
        &policy(&[r#"{"id":"t","match":{"type":["nope"]},"action":"warn"}"#]),
    );
    let envelope: Value = serde_json::from_str(typo.as_json()).unwrap();
    assert!(envelope["diagnostics"]["items"][0].get("related").is_none());
}

#[test]
fn a_rule_that_stops_evaluation_shadows_whether_fixed_or_default_and_order_matters() {
    for action in ["default", "allow"] {
        let early = policy(&[
            &format!(r#"{{"id":"early","match":{{"type":["jwt"]}},"action":"{action}"}}"#),
            r#"{"id":"late","match":{"type":["jwt"]},"action":"block"}"#,
        ]);
        assert_eq!(
            codes(&resolve("full", None, &early)),
            ["ACTION_POLICY_SHADOWED_RULE"],
            "{action}"
        );
    }
    // The narrow rule first leaves the broad one reachable.
    let narrow_first = policy(&[
        r#"{"id":"narrow","match":{"type":["jwt"],"confidence":["high"]},"action":"block"}"#,
        r#"{"id":"broad","match":{"type":["jwt"]},"action":"default"}"#,
    ]);
    assert!(codes(&resolve("full", None, &narrow_first)).is_empty());
    // A document whose rules never match falls to the base without a finding.
    let fallback = policy(&[r#"{"id":"only","match":{"type":["jwt"]},"action":"warn"}"#]);
    assert!(codes(&resolve("full", None, &fallback)).is_empty());
}

#[test]
fn an_empty_or_default_policy_has_nothing_to_analyze() {
    assert!(codes(&resolve("full", None, &policy(&[]))).is_empty());
    let none = resolve_config(&manifest("full"), &ConfigRequest::new());
    assert!(codes(&none).is_empty());
}

#[test]
fn open_vocabulary_sources_make_an_unknown_type_uncertain_not_a_typo() {
    let document =
        policy(&[r#"{"id":"r","match":{"type":["acme_internal_token"]},"action":"block"}"#]);
    // A ruleset can emit types no catalog names.
    let ruleset = b"ruleset-revision: 1\ndetector: acme-internal-token\nspecificity: contextual\nprefix: \"ACME_\"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n";
    let with_ruleset = resolve_config(
        &manifest("full"),
        &ConfigRequest::new()
            .action_policy(document.as_bytes())
            .ruleset(ruleset),
    );
    assert!(with_ruleset.is_ok());
    assert_eq!(codes(&with_ruleset), ["ACTION_POLICY_ANALYSIS_UNCERTAIN"]);
    assert_eq!(with_ruleset.diagnostics()[0].severity().as_str(), "info");
    // PII emits types no catalog names either.
    let with_pii = resolve("full", Some(r#"{"pii":["pii:global"]}"#), &document);
    assert_eq!(codes(&with_pii), ["ACTION_POLICY_ANALYSIS_UNCERTAIN"]);
    // A rule naming a supplied ruleset's detector is known.
    let named =
        policy(&[r#"{"id":"r","match":{"detector":["acme-internal-token"]},"action":"block"}"#]);
    let resolved = resolve_config(
        &manifest("full"),
        &ConfigRequest::new()
            .action_policy(named.as_bytes())
            .ruleset(ruleset),
    );
    assert!(codes(&resolved).is_empty());
    // A callback cannot be read at all.
    let callback = resolve_config(&manifest("full"), &ConfigRequest::new().callback_policy());
    assert_eq!(codes(&callback), ["ACTION_POLICY_ANALYSIS_UNCERTAIN"]);
    assert_eq!(callback.diagnostics()[0].path(), "actionPolicy");
}

#[test]
fn shadowing_stays_provable_for_names_the_catalog_has_never_heard_of() {
    // Containment compares the documents' own strings, so an open-vocabulary
    // name is as decidable as a known one.
    let document = policy(&[
        r#"{"id":"a","match":{"type":["custom_one","custom_two"]},"action":"warn"}"#,
        r#"{"id":"b","match":{"type":["custom_two"]},"action":"block"}"#,
    ]);
    let resolution = resolve("full", None, &document);
    let shadowed: Vec<&str> = resolution
        .diagnostics()
        .iter()
        .filter(|item| item.code() == "ACTION_POLICY_SHADOWED_RULE")
        .map(ConfigDiagnostic::path)
        .collect();
    assert_eq!(shadowed, ["actionPolicy.rules[1]"]);
}

#[test]
fn strict_validation_exists_only_with_a_declared_closed_vocabulary() {
    let document = policy(&[
        r#"{"id":"typo","match":{"type":["jwt_tokne"]},"action":"block"}"#,
        r#"{"id":"mine","match":{"type":["acme_internal_token"],"detector":["acme-detector"]},"action":"warn"}"#,
    ]);
    // Without a declaration: warnings only, and the resolution succeeds.
    let open = resolve("full", None, &document);
    assert!(open.is_ok());
    assert!(
        open.diagnostics()
            .iter()
            .all(|item| item.severity().as_str() == "warning")
    );
    // With a closed vocabulary the same typo is an error and the type the
    // caller declared is accepted.
    let types = ["acme_internal_token"];
    let detectors = ["acme-detector"];
    let strict = resolve_config(
        &manifest("full"),
        &ConfigRequest::new()
            .action_policy(document.as_bytes())
            .closed_types(&types)
            .closed_detectors(&detectors),
    );
    assert!(!strict.is_ok());
    assert!(strict.snapshot().is_none());
    assert_eq!(codes(&strict), ["ACTION_POLICY_UNKNOWN_TYPE"]);
    assert_eq!(strict.diagnostics()[0].severity().as_str(), "error");
    assert_eq!(
        strict.diagnostics()[0].path(),
        "actionPolicy.rules[0].match.type[0]"
    );
    // An undeclared detector is an error only under a declared detector set.
    let only_detectors =
        policy(&[r#"{"id":"d","match":{"detector":["acme-other"]},"action":"warn"}"#]);
    let strict_detector = resolve_config(
        &manifest("full"),
        &ConfigRequest::new()
            .action_policy(only_detectors.as_bytes())
            .closed_detectors(&detectors),
    );
    assert_eq!(codes(&strict_detector), ["ACTION_POLICY_UNKNOWN_DETECTOR"]);
    assert!(!strict_detector.is_ok());
    // The parser itself is not strict.
    assert!(load_action_policy(document.as_bytes()).is_ok());
}

#[test]
fn a_v2_document_cannot_replace_a_rust_builder_vocabulary() {
    for (config, request) in [
        (
            r#"{"schema":"runtime-config/v2","closedTypes":[]}"#,
            ConfigRequest::new().closed_types(&["synthetic_internal_type"]),
        ),
        (
            r#"{"schema":"runtime-config/v2","closedDetectors":[]}"#,
            ConfigRequest::new().closed_detectors(&["synthetic-detector"]),
        ),
    ] {
        let resolution = resolve_config(&manifest("full"), &request.runtime_config(config));
        assert!(!resolution.is_ok());
        assert!(resolution.snapshot().is_none());
        assert_eq!(codes(&resolution), ["INVALID_OPTIONS"]);
    }
}

#[test]
fn output_is_bounded_and_the_cut_is_reported() {
    // 90 rules of 100 unknown types each: 9,000 findings from a document
    // under the 64 KiB bound.
    let rules: Vec<String> = (0..90)
        .map(|rule| {
            let members: Vec<String> = (0..100).map(|member| format!("\"x{member}\"")).collect();
            format!(
                r#"{{"id":"r{rule}","match":{{"type":[{}]}},"action":"warn"}}"#,
                members.join(",")
            )
        })
        .collect();
    let document = format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{}]}}"#,
        rules.join(",")
    );
    assert!(document.len() < MAX_ACTION_POLICY_BYTES);
    let resolution = resolve("full", None, &document);
    assert!(resolution.is_ok());
    assert_eq!(resolution.diagnostics().len(), 256);
    let envelope: Value = serde_json::from_str(resolution.as_json()).unwrap();
    assert_eq!(envelope["diagnostics"]["truncated"], true);
    assert_eq!(
        envelope["diagnostics"]["items"].as_array().unwrap().len(),
        256
    );
    // Errors are kept ahead of everything the bound cuts.
    let strict_types = ["x0"];
    let strict = resolve_config(
        &manifest("full"),
        &ConfigRequest::new()
            .action_policy(document.as_bytes())
            .closed_types(&strict_types),
    );
    assert!(!strict.is_ok());
    assert_eq!(strict.diagnostics().len(), 256);
    assert!(
        strict
            .diagnostics()
            .iter()
            .all(|item| item.severity().as_str() == "error")
    );
}

#[test]
fn a_maximal_all_shadowing_policy_is_analyzed_within_bounds() {
    // 128 identical rules: every later rule is shadowed, 127 findings, and
    // the pairwise search stays small because it stops at the first shadower.
    let rule = |index: usize| {
        format!(r#"{{"id":"r{index}","match":{{"type":["jwt","private_key"]}},"action":"warn"}}"#)
    };
    let rules: Vec<String> = (0..128).map(rule).collect();
    let document = format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{}]}}"#,
        rules.join(",")
    );
    let resolution = resolve("full", None, &document);
    assert!(resolution.is_ok());
    assert_eq!(resolution.diagnostics().len(), 127);
    assert!(
        resolution
            .diagnostics()
            .iter()
            .all(|item| item.related() == Some("actionPolicy.rules[0]"))
    );
}

#[test]
fn oversized_or_malformed_policies_are_invalid_syntax_not_analysis() {
    let oversized = format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{}]}}"#,
        "x".repeat(MAX_ACTION_POLICY_BYTES)
    );
    let resolution = resolve("full", None, &oversized);
    assert!(!resolution.is_ok());
    assert_eq!(codes(&resolution), ["INVALID_ACTION_POLICY"]);
    assert_eq!(resolution.diagnostics()[0].path(), "actionPolicy");

    let malformed = resolve("full", None, "{not json");
    assert_eq!(codes(&malformed), ["INVALID_ACTION_POLICY"]);
    assert!(!malformed.as_json().contains("not json"));

    // 129 rules: the existing bound, reported at the first rule over it.
    let rules: Vec<String> = (0..129)
        .map(|index| format!(r#"{{"id":"r{index}","match":{{"type":["jwt"]}},"action":"warn"}}"#))
        .collect();
    let over = format!(
        r#"{{"actionPolicyRevision":1,"base":"default","rules":[{}]}}"#,
        rules.join(",")
    );
    let too_many = resolve("full", None, &over);
    assert_eq!(codes(&too_many), ["INVALID_ACTION_POLICY"]);
}

#[test]
fn sample_hits_are_kept_apart_from_static_reachability() {
    let document = policy(&[
        r#"{"id":"first","match":{"type":["jwt"]},"action":"warn"}"#,
        r#"{"id":"second","match":{"type":["private_key"]},"action":"block"}"#,
        r#"{"id":"third","match":{"type":["jwt"]},"action":"block"}"#,
    ]);
    let loaded = load_action_policy(document.as_bytes()).unwrap();
    let mut hits = SampleRuleHits::for_policy(&loaded);
    hits.record(&DecisionBasis::Rule {
        rule_id: "first".to_owned(),
        rule_index: 0,
    });
    hits.record(&DecisionBasis::RuleDefault {
        rule_id: "first".to_owned(),
        rule_index: 0,
    });
    hits.record(&DecisionBasis::NoRuleMatched);
    hits.record(&DecisionBasis::Callback);
    hits.record(&DecisionBasis::Rule {
        rule_id: "ghost".to_owned(),
        rule_index: 99,
    });
    assert_eq!(hits.rule_hits(), &[2, 0, 0]);
    assert_eq!(hits.no_rule_matched(), 1);
    assert_eq!(hits.unhit_rules().collect::<Vec<_>>(), [1, 2]);

    // Rule 1 had no hit and is not reported: no sample hit proves nothing.
    // Rule 2 had no hit and is reported: because rule 0 provably contains it,
    // not because of the samples.
    let resolution = resolve("full", None, &document);
    let shadowed: Vec<&str> = resolution
        .diagnostics()
        .iter()
        .map(ConfigDiagnostic::path)
        .collect();
    assert_eq!(shadowed, ["actionPolicy.rules[2]"]);
    // The analysis cannot see the samples: it is the same with or without them.
    assert_eq!(
        resolve("full", None, &document).as_json(),
        resolution.as_json()
    );
}

#[test]
fn resolution_with_diagnostics_is_pure() {
    let document = policy(&[
        r#"{"id":"a","match":{"type":["jwt"]},"action":"default"}"#,
        r#"{"id":"b","match":{"type":["jwt"]},"action":"warn"}"#,
        r#"{"id":"c","match":{"detector":["nope"]},"action":"warn"}"#,
    ]);
    let first = resolve("full", None, &document);
    let second = resolve("full", None, &document);
    assert_eq!(first.as_json(), second.as_json());
    assert_eq!(
        codes(&first),
        [
            "ACTION_POLICY_SHADOWED_RULE",
            "ACTION_POLICY_UNKNOWN_DETECTOR"
        ]
    );
}
