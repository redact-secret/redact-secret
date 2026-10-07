//! `compare_configurations` (issue #1254, `configuration-comparison/v1`).
//!
//! The shared cases live in `conformance/fixtures/configuration-compare-v1.json`
//! and are run here against the Rust core and, separately, by every JavaScript
//! runtime that loads a binding. Every input is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    Action, ActionPolicy, ArtifactKind, ArtifactManifest, ComparedPolicy, ConfigRequest,
    ConfigSnapshot, ConfigurationComparison, ConfigurationSide, DetectedFinding, DetectorRegistry,
    Policy, PolicyContext, PolicyFailure, SecretScanErrorCode, compare_configurations,
    load_action_policy, load_ruleset, resolve_config,
};
use serde_json::{Value, json};
use std::cell::RefCell;

const FIXTURE: &str = include_str!("../../../conformance/fixtures/configuration-compare-v1.json");

fn manifest(profile: &str) -> ArtifactManifest {
    match profile {
        "full" => ArtifactManifest::full(ArtifactKind::RustRegistry, true, None).unwrap(),
        "common" => ArtifactManifest::common(ArtifactKind::RustRegistry, true, None).unwrap(),
        other => panic!("unknown profile {other}"),
    }
}

/// One fixture side, built the way a Rust caller builds a temporary
/// registry from a resolved snapshot.
struct Built {
    snapshot: Result<ConfigSnapshot, &'static str>,
    registry: Option<DetectorRegistry>,
    policy: Option<ActionPolicy>,
}

fn text_of(value: &Value) -> Vec<u8> {
    match value {
        Value::String(text) => text.clone().into_bytes(),
        other => serde_json::to_vec(other).unwrap(),
    }
}

fn build(profile: &str, side: &Value, shared: Option<&Value>) -> Built {
    let manifest = manifest(profile);
    let config = side
        .get("config")
        .map(|config| serde_json::to_string(config).unwrap());
    let ruleset = side.get("ruleset").map(text_of);
    let policy_bytes = side.get("actionPolicy").or(shared).map(text_of);
    let mut request = ConfigRequest::new();
    if let Some(config) = &config {
        request = request.runtime_config(config);
    }
    if let Some(bytes) = &ruleset {
        request = request.ruleset(bytes);
    }
    if let Some(bytes) = &policy_bytes {
        request = request.action_policy(bytes);
    }
    let resolution = resolve_config(&manifest, &request);
    let policy = policy_bytes
        .as_deref()
        .map(|bytes| load_action_policy(bytes).unwrap());
    let Some(snapshot) = resolution.snapshot() else {
        let code = resolution.diagnostics()[0].code();
        return Built {
            snapshot: Err(code),
            registry: None,
            policy,
        };
    };
    if snapshot.is_inert() {
        return Built {
            snapshot: Err("EMPTY_DETECTION_SET"),
            registry: None,
            policy,
        };
    }
    let pii = snapshot.pii_selection();
    let detectors = ruleset
        .as_deref()
        .map(|bytes| load_ruleset(bytes).unwrap())
        .unwrap_or_default();
    let registry = match profile {
        "full" => DetectorRegistry::with_built_in_and_pii_custom(pii, detectors),
        _ => DetectorRegistry::with_common_built_in_and_pii_custom(pii, detectors),
    }
    .unwrap()
    .with_detection(snapshot.detection_selection())
    .unwrap();
    Built {
        snapshot: Ok(snapshot.clone()),
        registry: Some(registry),
        policy,
    }
}

fn run_case(profile: &str, case: &Value) -> (String, ConfigurationComparison) {
    let input = case["input"].as_str().unwrap().to_owned();
    let shared = case.get("actionPolicy");
    let built: Vec<Built> = case["sides"]
        .as_array()
        .unwrap()
        .iter()
        .map(|side| build(profile, side, shared))
        .collect();
    let sides: Vec<ConfigurationSide<'_>> = built
        .iter()
        .map(|built| {
            let policy = built
                .policy
                .as_ref()
                .map_or(ComparedPolicy::Default, ComparedPolicy::ActionPolicy);
            match (&built.snapshot, &built.registry) {
                (Ok(snapshot), Some(registry)) => ConfigurationSide::new(registry, policy)
                    .with_limits(snapshot.whole_input_limits())
                    .with_snapshot(snapshot),
                (Err(code), _) => ConfigurationSide::failed(code, policy),
                _ => unreachable!(),
            }
        })
        .collect();
    let comparison = compare_configurations(&input, &sides).unwrap();
    (input, comparison)
}

/// The fixture's projection: status, failure, findings in code points and the
/// differences, with nothing the fixture does not pin.
fn project(input: &str, comparison: &ConfigurationComparison) -> Value {
    let points = |byte: usize| input[..byte].chars().count();
    let sides: Vec<Value> = comparison
        .sides()
        .iter()
        .map(|side| {
            let findings: Vec<Value> = side
                .findings()
                .iter()
                .map(|compared| {
                    let finding = compared.finding();
                    json!({
                        "type": finding.type_name(),
                        "detector": finding.detector(),
                        "range": [points(finding.range().start()), points(finding.range().end())],
                    })
                })
                .collect();
            json!({
                "status": side.status().as_str(),
                "failure": side.failure(),
                "findings": findings,
            })
        })
        .collect();
    let differences: Vec<Value> = comparison
        .differences()
        .iter()
        .map(|differences| {
            differences.as_ref().map_or(Value::Null, |differences| {
                let entries: Vec<Value> = differences
                    .entries()
                    .iter()
                    .map(|entry| {
                        json!({
                            "kind": entry.kind().as_str(),
                            "correspondence": entry.correspondence().map(redact_secret::Correspondence::as_str),
                            "base": entry.base(),
                            "other": entry.other(),
                            "changes": entry.changes().collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                json!({ "unchanged": differences.unchanged(), "entries": entries })
            })
        })
        .collect();
    json!({ "sides": sides, "differences": differences })
}

#[test]
fn every_fixture_case_relates_the_sides_as_expected() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(fixture["schema"], "configuration-comparison-conformance/v1");
    let print = std::env::var_os("PRINT_CONFIGURATION_COMPARE").is_some();
    let mut actuals = serde_json::Map::new();
    let mut ran = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        for profile in case["profiles"].as_array().unwrap() {
            let profile = profile.as_str().unwrap();
            let (input, comparison) = run_case(profile, case);
            let actual = project(&input, &comparison);
            if print {
                actuals.insert(format!("{name}|{profile}"), actual.clone());
            } else {
                assert_eq!(actual, case["expect"][profile], "{name} [{profile}]");
            }
            ran += 1;
        }
    }
    if print {
        println!(
            "{}",
            serde_json::to_string_pretty(&Value::Object(actuals)).unwrap()
        );
    }
    assert!(ran >= 20);
}

#[test]
fn different_rulesets_have_distinct_identities_though_policy_bytes_match() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "different-rulesets-stay-distinct-when-policy-bytes-match")
        .unwrap();
    let (_, comparison) = run_case("full", case);
    let (a, b) = (&comparison.sides()[0], &comparison.sides()[1]);
    assert_ne!(a.detection_digest(), b.detection_digest());
    assert_ne!(a.digest(), b.digest());
    assert!(
        a.detection_digest()
            .is_some_and(|d| d.starts_with("sha256:"))
    );
    // The same policy document bytes on both sides: the same policy identity.
    assert_eq!(a.policy(), b.policy());
    assert!(a.policy().document_sha256().is_some());
}

#[test]
fn an_output_carries_neither_the_input_nor_a_matched_value() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let (input, comparison) = run_case("full", case);
        let rendered = format!("{comparison:?}");
        // Neither the input, nor any token-shaped run of it, nor a hash of one.
        for word in input.split_whitespace().filter(|word| word.len() >= 12) {
            assert!(!rendered.contains(word), "{word}");
        }
        assert!(!rendered.contains(&input));
    }
}

struct Recording<'a>(&'a RefCell<Vec<String>>, &'static str);
impl Policy for Recording<'_> {
    fn evaluate(
        &self,
        _: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        self.0
            .borrow_mut()
            .push(format!("{}{}", self.1, context.finding_index()));
        Ok(Action::Warn)
    }
}

#[test]
fn sides_run_in_order_and_a_callback_sees_scans_call_sequence() {
    let input = "a eyJhbGciOiJub25lIn0.eyJzdWIiOiJTWU5USEVUSUMifQ.SYNTHETIC_REVOKED_SIG_00 b";
    let log = RefCell::new(Vec::new());
    let (first, second) = (Recording(&log, "A"), Recording(&log, "B"));
    let all = DetectorRegistry::with_built_in([]).unwrap();
    let comparison = compare_configurations(
        input,
        &[
            ConfigurationSide::new(&all, ComparedPolicy::Callback(&first)),
            ConfigurationSide::new(&all, ComparedPolicy::Callback(&second)),
        ],
    )
    .unwrap();
    // Side 0 once for its one finding, then side 1 once for its own.
    assert_eq!(log.borrow().as_slice(), ["A0", "B0"]);
    assert_eq!(comparison.sides()[0].policy().kind(), "callback");
    assert_eq!(comparison.sides()[0].policy().document_sha256(), None);
}

#[test]
fn a_callback_failure_fails_the_whole_comparison_and_stops_later_sides() {
    struct Failing;
    impl Policy for Failing {
        fn evaluate(
            &self,
            _: &DetectedFinding,
            _: &PolicyContext,
        ) -> Result<Action, PolicyFailure> {
            Err(PolicyFailure)
        }
    }
    let input = "a eyJhbGciOiJub25lIn0.eyJzdWIiOiJTWU5USEVUSUMifQ.SYNTHETIC_REVOKED_SIG_00 b";
    let log = RefCell::new(Vec::new());
    let later = Recording(&log, "B");
    let all = DetectorRegistry::with_built_in([]).unwrap();
    let error = compare_configurations(
        input,
        &[
            ConfigurationSide::new(&all, ComparedPolicy::Callback(&Failing)),
            ConfigurationSide::new(&all, ComparedPolicy::Callback(&later)),
        ],
    )
    .unwrap_err();
    assert!(log.borrow().is_empty());
    assert_eq!(error.code(), SecretScanErrorCode::PolicyFailure);
}

#[test]
fn the_side_count_is_bounded() {
    let all = DetectorRegistry::with_built_in([]).unwrap();
    let side = || ConfigurationSide::new(&all, ComparedPolicy::Default);
    assert_eq!(
        compare_configurations("x", &[]).unwrap_err().code(),
        SecretScanErrorCode::InvalidOptions
    );
    let five = [side(), side(), side(), side(), side()];
    assert_eq!(
        compare_configurations("x", &five).unwrap_err().code(),
        SecretScanErrorCode::InvalidOptions
    );
    assert!(compare_configurations("x", &five[..4]).is_ok());
}
