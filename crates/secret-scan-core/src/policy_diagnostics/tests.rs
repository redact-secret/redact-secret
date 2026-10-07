use super::*;
use crate::action_policy::load_action_policy;
use crate::manifest::ArtifactKind;
use crate::test_rng::XorShift32;
use crate::types::{ByteRange, Confidence, DetectedFinding, Obfuscation};

const TYPES: [&str; 3] = ["ta", "tb", "tc"];
const DETECTORS: [&str; 2] = ["da", "db"];
const CONFIDENCES: [(&str, Confidence); 3] = [
    ("high", Confidence::High),
    ("medium", Confidence::Medium),
    ("low", Confidence::Low),
];
const OBFUSCATIONS: [(&str, Obfuscation); 2] = [
    ("none", Obfuscation::None),
    ("invisible-characters", Obfuscation::InvisibleCharacters),
];
const ACTIONS: [&str; 5] = ["allow", "warn", "block", "redact", "default"];

fn subset(rng: &mut XorShift32, names: &[&str]) -> Option<String> {
    if rng.below(2) == 0 {
        return None;
    }
    let mut chosen: Vec<String> = names
        .iter()
        .filter(|_| rng.below(2) == 0)
        .map(|name| format!("\"{name}\""))
        .collect();
    if chosen.is_empty() {
        chosen.push(format!("\"{}\"", names[rng.below(names.len())]));
    }
    Some(format!("[{}]", chosen.join(",")))
}

fn random_document(rng: &mut XorShift32) -> String {
    let confidences: Vec<&str> = CONFIDENCES.iter().map(|(name, _)| *name).collect();
    let obfuscations: Vec<&str> = OBFUSCATIONS.iter().map(|(name, _)| *name).collect();
    let count = 1 + rng.below(6);
    let rules: Vec<String> = (0..count)
        .map(|index| {
            let mut keys: Vec<String> = [
                ("type", subset(rng, &TYPES)),
                ("detector", subset(rng, &DETECTORS)),
                ("confidence", subset(rng, &confidences)),
                ("obfuscation", subset(rng, &obfuscations)),
            ]
            .into_iter()
            .filter_map(|(key, set)| set.map(|set| format!("\"{key}\":{set}")))
            .collect();
            if keys.is_empty() {
                keys.push("\"type\":[\"ta\"]".to_owned());
            }
            let action = ACTIONS[rng.below(ACTIONS.len())];
            format!(
                "{{\"id\":\"r{index}\",\"match\":{{{}}},\"action\":\"{action}\"}}",
                keys.join(",")
            )
        })
        .collect();
    format!(
        "{{\"actionPolicyRevision\":1,\"base\":\"default\",\"rules\":[{}]}}",
        rules.join(",")
    )
}

fn universe() -> Vec<DetectedFinding> {
    let mut findings = Vec::new();
    for type_name in TYPES {
        for detector in DETECTORS {
            for (_, confidence) in CONFIDENCES {
                for (_, obfuscation) in OBFUSCATIONS {
                    findings.push(
                        DetectedFinding::new(
                            "finding-1",
                            type_name,
                            detector,
                            confidence,
                            ByteRange::new(0, 1).unwrap(),
                        )
                        .unwrap()
                        .with_obfuscation(obfuscation),
                    );
                }
            }
        }
    }
    findings
}

fn index_of(pointer: &str) -> usize {
    pointer
        .trim_start_matches("actionPolicy.rules[")
        .trim_end_matches(']')
        .parse()
        .unwrap()
}

/// Soundness against the real evaluator: over a universe that holds every
/// combination of the names the generated rules use, a rule reported as
/// shadowed never decides a finding, and the reported shadower matches every
/// finding the shadowed rule matches.
#[test]
fn a_shadowed_rule_never_decides_any_finding() {
    let manifest = ArtifactManifest::full(ArtifactKind::RustRegistry, false, None).unwrap();
    let enabled: Vec<&str> = manifest.detector_ids().collect();
    let universe = universe();
    let mut reported = 0;
    for seed in 1..=400 {
        let mut rng = XorShift32::new(seed);
        let text = random_document(&mut rng);
        let policy = load_action_policy(text.as_bytes()).unwrap();
        let mut out = Diagnostics::default();
        analyze(
            &policy,
            &Context {
                manifest: &manifest,
                enabled: &enabled,
                ruleset_ids: &[],
                ruleset_present: false,
                pii_active: false,
                closed_types: None,
                closed_detectors: None,
            },
            &mut out,
        );
        let (items, _) = out.finish();
        for item in items.iter().filter(|item| item.code() == SHADOWED_RULE) {
            reported += 1;
            let index = index_of(item.path());
            let earlier = index_of(item.related().unwrap());
            assert!(earlier < index, "{text}");
            let rules = policy.rules();
            for finding in &universe {
                if rules[index].matches(finding) {
                    assert!(rules[earlier].matches(finding), "{text}");
                }
                let (_, basis) = policy.explain(finding);
                assert_ne!(basis.rule_index(), Some(index), "{text}");
            }
        }
    }
    assert!(reported > 20, "the generator reported only {reported}");
}

/// Completeness on the generated universe is deliberately not claimed, but a
/// rule that no earlier single rule contains must not be reported: whenever
/// some finding decides a rule, that rule is never in the shadowed list.
#[test]
fn a_rule_that_decides_some_finding_is_never_reported() {
    let manifest = ArtifactManifest::full(ArtifactKind::RustRegistry, false, None).unwrap();
    let enabled: Vec<&str> = manifest.detector_ids().collect();
    let universe = universe();
    for seed in 1..=400_u32 {
        let mut rng = XorShift32::new(seed.wrapping_mul(7919));
        let text = random_document(&mut rng);
        let policy = load_action_policy(text.as_bytes()).unwrap();
        let mut out = Diagnostics::default();
        analyze(
            &policy,
            &Context {
                manifest: &manifest,
                enabled: &enabled,
                ruleset_ids: &[],
                ruleset_present: false,
                pii_active: false,
                closed_types: None,
                closed_detectors: None,
            },
            &mut out,
        );
        let (items, _) = out.finish();
        let decided: Vec<usize> = universe
            .iter()
            .filter_map(|finding| policy.explain(finding).1.rule_index())
            .collect();
        for item in items.iter().filter(|item| item.code() == SHADOWED_RULE) {
            assert!(!decided.contains(&index_of(item.path())), "{text}");
        }
    }
}
