//! Tests of the non-enforcing shadow comparison (issue #771). Every value is
//! synthetic.

use super::*;
use crate::DEFAULT_MAX_INPUT_BYTES;
use crate::evidence::aggregate::{EvidenceExplanation, ShadowInputs, aggregate};
use crate::evidence::context::ContextClass;
use crate::incremental::{IncrementalLimits, IncrementalSanitizer};
use crate::pipeline::run_detector_pipeline;
use crate::policy::DefaultPolicy;
use crate::types::{DetectedFinding, Policy, PolicyContext};

/// A random-looking synthetic value with 32 distinct symbols (5 bits per
/// symbol, above the randomness ramp's upper end).
const RANDOM_VALUE: &str = "Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa";
/// A low-entropy synthetic value that `generic-token` still accepts after a
/// high-signal name.
const HUMAN_VALUE: &str = "hunter2hunter2";
const GITHUB_TOKEN: &str = "ghp_SYNTHETICREVOKED00000000000000000000";
const PRIVATE_KEY: &str =
    "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDX1NIQURPV19URVNUX0tFWQ==\n-----END PRIVATE KEY-----";
const VENDOR_PREFIXED: &str = "sk-SYNTHETICrevoked0001aaaaBBBBccccDDDD1234wxyzEFGH";

/// Inputs that exercise every authority and several context classes,
/// alone and together.
fn battery() -> Vec<String> {
    vec![
        String::new(),
        "plain text with nothing in it\n".to_owned(),
        format!("API_KEY={RANDOM_VALUE}"),
        format!("password: \"{HUMAN_VALUE}\"\n"),
        format!("auth_token = {RANDOM_VALUE}\nnext line\n"),
        format!("token={GITHUB_TOKEN}"),
        format!("{PRIVATE_KEY}\n"),
        format!("Authorization: Bearer {RANDOM_VALUE}\n"),
        "postgres://fakeuser:Zp9LxR4tWb8NcY3h@db.example.invalid:5432/app\n".to_owned(),
        VENDOR_PREFIXED.to_owned(),
        "API_KEY=Q7vK2mZp9LxR4tWb\u{200B}8NcY3hJd6FsG1eUa\n".to_owned(),
        format!(
            "API_KEY={RANDOM_VALUE}\ntoken={GITHUB_TOKEN}\npassword: \"{HUMAN_VALUE}\"\n{PRIVATE_KEY}\nAuthorization: Bearer {RANDOM_VALUE}\n{VENDOR_PREFIXED}\n"
        ),
    ]
}

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

fn comparisons(input: &str) -> (Vec<DetectedFinding>, Vec<ShadowComparison>) {
    let mut shadow = Vec::new();
    let findings = crate::pipeline::detect(input, &registry(), Some(&mut shadow)).unwrap();
    (findings, shadow)
}

/// The single comparison of `input` whose detector is `detector`.
fn only_from(input: &str, detector: &str) -> ShadowComparison {
    let (_, shadow) = comparisons(input);
    let matching: Vec<_> = shadow
        .into_iter()
        .filter(|comparison| comparison.detector == detector)
        .collect();
    assert_eq!(matching.len(), 1, "{input:?}: {matching:?}");
    matching.into_iter().next().unwrap()
}

fn explanation(comparison: &ShadowComparison) -> EvidenceExplanation {
    comparison.shadow.explanation.unwrap()
}

// --- legacy outputs are unchanged ------------------------------------------

#[test]
fn recording_the_shadow_changes_no_legacy_finding() {
    for input in battery() {
        let legacy = run_detector_pipeline(&input, &registry()).unwrap();
        let (recorded, shadow) = comparisons(&input);
        assert_eq!(recorded, legacy, "{input:?}");
        let unrecorded = crate::pipeline::detect(&input, &registry(), None).unwrap();
        assert_eq!(unrecorded, legacy, "{input:?}");

        // One comparison per finding, in finding order, carrying the legacy
        // decision exactly as the finding and the default policy have it.
        assert_eq!(shadow.len(), legacy.len(), "{input:?}");
        for (index, (finding, comparison)) in legacy.iter().zip(&shadow).enumerate() {
            assert_eq!(comparison.finding_index, index);
            assert_eq!(finding.id(), format!("finding-{}", index + 1));
            assert_eq!(comparison.range, finding.range());
            assert_eq!(comparison.detector, finding.detector());
            assert_eq!(comparison.type_name, finding.type_name());
            assert_eq!(comparison.legacy_confidence, finding.confidence());
            let context = PolicyContext::new(index, legacy.len());
            assert_eq!(
                comparison.legacy_action,
                DefaultPolicy.evaluate(finding, &context).unwrap()
            );
        }
    }
}

#[test]
fn the_evaluation_path_applies_the_default_whole_input_limits() {
    let oversized = "a".repeat(DEFAULT_MAX_INPUT_BYTES + 1);
    assert_eq!(
        shadow_evaluation_jsonl("big", &oversized, &registry()),
        "{\"record\":\"shadow-error\",\"input\":\"big\",\"code\":\"INPUT_LIMIT_EXCEEDED\"}\n"
    );
    assert_eq!(shadow_evaluation_jsonl("empty", "", &registry()), "");
}

// --- generic-token candidates are scored under SHADOW_MODEL ------------------

#[test]
fn a_credential_name_assignment_is_scored_with_context_and_randomness() {
    let comparison = only_from(&format!("API_KEY={RANDOM_VALUE}"), "generic-token");
    assert_eq!(comparison.type_name, "contextual_secret");
    assert_eq!(comparison.specificity, Specificity::Contextual);
    assert_eq!(comparison.shadow.authority, ShadowAuthority::Statistical);

    let explanation = explanation(&comparison);
    let expected = aggregate(
        &SHADOW_MODEL,
        &ShadowInputs::of_value(RANDOM_VALUE, ContextClass::CredentialName),
    );
    assert_eq!(explanation, expected);
    assert_eq!(explanation.context, ContextClass::CredentialName);
    assert_eq!(
        explanation.groups[EvidenceGroup::Contextual as usize].contribution,
        50
    );
    assert_eq!(
        explanation.groups[EvidenceGroup::Randomness as usize].contribution,
        30
    );
    assert_eq!(explanation.score, 80);
    assert_eq!(comparison.shadow.band, ShadowBand::High);
    assert_eq!(
        comparison.promotion,
        PromotionOutcome::of(ShadowBand::High, comparison.legacy_confidence)
    );
    assert_eq!(
        comparison.reasons(),
        ["credential-context", "randomness-capped"]
    );
}

#[test]
fn a_low_entropy_credential_name_assignment_has_context_only() {
    let comparison = only_from(&format!("password: \"{HUMAN_VALUE}\"\n"), "generic-token");
    let explanation = explanation(&comparison);
    assert_eq!(
        explanation,
        aggregate(
            &SHADOW_MODEL,
            &ShadowInputs::of_value(HUMAN_VALUE, ContextClass::CredentialName)
        )
    );
    assert_eq!(
        explanation.groups[EvidenceGroup::Randomness as usize].contribution,
        0
    );
    // Context alone (50) is `medium` under SHADOW_MODEL.
    assert_eq!(comparison.shadow.band, ShadowBand::Medium);
    assert_eq!(
        comparison.reasons(),
        ["credential-context", "randomness-none"]
    );
}

#[test]
fn a_bare_vendor_prefixed_candidate_is_bare_and_never_reaches_high() {
    let comparison = only_from(VENDOR_PREFIXED, "generic-token");
    assert_eq!(comparison.type_name, "vendor_prefixed_credential");
    assert_eq!(comparison.specificity, Specificity::Entropy);
    let explanation = explanation(&comparison);
    assert_eq!(
        explanation,
        aggregate(
            &SHADOW_MODEL,
            &ShadowInputs::of_value(VENDOR_PREFIXED, ContextClass::Bare)
        )
    );
    assert_eq!(explanation.context, ContextClass::Bare);
    assert_eq!(
        explanation.groups[EvidenceGroup::Contextual as usize].contribution,
        0
    );
    assert!(comparison.shadow.band <= ShadowBand::Medium);
    assert_eq!(comparison.reasons()[0], "no-credential-context");
}

#[test]
fn the_scorer_reads_the_scan_copy_not_the_invisible_characters() {
    let clean = only_from(&format!("API_KEY={RANDOM_VALUE}\n"), "generic-token");
    let (head, tail) = RANDOM_VALUE.split_at(16);
    let hidden = only_from(&format!("API_KEY={head}\u{200B}{tail}\n"), "generic-token");
    assert_eq!(hidden.shadow, clean.shadow);
    // The range is in original-input bytes, so it covers the removed
    // code point's three bytes inside the value.
    assert_eq!(hidden.range.len(), clean.range.len() + 3);
}

#[test]
fn a_comparison_does_not_depend_on_the_other_candidates_in_the_input() {
    let alone = only_from(&format!("API_KEY={RANDOM_VALUE}\n"), "generic-token");
    let (_, crowded) = comparisons(&format!(
        "token={GITHUB_TOKEN}\n{PRIVATE_KEY}\nAPI_KEY={RANDOM_VALUE}\n"
    ));
    let found = crowded
        .iter()
        .find(|comparison| comparison.detector == "generic-token")
        .unwrap();
    assert_eq!(found.shadow, alone.shadow);
    assert_eq!(found.promotion, alone.promotion);
    assert_eq!(found.legacy_confidence, alone.legacy_confidence);
}

// --- deterministic authority --------------------------------------------------

#[test]
fn provider_private_key_and_structural_candidates_stay_deterministic() {
    let cases = [
        (format!("token={GITHUB_TOKEN}"), Specificity::Provider),
        (format!("{PRIVATE_KEY}\n"), Specificity::PrivateKey),
        (
            format!("Authorization: Bearer {RANDOM_VALUE}\n"),
            Specificity::Structural,
        ),
        (
            "postgres://fakeuser:Zp9LxR4tWb8NcY3h@db.example.invalid:5432/app\n".to_owned(),
            Specificity::Structural,
        ),
        // Repetition inside a provider body changes nothing.
        (
            "token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            Specificity::Provider,
        ),
    ];
    for (input, specificity) in cases {
        let (findings, shadow) = comparisons(&input);
        assert!(!findings.is_empty(), "{input:?}");
        let deterministic: Vec<_> = shadow
            .iter()
            .filter(|comparison| comparison.specificity == specificity)
            .collect();
        assert!(!deterministic.is_empty(), "{input:?}: {shadow:?}");
        for comparison in deterministic {
            assert_eq!(comparison.shadow.authority, ShadowAuthority::Deterministic);
            assert_eq!(
                comparison.shadow.band,
                ShadowBand::of_confidence(comparison.legacy_confidence)
            );
            assert_eq!(comparison.shadow.explanation, None);
            assert_eq!(comparison.promotion, PromotionOutcome::Preserve);
            assert_eq!(comparison.reasons(), ["deterministic-authority"]);
        }
    }
}

// --- whole-input and incremental paths are equivalent ------------------------

fn incremental_comparisons(input: &str, chunk_bytes: usize) -> Vec<ShadowComparison> {
    let limits = IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap();
    let mut session = IncrementalSanitizer::new(limits).unwrap();
    session.record_shadow();
    let mut start = 0;
    while start < input.len() {
        let mut end = (start + chunk_bytes).min(input.len());
        while !input.is_char_boundary(end) {
            end += 1;
        }
        session.append(&input[start..end]).unwrap();
        start = end;
    }
    session.finalize().unwrap();
    session.take_shadow()
}

#[test]
fn whole_input_and_incremental_shadow_records_are_equal() {
    for input in battery() {
        let (_, whole) = comparisons(&input);
        for chunk_bytes in [1, 3, 7, 64, usize::MAX / 2] {
            assert_eq!(
                incremental_comparisons(&input, chunk_bytes),
                whole,
                "{input:?} in chunks of {chunk_bytes}"
            );
        }
    }
}

#[test]
fn a_public_incremental_session_records_nothing() {
    let limits = IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap();
    let mut session = IncrementalSanitizer::new(limits).unwrap();
    session
        .append(&format!("API_KEY={RANDOM_VALUE}\n"))
        .unwrap();
    session.finalize().unwrap();
    assert!(session.take_shadow().is_empty());
}

// --- outcomes and reasons -----------------------------------------------------

#[test]
fn promotion_compares_the_band_with_the_legacy_confidence() {
    use Confidence::{High, Low, Medium};
    assert_eq!(
        PromotionOutcome::of(ShadowBand::High, Medium),
        PromotionOutcome::Promote
    );
    assert_eq!(
        PromotionOutcome::of(ShadowBand::Medium, Medium),
        PromotionOutcome::Preserve
    );
    assert_eq!(
        PromotionOutcome::of(ShadowBand::Low, High),
        PromotionOutcome::Demote
    );
    assert_eq!(
        PromotionOutcome::of(ShadowBand::None, Low),
        PromotionOutcome::Demote
    );
}

#[test]
fn every_reason_comes_from_the_closed_set_in_its_order() {
    for input in battery() {
        let (_, shadow) = comparisons(&input);
        for comparison in shadow {
            let positions: Vec<usize> = comparison
                .reasons()
                .iter()
                .map(|reason| REASON_CODES.iter().position(|code| code == reason).unwrap())
                .collect();
            assert!(
                positions.windows(2).all(|pair| pair[0] < pair[1]),
                "{positions:?}"
            );
        }
    }
}

// --- rendering ------------------------------------------------------------------

#[test]
fn a_statistical_comparison_renders_to_one_fixed_line() {
    let input = format!("API_KEY={RANDOM_VALUE}");
    let comparison = only_from(&input, "generic-token");
    let confidence = comparison.legacy_confidence.as_str();
    let action = comparison.legacy_action.as_str();
    let promotion = comparison.promotion.as_str();
    assert_eq!(
        shadow_evaluation_jsonl("case-1", &input, &registry()),
        format!(
            "{{\"record\":\"shadow-comparison\",\"input\":\"case-1\",\"finding\":\"finding-1\",\"start\":8,\"end\":40,\"byteLength\":32,\"detector\":\"generic-token\",\"type\":\"contextual_secret\",\"specificity\":\"contextual\",\"legacyConfidence\":\"{confidence}\",\"legacyAction\":\"{action}\",\"authority\":\"statistical\",\"model\":\"evidence-aggregation/v2\",\"featureSchema\":\"evidence-features/v1\",\"contextClass\":\"credential-name\",\"exclusion\":null,\"groups\":{{\"randomness\":30,\"lexical\":0,\"contextual\":50,\"validation\":0,\"negative\":0}},\"signals\":[{{\"group\":\"randomness\",\"signal\":\"shannon_entropy_q16\",\"points\":30}},{{\"group\":\"contextual\",\"signal\":\"credential-context\",\"points\":50}},{{\"group\":\"negative\",\"signal\":\"strict-exclusion\",\"points\":0}}],\"positive\":80,\"negative\":0,\"score\":80,\"band\":\"high\",\"promotion\":\"{promotion}\",\"reasons\":[\"credential-context\",\"randomness-capped\"]}}\n"
        )
    );
}

#[test]
fn a_deterministic_comparison_renders_without_scorer_fields() {
    let input = format!("token={GITHUB_TOKEN}");
    assert_eq!(
        shadow_evaluation_jsonl("case-2", &input, &registry()),
        "{\"record\":\"shadow-comparison\",\"input\":\"case-2\",\"finding\":\"finding-1\",\"start\":6,\"end\":46,\"byteLength\":40,\"detector\":\"github-token\",\"type\":\"github_token\",\"specificity\":\"provider\",\"legacyConfidence\":\"high\",\"legacyAction\":\"redact\",\"authority\":\"deterministic\",\"model\":\"evidence-aggregation/v2\",\"featureSchema\":\"evidence-features/v1\",\"contextClass\":null,\"exclusion\":null,\"groups\":null,\"signals\":[],\"score\":null,\"band\":\"high\",\"promotion\":\"preserve\",\"reasons\":[\"deterministic-authority\"]}\n"
    );
}

#[test]
fn every_line_is_json_and_the_record_id_is_escaped() {
    let id = "odd \"id\"\\\n\u{1}";
    for input in battery() {
        let rendered = shadow_evaluation_jsonl(id, &input, &registry());
        for line in rendered.lines() {
            let record: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(record["input"], id);
            assert_eq!(record["record"], "shadow-comparison");
        }
    }
    let header = shadow_evaluation_header(2, "ab\"c", "full");
    let record: serde_json::Value = serde_json::from_str(header.trim_end()).unwrap();
    assert_eq!(record["format"], SHADOW_EVALUATION_FORMAT);
    assert_eq!(record["model"], SHADOW_MODEL.id);
    assert_eq!(record["featureSchema"], FEATURE_SCHEMA_VERSION);
    assert_eq!(record["artifactRevision"], 2);
    assert_eq!(record["modelFingerprint"], "ab\"c");
    assert_eq!(record["profile"], "full");
    assert_eq!(record["productVersion"], crate::VERSION);
}

#[test]
fn rendering_is_deterministic() {
    let input = battery().concat();
    let first = shadow_evaluation_jsonl("same", &input, &registry());
    assert!(!first.is_empty());
    for _ in 0..3 {
        assert_eq!(shadow_evaluation_jsonl("same", &input, &registry()), first);
    }
}

// --- no plaintext -----------------------------------------------------------------

/// Every substring of `value` at least `window` bytes long, on character
/// boundaries.
fn windows(value: &str, window: usize) -> Vec<&str> {
    let bounds: Vec<usize> = value
        .char_indices()
        .map(|(index, _)| index)
        .chain([value.len()])
        .collect();
    let mut out = Vec::new();
    for (i, &start) in bounds.iter().enumerate() {
        if let Some(&end) = bounds.get(i + window) {
            out.push(&value[start..end]);
        }
    }
    out
}

#[test]
fn diagnostics_carry_no_part_of_a_matched_value() {
    for input in battery() {
        let (findings, shadow) = comparisons(&input);
        let rendered = shadow_evaluation_jsonl("id", &input, &registry());
        let debugged = format!("{shadow:?}");
        for finding in &findings {
            let matched = &input[finding.range().start()..finding.range().end()];
            for fragment in windows(matched, 6) {
                assert!(
                    !rendered.contains(fragment),
                    "{fragment:?} leaked into {rendered}"
                );
                assert!(
                    !debugged.contains(fragment),
                    "{fragment:?} leaked into {debugged}"
                );
            }
        }
    }
}
