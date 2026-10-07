//! Detector-id selection (issue #1251,
//! `decision-define-detector-id-selection-and-configuration-replacement-precedence`):
//! applied when the registry is composed, before the prefilter and overlap
//! resolution, in canonical subsequence order, with strict rejection.
//!
//! Every input is synthetic; no test embeds a credential-shaped value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    BuiltInRegistry, DefaultPolicy, DetectionSelection, DetectorRegistry, Finding,
    IncrementalLimits, IncrementalSanitizer, SecretScanErrorCode, default_placeholder_formatter,
    scan,
};

const TOKEN: &str = "ghp_SYNTHETICREVOKED00000000000000000000";

fn keyed() -> String {
    format!("API_KEY={TOKEN}")
}

fn full_ids() -> Vec<String> {
    DetectorRegistry::with_built_in([])
        .unwrap()
        .ids()
        .map(str::to_owned)
        .collect()
}

fn common_ids() -> Vec<String> {
    DetectorRegistry::with_common_built_in([])
        .unwrap()
        .ids()
        .map(str::to_owned)
        .collect()
}

fn detectors(findings: &[Finding]) -> Vec<(&str, &str)> {
    findings
        .iter()
        .map(|finding| (finding.detector(), finding.type_name()))
        .collect()
}

#[test]
fn selection_is_applied_before_overlap_so_a_provider_span_becomes_contextual() {
    let full = DetectorRegistry::with_built_in([]).unwrap();
    let before = scan(&keyed(), &full, &DefaultPolicy).unwrap();
    assert_eq!(detectors(&before), [("github-token", "github_token")]);

    let selected = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::exclude(["github-token"]))
        .unwrap();
    let after = scan(&keyed(), &selected, &DefaultPolicy).unwrap();
    // The span is not lost: a weaker detector now owns it, with its own type
    // and a different default action. That is the documented cost.
    assert_eq!(after.len(), 1);
    assert_ne!(after[0].detector(), "github-token");
    assert_ne!(after[0].type_name(), "github_token");
    assert_eq!(after[0].range(), before[0].range());
}

#[test]
fn the_enabled_set_is_the_canonical_order_filtered_not_the_request_order() {
    let full = full_ids();
    let reversed = ["jwt", "github-token", "private-key"];
    let selected = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::include(reversed))
        .unwrap();
    let expected: Vec<&str> = full
        .iter()
        .map(String::as_str)
        .filter(|id| reversed.contains(id))
        .collect();
    assert_eq!(selected.ids().collect::<Vec<_>>(), expected);
    let forward = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::include([
            "private-key",
            "github-token",
            "jwt",
        ]))
        .unwrap();
    assert_eq!(
        forward.ids().collect::<Vec<_>>(),
        selected.ids().collect::<Vec<_>>()
    );
}

#[test]
fn include_and_exclude_are_complements_and_exclude_empty_is_absent() {
    let full = full_ids();
    let excluded = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::exclude(["github-token", "jwt"]))
        .unwrap();
    assert_eq!(excluded.len(), full.len() - 2);
    assert!(!excluded.contains("github-token"));
    assert!(!excluded.contains("jwt"));

    let none = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::exclude(Vec::<String>::new()))
        .unwrap();
    assert_eq!(
        none.ids().collect::<Vec<_>>(),
        full.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_eq!(
        scan(&keyed(), &none, &DefaultPolicy).unwrap(),
        scan(
            &keyed(),
            &DetectorRegistry::with_built_in([]).unwrap(),
            &DefaultPolicy
        )
        .unwrap()
    );
}

#[test]
fn full_with_the_common_ids_equals_the_common_registry() {
    let ids = common_ids();
    let selected = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::include(ids.clone()))
        .unwrap();
    let common = DetectorRegistry::with_common_built_in([]).unwrap();
    assert_eq!(
        selected.ids().collect::<Vec<_>>(),
        common.ids().collect::<Vec<_>>()
    );
    for input in [
        keyed(),
        "Authorization: Bearer abcDEF0123456789abcDEF0123456789".to_owned(),
        "password=Tr0ub4dor&3xampleSynthetic".to_owned(),
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.SYNTHETIC_SIG_00".to_owned(),
    ] {
        assert_eq!(
            scan(&input, &selected, &DefaultPolicy).unwrap(),
            scan(&input, &common, &DefaultPolicy).unwrap(),
            "{input}"
        );
    }
}

#[test]
fn an_enabled_detectors_candidates_equal_its_candidates_in_full() {
    // `github-token` alone finds the same range as in full when it is the
    // only enabled detector: per-detector invariance extends to selection.
    let alone = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::include(["github-token"]))
        .unwrap();
    let full = DetectorRegistry::with_built_in([]).unwrap();
    let selected = scan(&keyed(), &alone, &DefaultPolicy).unwrap();
    let baseline = scan(&keyed(), &full, &DefaultPolicy).unwrap();
    assert_eq!(selected, baseline);
}

#[test]
fn the_prefilter_is_rebuilt_over_the_survivors() {
    // A prefilter that kept the full registry's slot positions would skip or
    // run the wrong detectors. Debug builds also assert every skip is exact,
    // so this scans inputs that exercise both outcomes.
    let selected = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::include(["jwt", "github-token"]))
        .unwrap();
    for input in [
        keyed(),
        "no literal of any enabled detector here".to_owned(),
    ] {
        scan(&input, &selected, &DefaultPolicy).unwrap();
    }
    let hit = scan(&keyed(), &selected, &DefaultPolicy).unwrap();
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].detector(), "github-token");
}

#[test]
fn unknown_not_included_not_selectable_duplicate_and_malformed_ids_are_rejected() {
    let reject = |registry: DetectorRegistry, selection: DetectionSelection| {
        registry.with_detection(&selection).unwrap_err()
    };
    let full = || DetectorRegistry::with_built_in([]).unwrap();
    let common = || DetectorRegistry::with_common_built_in([]).unwrap();

    let unknown = reject(
        full(),
        DetectionSelection::include(["jwt", "no-such-detector"]),
    );
    assert_eq!(unknown.class_name(), "UNKNOWN_DETECTOR_ID");
    assert_eq!(unknown.index(), Some(1));
    assert_eq!(unknown.code(), SecretScanErrorCode::InvalidDetectionConfig);

    let missing = reject(common(), DetectionSelection::include(["github-token"]));
    assert_eq!(missing.class_name(), "DETECTOR_NOT_INCLUDED");

    let adapter = reject(full(), DetectionSelection::include(["pii-domain"]));
    assert_eq!(adapter.class_name(), "DETECTOR_NOT_SELECTABLE");

    let repeated = reject(full(), DetectionSelection::include(["jwt", "jwt"]));
    assert_eq!(repeated.class_name(), "DUPLICATE_DETECTOR_ID");
    assert_eq!(repeated.index(), Some(1));

    let family = DetectionSelection::from_json(r#"{"include":["pii:global:email"]}"#).unwrap_err();
    assert_eq!(family.class_name(), "INVALID_IDENTIFIER");
    let cased = DetectionSelection::from_json(r#"{"exclude":["Jwt"]}"#).unwrap_err();
    assert_eq!(cased.class_name(), "INVALID_IDENTIFIER");
    let both = DetectionSelection::from_json(r#"{"include":[],"exclude":[]}"#).unwrap_err();
    assert_eq!(both.class_name(), "DETECTION_SELECTOR_CONFLICT");

    // A rejection never echoes the input.
    for error in [unknown, missing, adapter, repeated, family, cased, both] {
        let text = format!("{error} {error:?}");
        assert!(!text.contains("no-such-detector"));
        assert!(!text.contains("pii:global"));
    }
}

#[test]
fn an_empty_selection_that_leaves_nothing_is_refused_but_pii_or_custom_detectors_keep_it_useful() {
    let inert = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::include(Vec::<String>::new()))
        .unwrap_err();
    assert_eq!(inert.code(), SecretScanErrorCode::EmptyDetectionSet);
    assert_eq!(inert.class_name(), "EMPTY_DETECTION_SET");

    let email = redact_secret::PiiSelection::parse(&["pii:family:global:email"]).unwrap();
    let pii_only = DetectorRegistry::with_built_in_and_pii(&email)
        .unwrap()
        .with_detection(&DetectionSelection::include(Vec::<String>::new()))
        .unwrap();
    assert_eq!(pii_only.ids().collect::<Vec<_>>(), ["pii-domain"]);
    assert_eq!(
        pii_only.activation_identity(),
        DetectorRegistry::with_built_in_and_pii(&email)
            .unwrap()
            .activation_identity(),
        "a selection never changes the PII activation identity"
    );
}

#[test]
fn a_selection_does_not_touch_ruleset_detectors() {
    let ruleset = b"ruleset-revision: 1\n\
detector: acme-internal-token\n\
specificity: contextual\n\
prefix: \"ACME_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";
    let detectors = redact_secret::load_ruleset(ruleset).unwrap();
    let selected = DetectorRegistry::with_built_in(detectors)
        .unwrap()
        .with_detection(&DetectionSelection::include(["jwt"]))
        .unwrap();
    assert_eq!(
        selected.ids().collect::<Vec<_>>(),
        ["jwt", "acme-internal-token"]
    );
    let named = DetectorRegistry::with_built_in(redact_secret::load_ruleset(ruleset).unwrap())
        .unwrap()
        .with_detection(&DetectionSelection::include(["acme-internal-token"]))
        .unwrap_err();
    assert_eq!(named.class_name(), "DETECTOR_NOT_SELECTABLE");
}

#[test]
fn the_shareable_registry_applies_the_same_selection() {
    let selection = DetectionSelection::exclude(["github-token"]);
    let shared = BuiltInRegistry::with_built_in()
        .unwrap()
        .with_detection(&selection)
        .unwrap();
    let owned = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&selection)
        .unwrap();
    assert_eq!(
        shared.ids().collect::<Vec<_>>(),
        owned.ids().collect::<Vec<_>>()
    );
    assert_eq!(shared.detection(), &selection);
    assert_eq!(
        shared.scan(&keyed(), &DefaultPolicy).unwrap(),
        scan(&keyed(), &owned, &DefaultPolicy).unwrap()
    );
}

/// The error of a refused session; the session itself has no `Debug`.
#[allow(clippy::needless_pass_by_value)]
fn refusal(
    result: Result<IncrementalSanitizer, redact_secret::SecretScanError>,
) -> redact_secret::SecretScanError {
    match result {
        Ok(_) => panic!("expected the session to be refused"),
        Err(error) => error,
    }
}

fn session_output(detection: &DetectionSelection, chunks: &[&str]) -> String {
    let limits = IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap();
    let mut session = IncrementalSanitizer::with_detection_policy_and_formatter(
        limits,
        detection,
        Box::new(redact_secret::DefaultPolicy),
        Box::new(default_placeholder_formatter),
    )
    .unwrap();
    let mut out = String::new();
    for chunk in chunks {
        out.push_str(session.append(chunk).unwrap().text());
    }
    out.push_str(session.finalize().unwrap().text());
    out
}

#[test]
fn a_session_captures_the_configuration_it_was_created_with() {
    let key = keyed();
    let (head, tail) = key.split_at(10);

    let everything = DetectionSelection::all();
    assert_eq!(
        session_output(&everything, &[head, tail]),
        "API_KEY=<SECRET_1>"
    );

    // The session sees only the enabled detectors; no other value created
    // before or after it can change that.
    let selection = DetectionSelection::include(["jwt"]);
    let selected = session_output(&selection, &[head, tail]);
    let _later = DetectorRegistry::with_built_in([]).unwrap();
    assert_eq!(selected, key, "no enabled detector claims the span");
    // Partition equivalence holds for the selected configuration.
    assert_eq!(selected, session_output(&selection, &[&key]));
    // And it equals the whole-input scan over the same selection.
    let registry = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&selection)
        .unwrap();
    assert!(scan(&key, &registry, &DefaultPolicy).unwrap().is_empty());

    // The selection is judged at creation: a rejected one makes no session.
    let limits = IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap();
    let error = refusal(IncrementalSanitizer::with_detection_policy_and_formatter(
        limits,
        &DetectionSelection::include(["no-such-detector"]),
        Box::new(DefaultPolicy),
        Box::new(default_placeholder_formatter),
    ));
    assert_eq!(error.code(), SecretScanErrorCode::InvalidDetectionConfig);
    let empty = refusal(IncrementalSanitizer::with_detection_policy_and_formatter(
        limits,
        &DetectionSelection::include(Vec::<String>::new()),
        Box::new(DefaultPolicy),
        Box::new(default_placeholder_formatter),
    ));
    assert_eq!(empty.code(), SecretScanErrorCode::EmptyDetectionSet);
}

#[test]
fn the_common_session_never_reaches_for_the_full_profile() {
    let limits = IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap();
    let error = refusal(
        IncrementalSanitizer::with_common_built_in_detection_policy_and_formatter(
            limits,
            &DetectionSelection::include(["github-token"]),
            Box::new(DefaultPolicy),
            Box::new(default_placeholder_formatter),
        ),
    );
    assert_eq!(error.code(), SecretScanErrorCode::InvalidDetectionConfig);
}

#[test]
fn the_standard_profile_registries_are_unchanged_without_a_selection() {
    let all = DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::all())
        .unwrap();
    assert_eq!(all.detection(), &DetectionSelection::all());
    assert_eq!(all.ids().count(), full_ids().len());
}
