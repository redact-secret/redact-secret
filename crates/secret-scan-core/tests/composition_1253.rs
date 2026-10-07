//! Static custom composition (issue #1253,
//! `decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`):
//! the per-detector public constructors, the canonical-order rule, the
//! composition identity and the agreement oracle. A composed registry must
//! give the findings of the `full` registry narrowed to the same ids, over the
//! whole canonical corpus, whole-input and chunked.
//!
//! Every input is synthetic; no test embeds a credential-shaped value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::composition::{
    self, Composition, SelectedDetector, aws_access_key, bearer_token, connection_string,
    generic_token, github_token, jwt, otpauth_uri, private_key, stripe_token,
};
use redact_secret::{
    ArtifactKind, ArtifactManifest, DefaultPolicy, DetectionSelection, DetectorRegistry, Finding,
    IncrementalLimits, IncrementalSanitizer, PiiSelection, Profile, SecretScanErrorCode,
    default_placeholder_formatter, scan, scan_and_redact,
};

/// A mixed provider and structural selection.
fn mixed() -> Composition {
    Composition::new(
        "mixed-checks",
        false,
        [
            aws_access_key(),
            github_token(),
            jwt(),
            bearer_token(),
            generic_token(),
        ],
    )
    .unwrap()
}

/// Exactly the `common` profile's six detectors.
fn common_six() -> Composition {
    Composition::new(
        "common-six",
        false,
        [
            private_key(),
            jwt(),
            bearer_token(),
            connection_string(),
            otpauth_uri(),
            generic_token(),
        ],
    )
    .unwrap()
}

/// One provider detector and the contextual fallback that competes with it.
fn stripe_and_fallback() -> Composition {
    Composition::new("stripe-checks", false, [stripe_token(), generic_token()]).unwrap()
}

fn compositions() -> Vec<Composition> {
    vec![mixed(), common_six(), stripe_and_fallback()]
}

fn oracle(composition: &Composition) -> DetectorRegistry {
    DetectorRegistry::with_built_in([])
        .unwrap()
        .with_detection(&DetectionSelection::include(
            composition.ids().collect::<Vec<_>>(),
        ))
        .unwrap()
}

fn shape(findings: &[Finding]) -> Vec<(String, String, usize, usize, String)> {
    findings
        .iter()
        .map(|finding| {
            (
                finding.detector().to_owned(),
                finding.type_name().to_owned(),
                finding.range().start(),
                finding.range().end(),
                finding.action().as_str().to_owned(),
            )
        })
        .collect()
}

fn corpus_inputs(limit: usize) -> Vec<String> {
    support::synchronous_corpus()
        .into_iter()
        .filter(|fixture| fixture.support != "not-yet-evaluated" && fixture.input.len() <= limit)
        .map(|fixture| fixture.input)
        .collect()
}

#[test]
fn a_composed_registry_holds_exactly_its_detectors_in_canonical_order() {
    let composition = mixed();
    let registry = DetectorRegistry::with_composition(&composition, []).unwrap();
    assert_eq!(registry.profile(), Some(Profile::Custom));
    assert_eq!(
        registry.ids().collect::<Vec<_>>(),
        [
            "aws-access-key",
            "github-token",
            "jwt",
            "bearer-token",
            "generic-token"
        ]
    );
    assert_eq!(
        registry.ids().collect::<Vec<_>>(),
        composition.ids().collect::<Vec<_>>()
    );
    assert_eq!(
        registry.activation_identity().split(';').next(),
        Some("credentials=custom")
    );
}

#[test]
fn the_six_common_detectors_compose_to_the_common_profile() {
    let composed = DetectorRegistry::with_composition(&common_six(), []).unwrap();
    let common = DetectorRegistry::with_common_built_in([]).unwrap();
    assert_eq!(
        composed.ids().collect::<Vec<_>>(),
        common.ids().collect::<Vec<_>>()
    );
    for input in corpus_inputs(8_192) {
        assert_eq!(
            shape(&scan(&input, &composed, &DefaultPolicy).unwrap()),
            shape(&scan(&input, &common, &DefaultPolicy).unwrap())
        );
    }
}

#[test]
fn the_composition_matches_the_full_artifact_narrowed_to_the_same_ids_on_the_corpus() {
    let inputs = corpus_inputs(8_192);
    assert!(
        inputs.len() > 1_000,
        "the canonical corpus supplies the cases"
    );
    for composition in compositions() {
        let composed = DetectorRegistry::with_composition(&composition, []).unwrap();
        let narrowed = oracle(&composition);
        assert_eq!(
            composed.ids().collect::<Vec<_>>(),
            narrowed.ids().collect::<Vec<_>>()
        );
        for input in &inputs {
            assert_eq!(
                shape(&scan(input, &composed, &DefaultPolicy).unwrap()),
                shape(&scan(input, &narrowed, &DefaultPolicy).unwrap()),
                "composition {}",
                composition.name()
            );
        }
    }
}

#[test]
fn an_excluded_detector_finds_nothing_and_a_selected_one_still_does() {
    let token = "ghp_SYNTHETICREVOKED00000000000000000000";
    let key = ["AKIA", "SYNTHETICEXAMPLE"].concat();
    let stripe_like = ["sk_", "live_", "SYNTHETICREVOKED000000000000"].concat();
    let text = format!("API_KEY={token}\n{key}\nstripe={stripe_like}\n");

    let selected = DetectorRegistry::with_composition(&mixed(), []).unwrap();
    let found = scan(&text, &selected, &DefaultPolicy).unwrap();
    let detectors: Vec<&str> = found.iter().map(Finding::detector).collect();
    assert!(detectors.contains(&"github-token"));
    assert!(detectors.contains(&"aws-access-key"));
    assert!(
        !detectors.contains(&"stripe-token"),
        "an excluded detector never reports"
    );
}

#[test]
fn composition_validation_rejects_bad_order_repeats_names_and_empty_sets() {
    let invalid = |result: Result<Composition, redact_secret::SecretScanError>| {
        assert_eq!(
            result.unwrap_err().code(),
            SecretScanErrorCode::InvalidDetector
        );
    };
    // Canonical order is the registration order; a composition never reorders.
    invalid(Composition::new(
        "out-of-order",
        false,
        [jwt(), github_token()],
    ));
    invalid(Composition::new("repeated", false, [jwt(), jwt()]));
    invalid(Composition::new(
        "empty",
        false,
        Vec::<SelectedDetector>::new(),
    ));
    invalid(Composition::new("Upper", false, [jwt()]));
    invalid(Composition::new("", false, [jwt()]));
    invalid(Composition::new(&"a".repeat(65), false, [jwt()]));
    assert!(Composition::new("fine-name", false, [github_token(), jwt()]).is_ok());
}

#[test]
fn the_identity_binds_the_name_the_ids_and_the_pii_flag() {
    let base = Composition::new("one", false, [github_token(), jwt()]).unwrap();
    let id = base.id().to_owned();
    assert!(id.starts_with("custom:") && id.len() == "custom:".len() + 64);
    assert!(
        id["custom:".len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(
        Composition::new("one", false, [github_token(), jwt()])
            .unwrap()
            .id(),
        id
    );
    assert_ne!(
        Composition::new("two", false, [github_token(), jwt()])
            .unwrap()
            .id(),
        id
    );
    assert_ne!(
        Composition::new("one", true, [github_token(), jwt()])
            .unwrap()
            .id(),
        id
    );
    assert_ne!(
        Composition::new("one", false, [github_token()])
            .unwrap()
            .id(),
        id
    );
}

#[test]
fn custom_detectors_cannot_reuse_any_built_in_id_even_an_unselected_one() {
    use redact_secret::{Candidate, Detector, DetectorContext, DetectorFailure};
    struct Named(&'static str);
    impl Detector for Named {
        fn id(&self) -> &str {
            self.0
        }
        fn detect(&self, _: &str, _: &DetectorContext) -> Result<Vec<Candidate>, DetectorFailure> {
            Ok(Vec::new())
        }
    }
    let composition = mixed();
    for reserved in ["github-token", "stripe-token"] {
        let error =
            DetectorRegistry::with_composition(&composition, [Box::new(Named(reserved)) as _])
                .unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);
    }
    let registry =
        DetectorRegistry::with_composition(&composition, [Box::new(Named("acme-internal")) as _])
            .unwrap();
    assert_eq!(registry.ids().last(), Some("acme-internal"));
    assert_eq!(registry.profile(), Some(Profile::Custom));
}

#[test]
fn a_ruleset_detector_runs_after_the_composed_built_ins() {
    let ruleset = b"ruleset-revision: 1\n\
detector: acme-internal-token\n\
specificity: contextual\n\
prefix: \"ACME_\"\n\
alphabet: alnum-dash\n\
run: at-least 20\n\
validator: none\n";
    let detectors = redact_secret::load_ruleset(ruleset).unwrap();
    let registry = DetectorRegistry::with_composition(&mixed(), detectors).unwrap();
    let text = ["ACME_", "SYNTHETIC-REVOKED-VALUE-0000"].concat();
    let found = scan(&text, &registry, &DefaultPolicy).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].detector(), "acme-internal-token");
}

#[test]
fn runtime_selection_narrows_within_the_ceiling_and_never_restores_an_excluded_detector() {
    let composition = mixed();
    let narrowed = DetectorRegistry::with_composition(&composition, [])
        .unwrap()
        .with_detection(&DetectionSelection::include(["jwt"]))
        .unwrap();
    assert_eq!(narrowed.ids().collect::<Vec<_>>(), ["jwt"]);

    for id in ["stripe-token", "private-key"] {
        let refused = DetectorRegistry::with_composition(&composition, [])
            .unwrap()
            .with_detection(&DetectionSelection::include([id]))
            .unwrap_err();
        assert_eq!(refused.class_name(), "DETECTOR_NOT_INCLUDED", "{id}");
        let excluded = DetectorRegistry::with_composition(&composition, [])
            .unwrap()
            .with_detection(&DetectionSelection::exclude([id]))
            .unwrap_err();
        assert_eq!(excluded.class_name(), "DETECTOR_NOT_INCLUDED", "{id}");
    }
}

#[test]
fn a_composed_registry_with_pii_keeps_the_custom_identity_and_the_adapter_slot() {
    let selection = PiiSelection::parse(&["pii:family:global:email"]).unwrap();
    let registry = DetectorRegistry::with_composition_and_pii(&mixed(), &selection, []).unwrap();
    assert_eq!(registry.profile(), Some(Profile::Custom));
    assert_eq!(registry.ids().last(), Some("pii-domain"));
    assert!(
        registry
            .activation_identity()
            .starts_with("credentials=custom;")
    );
}

#[test]
fn the_manifest_describes_the_actual_registry() {
    for composition in compositions() {
        let registry = DetectorRegistry::with_composition(&composition, []).unwrap();
        let manifest = ArtifactManifest::custom(ArtifactKind::Wasm, &composition, None).unwrap();
        assert_eq!(
            manifest.detector_ids().collect::<Vec<_>>(),
            registry.ids().collect::<Vec<_>>()
        );
        assert_eq!(manifest.composition_id(), Some(composition.id()));
        assert_eq!(manifest.profile(), Profile::Custom);
        assert!(manifest.detector_selection());
        let full = DetectorRegistry::with_built_in([]).unwrap();
        let mut partition: Vec<&str> = manifest
            .detector_ids()
            .chain(manifest.not_included_ids())
            .collect();
        partition.sort_unstable();
        let mut expected: Vec<&str> = full.ids().collect();
        expected.sort_unstable();
        assert_eq!(partition, expected);
        assert_eq!(manifest.verify_packaged(Some(manifest.as_json())), Ok(()));
    }
    // The packaged-manifest check has fixed, bounded classes.
    let manifest = ArtifactManifest::custom(ArtifactKind::Wasm, &mixed(), None).unwrap();
    assert_eq!(
        manifest.verify_packaged(None).unwrap_err().code(),
        "ARTIFACT_MANIFEST_MISSING"
    );
    assert_eq!(
        manifest.verify_packaged(Some("{}")).unwrap_err().code(),
        "ARTIFACT_MANIFEST_SCHEMA_MISMATCH"
    );
    let other = ArtifactManifest::custom(ArtifactKind::Wasm, &common_six(), None).unwrap();
    assert_eq!(
        manifest
            .verify_packaged(Some(other.as_json()))
            .unwrap_err()
            .code(),
        "ARTIFACT_MANIFEST_DIGEST_MISMATCH"
    );
}

fn chunked(mut session: IncrementalSanitizer, input: &str, chunk: usize) -> String {
    let mut out = String::new();
    let mut start = 0;
    let boundaries: Vec<usize> = input.char_indices().map(|(index, _)| index).collect();
    while start < input.len() {
        let target = start + chunk;
        let end = boundaries
            .iter()
            .copied()
            .find(|boundary| *boundary >= target)
            .unwrap_or(input.len());
        out.push_str(session.append(&input[start..end]).unwrap().text());
        start = end;
    }
    out.push_str(session.finalize().unwrap().text());
    out
}

fn limits() -> IncrementalLimits {
    IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap()
}

#[test]
fn incremental_output_is_partition_equivalent_and_equals_the_narrowed_full_session() {
    let inputs = corpus_inputs(2_048);
    for composition in compositions() {
        let narrowed = DetectionSelection::include(composition.ids().collect::<Vec<_>>());
        let composed_registry = DetectorRegistry::with_composition(&composition, []).unwrap();
        for input in inputs.iter().step_by(3) {
            let whole = scan_and_redact(
                input,
                &composed_registry,
                &DefaultPolicy,
                &default_placeholder_formatter,
            )
            .unwrap();
            for chunk in [1, 7, 64, 100_000] {
                let session =
                    IncrementalSanitizer::with_composition_detection_policy_and_formatter(
                        limits(),
                        &composition,
                        &DetectionSelection::all(),
                        Box::new(DefaultPolicy),
                        Box::new(default_placeholder_formatter),
                    )
                    .unwrap();
                let from_composition = chunked(session, input, chunk);
                let oracle_session = IncrementalSanitizer::with_detection_policy_and_formatter(
                    limits(),
                    &narrowed,
                    Box::new(DefaultPolicy),
                    Box::new(default_placeholder_formatter),
                )
                .unwrap();
                let from_oracle = chunked(oracle_session, input, chunk);
                assert_eq!(
                    from_composition,
                    from_oracle,
                    "{} chunk {chunk}",
                    composition.name()
                );
                assert_eq!(
                    from_composition,
                    whole.text(),
                    "{} chunk {chunk}",
                    composition.name()
                );
            }
        }
    }
}

#[test]
fn an_incremental_session_keeps_retention_for_the_selected_detectors() {
    // `generic-token` and `bearer-token` feed lookback retention across a
    // chunk boundary; a composition that keeps them must still join a header
    // split between chunks.
    let composition =
        Composition::new("auth-only", false, [bearer_token(), generic_token()]).unwrap();
    let header = [
        "Authorization: Bearer ",
        "SYNTHETICREVOKEDTOKEN0000000000",
        "\n",
    ]
    .concat();
    let session = IncrementalSanitizer::with_composition_detection_policy_and_formatter(
        limits(),
        &composition,
        &DetectionSelection::all(),
        Box::new(DefaultPolicy),
        Box::new(default_placeholder_formatter),
    )
    .unwrap();
    let split = chunked(session, &header, 5);
    let registry = DetectorRegistry::with_composition(&composition, []).unwrap();
    let whole = scan_and_redact(
        &header,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();
    assert_eq!(split, whole.text());
    assert!(!split.contains("SYNTHETICREVOKED"));
}

#[test]
fn the_session_refuses_a_selection_above_the_composition() {
    let result = IncrementalSanitizer::with_composition_detection_policy_and_formatter(
        limits(),
        &mixed(),
        &DetectionSelection::include(["stripe-token"]),
        Box::new(DefaultPolicy),
        Box::new(default_placeholder_formatter),
    );
    match result {
        Ok(_) => panic!("a detector outside the composition must be refused"),
        Err(error) => assert_eq!(error.code(), SecretScanErrorCode::InvalidDetectionConfig),
    }
}

/// The constructor of one fixture id: the fixture only names these.
fn constructor(id: &str) -> SelectedDetector {
    match id {
        "github-token" => github_token(),
        "stripe-token" => stripe_token(),
        "slack-token" => composition::slack_token(),
        "bearer-token" => bearer_token(),
        "connection-string" => connection_string(),
        "generic-token" => generic_token(),
        "jwt" => jwt(),
        "otpauth-uri" => otpauth_uri(),
        "private-key" => private_key(),
        other => panic!("the fixture names an id this test has no constructor for: {other}"),
    }
}

#[test]
fn the_composition_identity_is_the_shared_conformance_value() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/composition-v1.json");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for case in cases {
        let ids: Vec<&str> = case["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap())
            .collect();
        let composition = Composition::new(
            case["name"].as_str().unwrap(),
            case["pii"] == "all",
            ids.iter().map(|id| constructor(id)),
        )
        .unwrap();
        assert_eq!(composition.ids().collect::<Vec<_>>(), ids);
        assert_eq!(
            composition.id(),
            case["id"].as_str().unwrap(),
            "{}: the identity both implementations derive",
            case["name"]
        );
    }
}

#[test]
fn the_composition_module_exports_one_constructor_per_built_in_detector() {
    // Compile-time names through the public path; the count is pinned by the
    // crate's own table test, and these confirm the path is public.
    let _ = (
        composition::aws_access_key(),
        composition::github_token(),
        composition::stripe_token(),
        composition::generic_token(),
    );
    let full = DetectorRegistry::with_built_in([]).unwrap();
    assert!(full.len() > 100);
}
