//! The stabilized public API, exercised the way a dependent crate sees it.
//!
//! Every item is reached through a `redact_secret::` path, so this file fails
//! to compile if a promised export is renamed or removed, and the module
//! privacy assertions below fail to compile if an internal is re-exposed.
//! `scripts/check-rust-workspace.py` pins the same surface from the manifest
//! side; this file pins that the surface is usable.
//!
//! Every input is synthetic; no test embeds a credential-shaped value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The extension-point signatures are fixed by the traits this file is here to
// exercise: a formatter takes `&PlaceholderContext` and returns a `Result`
// even when this one never fails, and `Detector::id` returns a `&str`.
#![allow(
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_wraps,
    clippy::needless_lifetimes,
    clippy::elidable_lifetime_names,
    clippy::unnecessary_literal_bound
)]

mod support;

use redact_secret::{
    Action, ByteRange, Candidate, Confidence, DEFAULT_MAX_FINDINGS, DEFAULT_MAX_INPUT_BYTES,
    DefaultPolicy, DetectedFinding, Detector, DetectorContext, DetectorFailure, DetectorRegistry,
    Finding, FormatterFailure, IncrementalLimits, IncrementalPolicy, IncrementalPolicyContext,
    IncrementalResult, IncrementalSanitizer, MAX_IDENTIFIER_LENGTH, MAX_PLACEHOLDER_LENGTH,
    Obfuscation, PlaceholderContext, PlaceholderFormatter, Policy, PolicyContext, PolicyFailure,
    Profile, RANGE_UNIT, RegisteredDetector, ScanResult, SecretScanError, SecretScanErrorCode,
    SessionState, Specificity, VERSION, WholeInputLimits, default_placeholder_formatter,
    is_identifier, redact, redact_with_limits, run_detector_pipeline, scan, scan_and_redact,
    scan_and_redact_with_limits, scan_with_limits, shannon_entropy, typed_placeholder_formatter,
};

/// The canonical corpus fixture used wherever one detected value is enough.
/// `github-token` at bytes 8..48 (`host-dotenv-github`).
const FIXTURE: &str = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
const FIXTURE_VALUE: &str = "ghp_SYNTHETICREVOKED00000000000000000000";

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

// ---------------------------------------------------------------------------
// scan, redact, scan-and-redact
// ---------------------------------------------------------------------------

#[test]
fn scan_reports_findings_and_redact_consumes_them() {
    let registry = registry();

    let findings: Vec<Finding> = scan(FIXTURE, &registry, &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id(), "finding-1");
    assert_eq!(findings[0].type_name(), "github_token");
    assert_eq!(findings[0].detector(), "github-token");
    assert_eq!(findings[0].confidence(), Confidence::High);
    assert_eq!(findings[0].action(), Action::Redact);
    assert_eq!(findings[0].range(), ByteRange::new(8, 48).unwrap());

    let text = redact(FIXTURE, &findings, &default_placeholder_formatter).unwrap();
    assert_eq!(text, "API_KEY=<SECRET_1>");
    assert_eq!(
        redact(FIXTURE, &findings, &typed_placeholder_formatter).unwrap(),
        "API_KEY=<GITHUB_TOKEN_1>"
    );
}

#[test]
fn scan_and_redact_returns_the_text_and_the_findings_together() {
    let registry = registry();

    let result: ScanResult = scan_and_redact(
        FIXTURE,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();

    assert_eq!(result.text(), "API_KEY=<SECRET_1>");
    assert_eq!(result.findings().len(), 1);

    let (text, findings) = result.into_parts();
    assert_eq!(text, "API_KEY=<SECRET_1>");
    assert_eq!(findings[0].id(), "finding-1");
}

#[test]
fn the_with_limits_variants_are_usable_and_agree_with_their_default_counterparts() {
    let registry = registry();
    let limits = WholeInputLimits::new(DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_FINDINGS).unwrap();

    let findings = scan_with_limits(FIXTURE, &registry, &DefaultPolicy, &limits).unwrap();
    assert_eq!(findings, scan(FIXTURE, &registry, &DefaultPolicy).unwrap());

    let text =
        redact_with_limits(FIXTURE, &findings, &default_placeholder_formatter, &limits).unwrap();
    assert_eq!(
        text,
        redact(FIXTURE, &findings, &default_placeholder_formatter).unwrap()
    );

    let result = scan_and_redact_with_limits(
        FIXTURE,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
        &limits,
    )
    .unwrap();
    assert_eq!(result.text(), text);
}

#[test]
fn run_detector_pipeline_reports_findings_before_any_policy_runs() {
    let detected: Vec<DetectedFinding> = run_detector_pipeline(FIXTURE, &registry()).unwrap();
    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].detector(), "github-token");
    assert_eq!(
        detected[0].clone().with_action(Action::Block).action(),
        Action::Block
    );
}

// ---------------------------------------------------------------------------
// the range contract: UTF-8 byte offsets into the original input
// ---------------------------------------------------------------------------

#[test]
fn public_ranges_are_utf8_byte_offsets_into_the_original_input() {
    assert_eq!(RANGE_UNIT, "utf8-bytes");

    // A multi-byte prefix makes byte offsets differ from every other unit a
    // host might assume (code points, UTF-16 code units).
    let prefix = "\u{1F511}\u{00E9}";
    let input = format!("{prefix} {FIXTURE}");
    assert_ne!(input.len(), input.chars().count());

    let result = scan_and_redact(
        &input,
        &registry(),
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();

    let range = result.findings()[0].range();
    assert_eq!(range.start(), prefix.len() + 1 + 8);
    // The range indexes the original input, never the sanitized text.
    assert_eq!(&input[range.start()..range.end()], FIXTURE_VALUE);
    assert!(range.is_char_aligned_in(&input));
    assert_eq!(range.len(), FIXTURE_VALUE.len());
    assert_eq!(result.text(), format!("{prefix} API_KEY=<SECRET_1>"));
    assert!(result.text().len() < input.len());
}

#[test]
fn every_supported_corpus_fixture_keeps_char_aligned_original_input_ranges() {
    for fixture in support::synchronous_corpus() {
        if fixture.support != "supported" {
            continue;
        }
        let result = scan_and_redact(
            &fixture.input,
            &registry(),
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap();
        for finding in result.findings() {
            let range = finding.range();
            assert!(
                range.is_char_aligned_in(&fixture.input),
                "{}: range is not char-aligned in the original input",
                fixture.id,
            );
            assert!(range.end() <= fixture.input.len(), "{}", fixture.id);
        }
    }
}

// ---------------------------------------------------------------------------
// conformance: scan_and_redact is exactly scan then redact
// ---------------------------------------------------------------------------

#[test]
fn scan_and_redact_equals_scan_then_redact_over_the_canonical_corpus() {
    let registry = registry();
    for fixture in support::synchronous_corpus() {
        let (expected_text, expected_findings) = support::whole_input(&fixture.input);
        let result = scan_and_redact(
            &fixture.input,
            &registry,
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap();
        assert_eq!(result.text(), expected_text, "{}", fixture.id);
        assert_eq!(result.findings(), expected_findings, "{}", fixture.id);
    }
}

#[test]
fn scan_and_redact_reports_the_error_of_whichever_stage_fails() {
    struct FailingPolicy;
    impl Policy for FailingPolicy {
        fn evaluate(
            &self,
            _: &DetectedFinding,
            _: &PolicyContext,
        ) -> Result<Action, PolicyFailure> {
            Err(PolicyFailure)
        }
    }

    fn failing_formatter(_: &Finding, _: &PlaceholderContext) -> Result<String, FormatterFailure> {
        Err(FormatterFailure)
    }

    let registry = registry();
    let error = scan_and_redact(
        FIXTURE,
        &registry,
        &FailingPolicy,
        &default_placeholder_formatter,
    )
    .unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::PolicyFailure);

    let error =
        scan_and_redact(FIXTURE, &registry, &DefaultPolicy, &failing_formatter).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::PlaceholderFailure);
}

// ---------------------------------------------------------------------------
// policy and formatter extension points
// ---------------------------------------------------------------------------

#[test]
fn a_closure_is_a_policy_and_a_formatter() {
    let policy = |_: &DetectedFinding, context: &PolicyContext| {
        assert_eq!(context.finding_count(), 1);
        assert_eq!(context.finding_index(), 0);
        Ok(Action::Block)
    };
    let formatter = |finding: &Finding, context: &PlaceholderContext| {
        Ok(format!(
            "[{}#{}]",
            finding.type_name(),
            context.placeholder_index()
        ))
    };

    let result = scan_and_redact(FIXTURE, &registry(), &policy, &formatter).unwrap();
    assert_eq!(result.text(), "API_KEY=[github_token#1]");
    assert_eq!(result.findings()[0].action(), Action::Block);
}

#[test]
fn warn_and_allow_actions_leave_the_input_untouched() {
    for action in [Action::Warn, Action::Allow] {
        assert!(!action.replaces_text());
        let policy = move |_: &DetectedFinding, _: &PolicyContext| Ok(action);
        let result = scan_and_redact(
            FIXTURE,
            &registry(),
            &policy,
            &default_placeholder_formatter,
        )
        .unwrap();
        assert_eq!(result.text(), FIXTURE);
    }
    assert!(Action::Redact.replaces_text());
    assert!(Action::Block.replaces_text());
}

#[test]
fn a_placeholder_that_reproduces_the_matched_value_is_rejected() {
    let leaking = |finding: &Finding, _: &PlaceholderContext| {
        let _ = finding;
        Ok(format!("<{FIXTURE_VALUE}>"))
    };
    let error = scan_and_redact(FIXTURE, &registry(), &DefaultPolicy, &leaking).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidPlaceholder);

    let too_long = |_: &Finding, _: &PlaceholderContext| Ok("x".repeat(MAX_PLACEHOLDER_LENGTH + 1));
    let error = scan_and_redact(FIXTURE, &registry(), &DefaultPolicy, &too_long).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidPlaceholder);
}

// ---------------------------------------------------------------------------
// custom detectors
// ---------------------------------------------------------------------------

struct MarkerDetector;

impl Detector for MarkerDetector {
    fn id(&self) -> &str {
        "marker"
    }

    fn detect(
        &self,
        input: &str,
        context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        assert_eq!(context.input_len(), input.len());
        let Some(start) = input.find("MARKER") else {
            return Ok(Vec::new());
        };
        let range = ByteRange::new(start, start + "MARKER".len()).ok_or(DetectorFailure)?;
        Ok(vec![
            Candidate::new("marker_value", Confidence::Medium, range)
                .with_specificity(Specificity::Contextual)
                .with_signals(["fixture"]),
        ])
    }
}

#[test]
fn a_custom_detector_registers_after_the_built_ins_and_reports_findings() {
    let mut registry =
        DetectorRegistry::with_built_in([Box::new(MarkerDetector) as Box<dyn Detector>]).unwrap();
    assert!(registry.contains("marker"));
    assert!(!registry.is_empty());
    let ids: Vec<&str> = registry.ids().collect();
    assert_eq!(*ids.last().unwrap(), "marker");
    assert_eq!(ids.len(), registry.len());

    let last: &RegisteredDetector = registry.detectors().last().unwrap();
    assert_eq!(last.id(), "marker");
    assert_eq!(last.detector().id(), "marker");

    // A duplicate id is refused and leaves the registry unchanged.
    let before = registry.len();
    let error = registry.register(Box::new(MarkerDetector)).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);
    assert_eq!(registry.len(), before);

    let findings = scan("value MARKER here", &registry, &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector(), "marker");
    assert_eq!(findings[0].type_name(), "marker_value");
    assert_eq!(findings[0].action(), Action::Warn);
}

// ---------------------------------------------------------------------------
// incremental session
// ---------------------------------------------------------------------------

#[test]
fn an_incremental_session_reproduces_the_whole_input_reference() {
    let input = format!("{FIXTURE}\nplain trailing text\n");
    let (expected_text, expected_findings) = support::whole_input(&input);

    let limits = IncrementalLimits::new(
        1 << 20,
        IncrementalLimits::minimum_buffered_bytes(8_192, 16_384),
        8_192,
        16_384,
    )
    .unwrap();
    assert_eq!(limits.max_input_bytes(), 1 << 20);
    assert_eq!(limits.max_buffered_bytes(), 16_384 + 128);
    assert_eq!(limits.max_token_bytes(), 8_192);
    assert_eq!(limits.max_multiline_bytes(), 16_384);

    let mut session = IncrementalSanitizer::new(limits).unwrap();
    assert_eq!(session.state(), SessionState::Accepting);

    let mut text = String::new();
    let mut findings: Vec<Finding> = Vec::new();
    for chunk in [&input[..20], &input[20..]] {
        let result: IncrementalResult = session.append(chunk).unwrap();
        let (piece, released) = result.into_parts();
        text.push_str(&piece);
        findings.extend(released);
    }
    let result = session.finalize().unwrap();
    text.push_str(result.text());
    findings.extend(result.findings().iter().cloned());

    assert_eq!(session.state(), SessionState::Finalized);
    assert_eq!(text, expected_text);
    assert_eq!(findings, expected_findings);

    // Terminal states reject every further call.
    assert_eq!(
        session.append("more").unwrap_err().code(),
        SecretScanErrorCode::InvalidState
    );
}

#[test]
fn an_incremental_session_accepts_a_custom_policy_and_formatter_and_can_abort() {
    struct BlockEverything;
    impl IncrementalPolicy for BlockEverything {
        fn evaluate(
            &self,
            _: &DetectedFinding,
            context: &IncrementalPolicyContext,
        ) -> Result<Action, PolicyFailure> {
            assert_eq!(context.finding_index(), 0);
            Ok(Action::Block)
        }
    }

    fn marker(_: &Finding, context: &PlaceholderContext) -> Result<String, FormatterFailure> {
        Ok(format!("<GONE_{}>", context.placeholder_index()))
    }

    let limits = IncrementalLimits::new(
        1 << 20,
        IncrementalLimits::minimum_buffered_bytes(8_192, 16_384),
        8_192,
        16_384,
    )
    .unwrap();
    let formatter: Box<dyn PlaceholderFormatter> = Box::new(marker);
    let mut session = IncrementalSanitizer::with_policy_and_formatter(
        limits,
        Box::new(BlockEverything),
        formatter,
    )
    .unwrap();

    let result = session.append(&format!("{FIXTURE}\n")).unwrap();
    assert_eq!(result.text(), "API_KEY=<GONE_1>\n");
    assert_eq!(result.findings()[0].action(), Action::Block);

    session.abort().unwrap();
    assert_eq!(session.state(), SessionState::Aborted);
    assert_eq!(
        session.finalize().unwrap_err().code(),
        SecretScanErrorCode::InvalidState
    );
}

#[test]
fn invalid_limits_are_refused_before_a_session_starts() {
    let error = IncrementalLimits::new(1_000, 128, 512, 512).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidLimits);
    assert_eq!(
        IncrementalLimits::minimum_buffered_bytes(512, 4_096),
        4_096 + 128
    );
    assert_eq!(
        IncrementalLimits::minimum_buffered_bytes(usize::MAX, 1),
        usize::MAX
    );
}

// ---------------------------------------------------------------------------
// sanitized errors
// ---------------------------------------------------------------------------

#[test]
fn every_error_is_a_fixed_code_and_message_with_no_payload() {
    for code in SecretScanErrorCode::ALL {
        let error: SecretScanError = code.into();
        assert_eq!(error.code(), code);
        assert_eq!(error.message(), code.message());
        assert_eq!(error.to_string(), code.message());
        assert!(!code.as_str().is_empty());
        // A sanitized error is a plain value: it carries nothing but its code.
        assert_eq!(
            size_of::<SecretScanError>(),
            size_of::<SecretScanErrorCode>()
        );
    }
    assert_eq!(
        SecretScanError::new(SecretScanErrorCode::PolicyFailure)
            .code()
            .as_str(),
        "POLICY_FAILURE"
    );

    // The opaque failures an extension point returns carry nothing either.
    assert_eq!(size_of::<DetectorFailure>(), 0);
    assert_eq!(size_of::<PolicyFailure>(), 0);
    assert_eq!(size_of::<FormatterFailure>(), 0);
}

// ---------------------------------------------------------------------------
// remaining exported helpers and privacy
// ---------------------------------------------------------------------------

#[test]
fn identifier_and_entropy_helpers_are_public() {
    assert!(is_identifier("github-token"));
    assert!(!is_identifier("GitHub"));
    assert!(!is_identifier(&"a".repeat(MAX_IDENTIFIER_LENGTH + 1)));
    assert!(shannon_entropy("").abs() < f64::EPSILON);
    assert!(shannon_entropy(FIXTURE_VALUE) > 0.0);
    assert!(!VERSION.is_empty());
}

#[test]
fn enum_names_round_trip_through_their_public_wire_form() {
    for (confidence, name) in [
        (Confidence::Low, "low"),
        (Confidence::Medium, "medium"),
        (Confidence::High, "high"),
    ] {
        assert_eq!(confidence.as_str(), name);
        assert_eq!(Confidence::from_name(name), Some(confidence));
    }
    for (specificity, name) in [
        (Specificity::Entropy, "entropy"),
        (Specificity::Contextual, "contextual"),
        (Specificity::Structural, "structural"),
        (Specificity::Provider, "provider"),
    ] {
        assert_eq!(specificity.as_str(), name);
        assert_eq!(Specificity::from_name(name), Some(specificity));
    }
    for (action, name) in [
        (Action::Allow, "allow"),
        (Action::Warn, "warn"),
        (Action::Redact, "redact"),
        (Action::Block, "block"),
    ] {
        assert_eq!(action.as_str(), name);
        assert_eq!(Action::from_name(name), Some(action));
    }
    for (obfuscation, name) in [
        (Obfuscation::None, "none"),
        (Obfuscation::InvisibleCharacters, "invisible-characters"),
    ] {
        assert_eq!(obfuscation.as_str(), name);
        assert_eq!(Obfuscation::from_name(name), Some(obfuscation));
    }
}

/// The built-in detector set is not a public path: a dependent crate reaches
/// it only through [`DetectorRegistry::with_built_in`]. `redact_secret` has no
/// `detectors` module to import, and this test states the consequence a
/// caller can observe.
#[test]
fn built_in_detectors_are_reachable_only_through_the_registry() {
    let built_in = registry();
    assert!(built_in.len() > 1);
    assert_eq!(built_in.ids().next(), Some("private-key"));
    assert!(DetectorRegistry::new().is_empty());
    assert_eq!(DetectorRegistry::default().len(), 0);
    assert!(
        run_detector_pipeline(FIXTURE, &DetectorRegistry::new())
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// the `common` profile
// ---------------------------------------------------------------------------

/// The `common` profile's canonical membership
/// (`decision-define-detector-profile-and-pack-contract`): a strict,
/// order-preserving subset of `full`.
const COMMON_IDS: [&str; 6] = [
    "private-key",
    "jwt",
    "bearer-token",
    "connection-string",
    "otpauth-uri",
    "generic-token",
];

#[test]
fn common_profile_registers_its_declared_membership_in_canonical_order() {
    let common = DetectorRegistry::with_common_built_in([]).unwrap();
    assert_eq!(common.profile(), Some(Profile::Common));
    assert_eq!(common.ids().collect::<Vec<_>>(), COMMON_IDS);

    let full = registry_full();
    assert_eq!(full.profile(), Some(Profile::Full));
    for id in COMMON_IDS {
        assert!(full.contains(id));
    }
}

fn registry_full() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

/// "openai-token" is a `provider` id: `common` never registers it itself,
/// but it is still reserved.
struct ReservedIdDetector;

impl Detector for ReservedIdDetector {
    fn id(&self) -> &str {
        "openai-token"
    }

    fn detect(&self, _: &str, _: &DetectorContext) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(Vec::new())
    }
}

/// "private-key" is a `common` id the profile already registers.
struct DuplicateCommonIdDetector;

impl Detector for DuplicateCommonIdDetector {
    fn id(&self) -> &str {
        "private-key"
    }

    fn detect(&self, _: &str, _: &DetectorContext) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(Vec::new())
    }
}

#[test]
fn common_registry_rejects_a_custom_detector_that_reuses_a_full_built_in_id() {
    // An id no built-in uses registers normally.
    let registry =
        DetectorRegistry::with_common_built_in([Box::new(MarkerDetector) as Box<dyn Detector>])
            .unwrap();
    assert!(registry.contains("marker"));

    let error =
        DetectorRegistry::with_common_built_in([Box::new(ReservedIdDetector) as Box<dyn Detector>])
            .unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);

    let error = DetectorRegistry::with_common_built_in([
        Box::new(DuplicateCommonIdDetector) as Box<dyn Detector>
    ])
    .unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);
}

#[test]
fn common_profile_finding_can_differ_from_full_by_design() {
    // A validly shaped legacy OpenAI key (`sk-<20>T3BlbkFJ<20>`) inside a
    // `Bearer` header: `full` claims it as `openai-token`
    // (provider-specific), while `common` — which does not register that
    // detector — reports it only as `bearer-token`. This is the documented
    // false-negative tradeoff of `common`, not a bug.
    let input = "Authorization: Bearer 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";

    let full_findings = scan(input, &registry_full(), &DefaultPolicy).unwrap();
    assert!(full_findings.iter().any(|f| f.detector() == "openai-token"));

    let common_registry = DetectorRegistry::with_common_built_in([]).unwrap();
    let common_findings = scan(input, &common_registry, &DefaultPolicy).unwrap();
    assert!(
        common_findings
            .iter()
            .any(|f| f.detector() == "bearer-token")
    );
    assert!(
        !common_findings
            .iter()
            .any(|f| f.detector() == "openai-token")
    );
}

#[test]
fn common_profile_incremental_session_selects_the_same_built_ins_as_the_whole_input_path() {
    let limits = IncrementalLimits::new(
        1 << 20,
        IncrementalLimits::minimum_buffered_bytes(8_192, 16_384),
        8_192,
        16_384,
    )
    .unwrap();
    let mut session = IncrementalSanitizer::with_common_built_in(limits).unwrap();
    assert_eq!(session.profile(), Some(Profile::Common));

    let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
    let registry = DetectorRegistry::with_common_built_in([]).unwrap();
    let expected = scan_and_redact(
        input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .unwrap();

    let (piece, released) = session.append(input).unwrap().into_parts();
    let mut text = piece;
    let mut findings = released;
    let result = session.finalize().unwrap();
    text.push_str(result.text());
    findings.extend(result.findings().iter().cloned());

    assert_eq!(text, expected.text());
    assert_eq!(findings, expected.findings().to_vec());
}
