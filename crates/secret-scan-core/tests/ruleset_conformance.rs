//! Asserts the Rust core against the reference ruleset conformance fixture
//! (`conformance/fixtures/ruleset-reference.json`, issue #495,
//! `decision-define-declarative-detector-ruleset-contract`'s "Conformance"):
//! the same fixture every accepting binding surface runs, not a per-binding
//! smoke test.
//!
//! Every ruleset text and scanned input in the fixture is synthetic; nothing
//! here reproduces a matched value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    Confidence, DefaultPolicy, DetectorRegistry, RulesetErrorClass, load_ruleset, scan,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../conformance/fixtures/ruleset-reference.json");

fn document() -> Value {
    serde_json::from_str(FIXTURE).expect("ruleset-reference.json must be valid JSON")
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("expected string field {key:?}"))
}

// ---------------------------------------------------------------------------
// accepted: value grammar
// ---------------------------------------------------------------------------

#[test]
fn the_accepted_ruleset_parses_and_every_case_matches_as_declared() {
    let document = document();
    let accepted = &document["accepted"];
    let ruleset_text = str_field(accepted, "ruleset");

    let detectors = load_ruleset(ruleset_text.as_bytes())
        .unwrap_or_else(|error| panic!("the reference ruleset must load: {error:?}"));
    let registry = DetectorRegistry::with_built_in(detectors).unwrap();

    for case in accepted["cases"].as_array().unwrap() {
        let id = str_field(case, "id");
        let input = str_field(case, "input");
        let findings = scan(input, &registry, &DefaultPolicy).unwrap();

        if let Some(0) = case.get("findingCount").and_then(Value::as_u64) {
            assert!(findings.is_empty(), "case {id}: expected no findings");
            continue;
        }

        assert_eq!(findings.len(), 1, "case {id}: expected exactly one finding");
        let finding = &findings[0];
        assert_eq!(finding.detector(), str_field(case, "detector"), "case {id}");
        assert_eq!(finding.type_name(), str_field(case, "type"), "case {id}");
        assert_eq!(
            finding.confidence(),
            Confidence::from_name(str_field(case, "confidence")).unwrap(),
            "case {id}"
        );
        let start = usize::try_from(case["start"].as_u64().unwrap()).unwrap();
        let end = usize::try_from(case["end"].as_u64().unwrap()).unwrap();
        assert_eq!(finding.range().start(), start, "case {id}");
        assert_eq!(finding.range().end(), end, "case {id}");
    }
}

// ---------------------------------------------------------------------------
// names: the declarative ruleset's names section (issue #484)
// ---------------------------------------------------------------------------

#[test]
fn the_names_section_ruleset_parses_and_every_case_matches_as_declared() {
    let document = document();
    let names = &document["names"];
    let ruleset_text = str_field(names, "ruleset");

    let detectors = load_ruleset(ruleset_text.as_bytes())
        .unwrap_or_else(|error| panic!("the reference names-section ruleset must load: {error:?}"));
    let registry = DetectorRegistry::with_built_in(detectors).unwrap();

    for case in names["cases"].as_array().unwrap() {
        let id = str_field(case, "id");
        let input = str_field(case, "input");
        let findings = scan(input, &registry, &DefaultPolicy).unwrap();

        if let Some(0) = case.get("findingCount").and_then(Value::as_u64) {
            assert!(findings.is_empty(), "case {id}: expected no findings");
            continue;
        }

        assert_eq!(findings.len(), 1, "case {id}: expected exactly one finding");
        let finding = &findings[0];
        assert_eq!(finding.detector(), str_field(case, "detector"), "case {id}");
        assert_eq!(finding.type_name(), str_field(case, "type"), "case {id}");
        assert_eq!(
            finding.confidence(),
            Confidence::from_name(str_field(case, "confidence")).unwrap(),
            "case {id}"
        );
        let start = usize::try_from(case["start"].as_u64().unwrap()).unwrap();
        let end = usize::try_from(case["end"].as_u64().unwrap()).unwrap();
        assert_eq!(finding.range().start(), start, "case {id}");
        assert_eq!(finding.range().end(), end, "case {id}");
    }
}

// ---------------------------------------------------------------------------
// ordering: a ruleset detector cannot overturn a built-in
// ---------------------------------------------------------------------------

#[test]
fn the_ordering_fixture_shows_the_built_in_winning_the_tie() {
    let document = document();
    let ordering = &document["ordering"];
    let ruleset_text = str_field(ordering, "ruleset");
    let input = str_field(ordering, "input");
    let expected = &ordering["expectedWinner"];

    let detectors = load_ruleset(ruleset_text.as_bytes()).unwrap();
    let registry = DetectorRegistry::with_built_in(detectors).unwrap();
    let findings = scan(input, &registry, &DefaultPolicy).unwrap();

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.detector(), str_field(expected, "detector"));
    assert_eq!(finding.type_name(), str_field(expected, "type"));
    assert_eq!(
        finding.confidence(),
        Confidence::from_name(str_field(expected, "confidence")).unwrap()
    );
    assert_eq!(
        finding.range().start(),
        usize::try_from(expected["start"].as_u64().unwrap()).unwrap()
    );
    assert_eq!(
        finding.range().end(),
        usize::try_from(expected["end"].as_u64().unwrap()).unwrap()
    );
}

// ---------------------------------------------------------------------------
// rejections: every fixed RulesetErrorClass
// ---------------------------------------------------------------------------

/// Builds the `TOO_MANY_DETECTORS` ruleset: one more detector block than the
/// core's fixed maximum, each block otherwise shaped like the accepted
/// fixture's `acme-alnum-token` case with a unique id.
fn too_many_detectors_ruleset(count: u64) -> String {
    use std::fmt::Write;

    let mut text = String::from("ruleset-revision: 1\n");
    for index in 0..count {
        let _ = write!(
            text,
            "detector: acme-token-{index}\nspecificity: contextual\nprefix: \"ACME_\"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\n"
        );
    }
    text
}

fn class_from_wire(name: &str) -> RulesetErrorClass {
    for class in [
        RulesetErrorClass::RulesetTooLarge,
        RulesetErrorClass::UnknownRevision,
        RulesetErrorClass::UnknownField,
        RulesetErrorClass::UnsupportedConstruct,
        RulesetErrorClass::UnknownAlphabet,
        RulesetErrorClass::UnknownValidator,
        RulesetErrorClass::SpecificityNotClaimable,
        RulesetErrorClass::MissingField,
        RulesetErrorClass::PrefixTooShort,
        RulesetErrorClass::PrefixTooLong,
        RulesetErrorClass::RunLengthOutOfBounds,
        RulesetErrorClass::TooManyDetectors,
        RulesetErrorClass::DuplicateDetectorId,
        RulesetErrorClass::ReservedDetectorId,
        RulesetErrorClass::EmptyRuleset,
        RulesetErrorClass::NameBucketNotClaimable,
        RulesetErrorClass::NameTooLong,
        RulesetErrorClass::TooManyNames,
    ] {
        if class.as_str() == name {
            return class;
        }
    }
    panic!("unknown fixture class {name:?}");
}

/// Builds the `TOO_MANY_NAMES` ruleset: `count` unique ambiguous-bucket
/// `name:` declarations in one `names: ambiguous` block (mirrors
/// [`too_many_detectors_ruleset`]).
fn too_many_names_ruleset(count: u64) -> String {
    use std::fmt::Write;

    let mut text = String::from("ruleset-revision: 1\nnames: ambiguous\n");
    for index in 0..count {
        let _ = writeln!(text, "name: corp-token-{index}");
    }
    text
}

#[test]
fn every_declared_rejection_class_is_reproduced() {
    let document = document();
    let rejections = document["rejections"].as_array().unwrap();

    for rejection in rejections {
        let class_name = str_field(rejection, "class");
        let expected_class = class_from_wire(class_name);

        let bytes: Vec<u8> = if let Some(oversized) = rejection.get("oversizedBytes") {
            let size = usize::try_from(oversized.as_u64().unwrap()).unwrap();
            "x".repeat(size).into_bytes()
        } else if let Some(count) = rejection.get("detectorCount") {
            too_many_detectors_ruleset(count.as_u64().unwrap()).into_bytes()
        } else if let Some(count) = rejection.get("nameCount") {
            too_many_names_ruleset(count.as_u64().unwrap()).into_bytes()
        } else {
            str_field(rejection, "ruleset").as_bytes().to_vec()
        };

        let error = load_ruleset(&bytes)
            .err()
            .unwrap_or_else(|| panic!("{class_name}: expected rejection"));
        assert_eq!(error.class(), expected_class, "{class_name}");
        assert_eq!(
            error.code(),
            redact_secret::SecretScanErrorCode::InvalidRuleset,
            "{class_name}"
        );
    }
}

/// Every `RulesetErrorClass` the core defines appears exactly once in the
/// fixture's `rejections` array: the fixture is complete, not merely
/// non-empty.
#[test]
fn every_class_the_core_defines_is_covered_exactly_once() {
    let document = document();
    let names: Vec<&str> = document["rejections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rejection| str_field(rejection, "class"))
        .collect();

    let all_classes = [
        "RULESET_TOO_LARGE",
        "UNKNOWN_REVISION",
        "UNKNOWN_FIELD",
        "UNSUPPORTED_CONSTRUCT",
        "UNKNOWN_ALPHABET",
        "UNKNOWN_VALIDATOR",
        "SPECIFICITY_NOT_CLAIMABLE",
        "MISSING_FIELD",
        "PREFIX_TOO_SHORT",
        "PREFIX_TOO_LONG",
        "RUN_LENGTH_OUT_OF_BOUNDS",
        "TOO_MANY_DETECTORS",
        "DUPLICATE_DETECTOR_ID",
        "RESERVED_DETECTOR_ID",
        "EMPTY_RULESET",
        "NAME_BUCKET_NOT_CLAIMABLE",
        "NAME_TOO_LONG",
        "TOO_MANY_NAMES",
    ];
    assert_eq!(names.len(), all_classes.len());
    for class in all_classes {
        assert_eq!(
            names.iter().filter(|&&name| name == class).count(),
            1,
            "{class} must appear exactly once"
        );
    }
}
