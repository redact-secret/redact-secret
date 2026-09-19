//! Asserts the `common` profile against its reviewed, committed expectations
//! over the canonical synchronous corpus
//! (`decision-define-detector-profile-and-pack-contract`, qualification
//! obligations 2 and 3).
//!
//! `common` findings differ from `full` by design: overlap resolution is
//! global, so removing `provider` competitors changes which candidate wins,
//! and a bare provider token with no credential-bearing context is not
//! detected at all. They are therefore pinned in their own file,
//! `conformance/fixtures/common-profile-expectations.json`, rather than
//! derived from the `full` expectations at runtime. A reviewer sees every
//! `common` outcome change as a diff to that file.
//!
//! The file is regenerated, never hand-edited, by running this test with
//! `REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1`; the regenerated diff is then
//! reviewed like any other conformance change. Every fixture value is
//! synthetic; the file carries detector metadata and byte offsets only,
//! never a matched value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use redact_secret::{DefaultPolicy, DetectorContext, DetectorRegistry, Profile, scan};
use serde_json::{Value, json};
use support::CanonicalFixture;

const EXPECTATIONS_FILE: &str = "common-profile-expectations.json";
const UPDATE_VARIABLE: &str = "REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS";

fn expectations_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures")
        .join(EXPECTATIONS_FILE)
}

/// Every fixture whose `support` is not `"not-yet-evaluated"`, the same set
/// `canonical_corpus.rs` asserts `full` against.
fn evaluated_fixtures() -> Vec<CanonicalFixture> {
    support::synchronous_corpus()
        .into_iter()
        .filter(|fixture| fixture.support != "not-yet-evaluated")
        .collect()
}

fn common() -> DetectorRegistry {
    let registry = DetectorRegistry::with_common_built_in([]).unwrap();
    assert_eq!(registry.profile(), Some(Profile::Common));
    registry
}

/// The `common` findings for one input, in the file's shape.
fn findings(input: &str, registry: &DetectorRegistry) -> Vec<Value> {
    scan(input, registry, &DefaultPolicy)
        .unwrap()
        .iter()
        .map(|finding| {
            json!({
                "detector": finding.detector(),
                "type": finding.type_name(),
                "confidence": finding.confidence().as_str(),
                "action": finding.action().as_str(),
                "start": finding.range().start(),
                "end": finding.range().end(),
            })
        })
        .collect()
}

/// Serializes the whole expectation set: stable key order, one fixture per
/// line, so a behavior change shows up as a one-line diff per fixture.
fn render(registry: &DetectorRegistry, fixtures: &[CanonicalFixture]) -> String {
    let detectors: Vec<&str> = registry.ids().collect();
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"profile\": \"common\",\n");
    out.push_str("  \"corpus\": \"synchronous-corpus.json\",\n");
    out.push_str("  \"offsetUnit\": \"utf8-byte\",\n");
    writeln!(
        out,
        "  \"detectors\": {},",
        serde_json::to_string(&detectors).unwrap()
    )
    .unwrap();
    writeln!(out, "  \"fixtureCount\": {},", fixtures.len()).unwrap();
    out.push_str("  \"fixtures\": [\n");
    let lines: Vec<String> = fixtures
        .iter()
        .map(|fixture| {
            let entry = json!({
                "id": fixture.id,
                "expected": findings(&fixture.input, registry),
            });
            format!("    {}", serde_json::to_string(&entry).unwrap())
        })
        .collect();
    out.push_str(&lines.join(",\n"));
    out.push_str("\n  ]\n}\n");
    out
}

#[test]
fn common_findings_match_the_committed_common_expectations() {
    let registry = common();
    let fixtures = evaluated_fixtures();
    let rendered = render(&registry, &fixtures);
    let path = expectations_path();

    if std::env::var_os(UPDATE_VARIABLE).is_some() {
        std::fs::write(&path, &rendered).unwrap();
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("{EXPECTATIONS_FILE} is missing; regenerate it with {UPDATE_VARIABLE}=1")
    });
    let committed: Value = serde_json::from_str(&committed).unwrap();
    let actual: Value = serde_json::from_str(&rendered).unwrap();

    assert_eq!(committed["profile"], "common");
    assert_eq!(
        committed["detectors"], actual["detectors"],
        "common membership changed; regenerate {EXPECTATIONS_FILE} with {UPDATE_VARIABLE}=1 and review the diff"
    );
    let committed_fixtures = committed["fixtures"].as_array().unwrap();
    let actual_fixtures = actual["fixtures"].as_array().unwrap();
    let committed_ids: Vec<&Value> = committed_fixtures.iter().map(|f| &f["id"]).collect();
    let actual_ids: Vec<&Value> = actual_fixtures.iter().map(|f| &f["id"]).collect();
    assert_eq!(
        committed_ids, actual_ids,
        "the evaluated corpus changed; regenerate {EXPECTATIONS_FILE} with {UPDATE_VARIABLE}=1 and review the diff"
    );
    let mismatched: Vec<&Value> = committed_fixtures
        .iter()
        .zip(actual_fixtures)
        .filter(|(committed, actual)| committed != actual)
        .map(|(committed, _)| &committed["id"])
        .collect();
    assert!(
        mismatched.is_empty(),
        "{} fixture(s) disagree with {EXPECTATIONS_FILE}: {mismatched:?}",
        mismatched.len()
    );
}

/// Every `common` finding comes from a `common` detector, never a
/// `provider`-only one. Checking `finding.detector()` against `common`'s own
/// `registry.ids()` would be true by construction — `scan` can only
/// attribute a finding to a detector actually in the registry it was given —
/// so this instead checks against the `provider`-only ids `full` has and
/// `common` does not: a finding under one of those would mean the registry,
/// not just its overlap outcomes, changed.
#[test]
fn common_findings_come_only_from_common_detectors() {
    let registry = common();
    let common_ids: Vec<&str> = registry.ids().collect();
    let full_registry = DetectorRegistry::with_built_in([]).unwrap();
    let provider_only_ids: Vec<&str> = full_registry
        .ids()
        .filter(|id| !common_ids.contains(id))
        .collect();
    assert!(
        !provider_only_ids.is_empty(),
        "sanity: full must have detectors common does not"
    );
    for fixture in evaluated_fixtures() {
        for finding in scan(&fixture.input, &registry, &DefaultPolicy).unwrap() {
            assert!(
                !provider_only_ids.contains(&finding.detector()),
                "{}: {} is a provider-only detector",
                fixture.id,
                finding.detector()
            );
        }
    }
}

/// Per-detector invariance over the whole canonical corpus: each `common`
/// detector's candidates in `common` equal its candidates in `full`.
#[test]
fn every_common_detector_emits_the_same_candidates_as_in_full() {
    let full = DetectorRegistry::with_built_in([]).unwrap();
    let common = common();
    for fixture in evaluated_fixtures() {
        let context = DetectorContext::new(fixture.input.len());
        for registered in common.detectors() {
            let in_full = full
                .detectors()
                .iter()
                .find(|candidate| candidate.id() == registered.id())
                .unwrap();
            assert_eq!(
                registered
                    .detector()
                    .detect(&fixture.input, &context)
                    .unwrap(),
                in_full.detector().detect(&fixture.input, &context).unwrap(),
                "{}: {}",
                fixture.id,
                registered.id()
            );
        }
    }
}
