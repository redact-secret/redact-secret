//! Asserts `scan` against the canonical synchronous corpus
//! (`decision-govern-cross-language-conformance`): the same behavioral
//! contract `bindings/python/tests/test_conformance.py` asserts for the
//! Python binding, now asserted on the Rust core itself rather than only
//! through a binding.
//!
//! Every fixture value is synthetic; nothing here reproduces a matched value
//! outside the fixture input it came from.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Confidence, DefaultPolicy, DetectorRegistry, scan};
use support::CanonicalFixture;

fn registry() -> DetectorRegistry {
    DetectorRegistry::with_built_in([]).unwrap()
}

/// Every fixture whose `support` is not `"not-yet-evaluated"`: a current
/// behavioral contract, not a documented future gap.
fn evaluated_fixtures() -> Vec<CanonicalFixture> {
    support::synchronous_corpus()
        .into_iter()
        .filter(|fixture| fixture.support != "not-yet-evaluated")
        .collect()
}

#[test]
fn scan_matches_the_canonical_synchronous_corpus() {
    let registry = registry();
    for fixture in evaluated_fixtures() {
        let findings = scan(&fixture.input, &registry, &DefaultPolicy).unwrap();
        let actual: Vec<(&str, &str, Confidence, usize, usize)> = findings
            .iter()
            .map(|finding| {
                (
                    finding.detector(),
                    finding.type_name(),
                    finding.confidence(),
                    finding.range().start(),
                    finding.range().end(),
                )
            })
            .collect();
        let expected: Vec<(&str, &str, Confidence, usize, usize)> = fixture
            .declared_expectations()
            .iter()
            .map(|expectation| {
                (
                    expectation.detector.as_str(),
                    expectation.type_name.as_str(),
                    expectation.confidence,
                    expectation.start,
                    expectation.end,
                )
            })
            .collect();
        assert_eq!(actual, expected, "{}", fixture.id);

        // `obfuscation` is optional in the schema; only the fixtures that
        // declare it are asserted, so every pre-existing fixture stays valid
        // unchanged.
        for (finding, expectation) in findings.iter().zip(fixture.declared_expectations()) {
            if let Some(declared) = &expectation.obfuscation {
                assert_eq!(finding.obfuscation().as_str(), declared, "{}", fixture.id);
            }
        }
    }
}

/// Guards against every fixture being filtered out by accident, which would
/// make the assertion above pass without checking anything.
#[test]
fn the_evaluated_fixture_set_is_not_empty() {
    let fixtures = evaluated_fixtures();
    assert!(!fixtures.is_empty());
    assert!(
        fixtures
            .iter()
            .any(|fixture| !fixture.declared_expectations().is_empty())
    );
    assert!(
        fixtures
            .iter()
            .any(|fixture| fixture.declared_expectations().is_empty())
    );
}
