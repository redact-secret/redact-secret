//! Bounded adversarial behavior for the canonical corpus.
//!
//! Every adversarial fixture in
//! `conformance/fixtures/synchronous-corpus.json` declares the input,
//! finding-count, and runtime caps it must stay within. This runs each of
//! them through both the whole-input pipeline and a bounded incremental
//! session and asserts the declared caps hold, that the two surfaces agree,
//! and that detection is deterministic.
//!
//! Every fixture input is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

use redact_secret::{IncrementalLimits, IncrementalSanitizer, SecretScanErrorCode, SessionState};
use support::{CanonicalFixture, run_session, synchronous_corpus, whole_input};

/// Keeps the wall-clock assertions from measuring their sibling tests.
///
/// The tests in this binary run concurrently and most of them walk the whole
/// adversarial corpus, so a per-fixture `Instant` measurement would also count
/// the CPU the other tests are spending. Timed tests take the write side and
/// run alone; every other test takes the read side and still runs alongside
/// its peers.
static TIMING_ISOLATION: RwLock<()> = RwLock::new(());

/// Held by a test whose assertions depend on wall-clock time.
fn timed() -> RwLockWriteGuard<'static, ()> {
    TIMING_ISOLATION
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Held by a test that does not measure time, so a timed test can exclude it.
fn untimed() -> RwLockReadGuard<'static, ()> {
    TIMING_ISOLATION
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The adversarial tier of the canonical synchronous corpus.
fn adversarial_fixtures() -> Vec<CanonicalFixture> {
    synchronous_corpus()
        .into_iter()
        .filter(|fixture| fixture.tier == "adversarial" || fixture.kind == "adversarial")
        .collect()
}

/// How much slack an unoptimized build gets over the corpus's declared
/// `maxRuntimeMs`.
///
/// The declared cap describes the shipped, optimized core. The slowest
/// adversarial fixture (`connection-adversarial-azure-overlong`, 300KB)
/// measures ~0.9s in the unoptimized build `cargo test` produces by default,
/// and hosted Windows runners have taken up to ~5.0s for it under load, so
/// asserting the declared number in a debug build would be measuring the
/// profile and runner contention rather than the detector. An optimized test
/// binary is held to the declared cap exactly; a debug binary is held to this
/// multiple of it, which leaves headroom over the slowest observed runner and
/// is still orders of magnitude below the superlinear blowup these fixtures
/// exist to catch.
const DEBUG_RUNTIME_ALLOWANCE: u128 = 32;

/// The runtime budget this build is held to for `declared` declared
/// milliseconds.
fn runtime_budget_ms(declared: u128) -> u128 {
    if cfg!(debug_assertions) {
        declared * DEBUG_RUNTIME_ALLOWANCE
    } else {
        declared
    }
}

/// Limits sized from the fixture itself: large enough that a fixture within
/// its declared caps never trips a session limit, so a cap violation is
/// reported as such rather than as a limit failure.
fn limits_for(fixture: &CanonicalFixture) -> IncrementalLimits {
    let declared = fixture
        .resource
        .expect("an adversarial fixture must declare resource caps")
        .max_input_bytes;
    let construct = declared.max(1);
    IncrementalLimits::new(
        declared.max(fixture.input.len()),
        IncrementalLimits::minimum_buffered_bytes(construct, construct),
        construct,
        construct,
    )
    .unwrap()
}

#[test]
fn the_adversarial_tier_is_present_and_fully_declared() {
    let _isolation = untimed();
    let fixtures = adversarial_fixtures();
    assert!(
        fixtures.len() >= 26,
        "the adversarial corpus shrank to {} fixtures",
        fixtures.len(),
    );
    for fixture in &fixtures {
        let resource = fixture
            .resource
            .unwrap_or_else(|| panic!("{}: adversarial fixtures must declare caps", fixture.id));
        assert!(resource.max_input_bytes > 0, "{}", fixture.id);
        assert!(resource.max_runtime_ms > 0, "{}", fixture.id);
        assert_eq!(
            fixture.declared_expectations().len(),
            resource.max_findings,
            "{}: declared maxFindings must equal the expected finding count",
            fixture.id,
        );
    }
}

#[test]
fn every_adversarial_fixture_stays_within_its_declared_input_and_finding_caps() {
    let _isolation = untimed();
    for fixture in adversarial_fixtures() {
        let resource = fixture.resource.unwrap();
        assert!(
            fixture.input.len() <= resource.max_input_bytes,
            "{}: input is {} bytes, above the declared {} cap",
            fixture.id,
            fixture.input.len(),
            resource.max_input_bytes,
        );

        let (_, findings) = whole_input(&fixture.input);
        assert!(
            findings.len() <= resource.max_findings,
            "{}: {} findings, above the declared {} cap",
            fixture.id,
            findings.len(),
            resource.max_findings,
        );
        let expectations = fixture.declared_expectations();
        assert_eq!(
            findings.len(),
            expectations.len(),
            "{}: finding count",
            fixture.id,
        );
        for (index, expected) in expectations.iter().enumerate() {
            let finding = &findings[index];
            let label = format!("{}: finding {index}", fixture.id);
            assert_eq!(finding.detector(), expected.detector, "{label} detector");
            assert_eq!(finding.type_name(), expected.type_name, "{label} type");
            assert_eq!(
                finding.confidence(),
                expected.confidence,
                "{label} confidence"
            );
            assert_eq!(finding.range().start(), expected.start, "{label} start");
            assert_eq!(finding.range().end(), expected.end, "{label} end");
        }
    }
}

#[test]
fn every_adversarial_fixture_is_deterministic() {
    let _isolation = untimed();
    for fixture in adversarial_fixtures() {
        let (first_text, first_findings) = whole_input(&fixture.input);
        let (second_text, second_findings) = whole_input(&fixture.input);
        assert_eq!(first_text, second_text, "{}", fixture.id);
        assert_eq!(first_findings, second_findings, "{}", fixture.id);
    }
}

#[test]
fn the_whole_input_adversarial_corpus_stays_within_its_declared_runtime_cap() {
    let _isolation = timed();
    for fixture in adversarial_fixtures() {
        let resource = fixture.resource.unwrap();
        let started_at = Instant::now();
        let (_, findings) = whole_input(&fixture.input);
        let elapsed = started_at.elapsed().as_millis();
        let budget = runtime_budget_ms(resource.max_runtime_ms);
        assert!(
            elapsed <= budget,
            "{}: whole-input scan took {elapsed}ms, above the {budget}ms budget for the declared {}ms cap",
            fixture.id,
            resource.max_runtime_ms,
        );
        assert!(findings.len() <= resource.max_findings, "{}", fixture.id);
    }
}

#[test]
fn the_incremental_adversarial_corpus_agrees_and_stays_within_its_runtime_cap() {
    let _isolation = timed();
    for fixture in adversarial_fixtures() {
        let resource = fixture.resource.unwrap();
        let (expected_text, expected_findings) = whole_input(&fixture.input);
        let limits = limits_for(&fixture);

        let started_at = Instant::now();
        let session = run_session(&[&fixture.input], limits);
        let elapsed = started_at.elapsed().as_millis();

        assert_eq!(session.text(), expected_text, "{}: text", fixture.id);
        assert_eq!(
            session.findings(),
            expected_findings,
            "{}: findings",
            fixture.id,
        );
        assert!(
            session.findings().len() <= resource.max_findings,
            "{}: {} incremental findings, above the declared {} cap",
            fixture.id,
            session.findings().len(),
            resource.max_findings,
        );
        let budget = runtime_budget_ms(resource.max_runtime_ms);
        assert!(
            elapsed <= budget,
            "{}: incremental session took {elapsed}ms, above the {budget}ms budget for the declared {}ms cap",
            fixture.id,
            resource.max_runtime_ms,
        );
    }
}

#[test]
fn a_fragmented_adversarial_partition_stays_within_the_same_runtime_cap() {
    // Fragmentation is where an unbounded implementation degrades: each
    // chunk could rescan everything retained so far. Split the adversarial
    // inputs into fixed-size chunks and assert the declared runtime cap
    // still holds and the result is unchanged.
    const CHUNK_BYTES: usize = 1_024;
    let _isolation = timed();

    for fixture in adversarial_fixtures() {
        let resource = fixture.resource.unwrap();
        let (expected_text, expected_findings) = whole_input(&fixture.input);
        let limits = limits_for(&fixture);

        let mut chunks: Vec<&str> = Vec::new();
        let mut cursor = 0;
        while cursor < fixture.input.len() {
            let mut end = (cursor + CHUNK_BYTES).min(fixture.input.len());
            while !fixture.input.is_char_boundary(end) {
                end += 1;
            }
            chunks.push(&fixture.input[cursor..end]);
            cursor = end;
        }

        let started_at = Instant::now();
        let session = run_session(&chunks, limits);
        let elapsed = started_at.elapsed().as_millis();

        assert_eq!(session.text(), expected_text, "{}: text", fixture.id);
        assert_eq!(
            session.findings(),
            expected_findings,
            "{}: findings",
            fixture.id,
        );
        let budget = runtime_budget_ms(resource.max_runtime_ms);
        assert!(
            elapsed <= budget,
            "{}: {CHUNK_BYTES}-byte-chunk session took {elapsed}ms, above the {budget}ms budget for the declared {}ms cap",
            fixture.id,
            resource.max_runtime_ms,
        );
    }
}

#[test]
fn an_adversarial_input_above_a_session_limit_fails_safely_without_output() {
    let _isolation = untimed();
    // The caps above are the corpus's declaration of bounded behavior; this
    // is the complementary guarantee, that an input beyond a session's own
    // limits is refused rather than absorbed. The fixture is the corpus's
    // longest adversarial input, run under limits deliberately below it.
    let fixture = adversarial_fixtures()
        .into_iter()
        .max_by_key(|fixture| fixture.input.len())
        .expect("the adversarial corpus must not be empty");
    let limits = IncrementalLimits::new(fixture.input.len() / 2, 4_096, 1_024, 2_048).unwrap();

    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    let error = sanitizer
        .append(&fixture.input)
        .expect_err("an over-limit adversarial input must fail");

    // The failure is the fixed, input-free code for the limit that was
    // reached, and nothing is emitted before it.
    assert_eq!(
        error.code(),
        SecretScanErrorCode::InputLimitExceeded,
        "{}",
        fixture.id,
    );
    assert_eq!(error.to_string(), error.code().message(), "{}", fixture.id);
    assert!(
        !error.to_string().contains("SYNTHETIC"),
        "{}: a failure diagnostic must not carry input",
        fixture.id,
    );
    assert_eq!(sanitizer.state(), SessionState::Failed);
    assert_eq!(
        sanitizer.finalize().map(|result| result.text().to_owned()),
        Err(SecretScanErrorCode::InvalidState.into()),
        "{}: a failed session must release nothing",
        fixture.id,
    );
}
