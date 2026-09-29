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

use redact_secret::{
    DefaultPolicy, DetectorRegistry, IncrementalLimits, IncrementalSanitizer, PiiSelection,
    SecretScanErrorCode, SessionState, default_placeholder_formatter, scan_and_redact,
};
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

/// One 256 KiB line built by repeating `record`, closed with `suffix`.
fn single_line(prefix: &str, record: impl Fn(usize) -> String, suffix: &str) -> String {
    const TARGET_BYTES: usize = 256 * 1_024;
    let mut input = String::from(prefix);
    let mut index = 0;
    while input.len() < TARGET_BYTES {
        input.push_str(&record(index));
        index += 1;
    }
    input.push_str(suffix);
    input
}

#[test]
fn a_long_single_line_of_assignments_scans_in_linear_time() {
    // Minified JSON and single-line logs put thousands of `name: value`
    // pairs on one line. A per-pair look back to the line start made that
    // quadratic: 256 KiB took ~1.4 s optimized and over 50 s unoptimized
    // (issue #989). Linear, it takes tens of milliseconds optimized and
    // under a second unoptimized, so the budget below separates the two by
    // a wide margin on either profile.
    const DECLARED_MS: u128 = 500;
    let _isolation = timed();

    let minified_json = single_line(
        "{\"items\":[",
        |i| {
            format!(
                "{{\"id\":{i},\"status\":200,\"name\":\"item-{i}\",\"enabled\":true,\"tags\":[\"a\",\"b\"],\"url\":\"https://example.invalid/p/{i}\"}},"
            )
        },
        "{}]}",
    );
    let dense_credential_names = single_line(
        "{",
        |i| format!("\"api_key\":\"SYNTHETICvalue{i:08}Xq9Zr7Lm\","),
        "\"end\":1}",
    );

    for (id, input) in [
        ("minified-json", minified_json),
        ("dense-api-key-pairs", dense_credential_names),
    ] {
        assert!(!input.contains('\n'), "{id}: must be one line");
        let started_at = Instant::now();
        let (text, findings) = whole_input(&input);
        let elapsed = started_at.elapsed().as_millis();
        let budget = runtime_budget_ms(DECLARED_MS);
        assert!(
            elapsed <= budget,
            "{id}: whole-input scan of {} bytes took {elapsed}ms, above the {budget}ms budget",
            input.len(),
        );
        assert_eq!(whole_input(&input), (text, findings), "{id}: deterministic");
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

/// Splits `input` into chunks of at least `bytes` bytes, each ending on a
/// character boundary.
fn chunked(input: &str, bytes: usize) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        let mut end = (cursor + bytes).min(input.len());
        while !input.is_char_boundary(end) {
            end += 1;
        }
        chunks.push(&input[cursor..end]);
        cursor = end;
    }
    chunks
}

#[test]
fn whitespace_lines_after_an_open_assignment_stay_linear_in_a_session() {
    // An open contextual assignment followed only by whitespace-only lines
    // stays open, and every closed line asks again whether it is. Each ask
    // used to renormalize the whole retained unit and scan back across every
    // blank line, so the session cost grew with the square of the gap
    // (issue #986: 40,000 eight-space lines took ~9s in a release build).
    // Maintained incrementally it is a few tens of milliseconds, so the
    // budget below is far above the linear cost and far below the quadratic.
    const LINES: usize = 40_000;
    const DECLARED_RUNTIME_MS: u128 = 500;
    let _isolation = timed();

    for (label, line) in [("blank", "\n"), ("eight-space", "        \n")] {
        let mut input = String::from("API_KEY=\n");
        input.push_str(&line.repeat(LINES));
        let (expected_text, expected_findings) = whole_input(&input);
        let limits = IncrementalLimits::new(
            input.len(),
            IncrementalLimits::minimum_buffered_bytes(input.len(), input.len()),
            input.len(),
            input.len(),
        )
        .unwrap();

        for chunk_bytes in [64 * 1_024, 1_024] {
            let chunks = chunked(&input, chunk_bytes);
            let started_at = Instant::now();
            let session = run_session(&chunks, limits);
            let elapsed = started_at.elapsed().as_millis();

            assert_eq!(session.text(), expected_text, "{label}/{chunk_bytes}: text");
            assert_eq!(
                session.findings(),
                expected_findings,
                "{label}/{chunk_bytes}: findings",
            );
            let budget = runtime_budget_ms(DECLARED_RUNTIME_MS);
            assert!(
                elapsed <= budget,
                "{label} lines, {chunk_bytes}-byte chunks: session took {elapsed}ms, above the {budget}ms budget",
            );
        }
    }
}

#[test]
fn many_pii_candidates_on_one_line_associate_context_in_linear_time() {
    // PII context association used to scan from the input start for every
    // candidate's logical line, compare every candidate with every other for
    // its barriers, and renormalize the whole line for every candidate on it
    // once per context occurrence. On one line that is worse than quadratic:
    // 125 of the records below (11.6 KB) took ~21 s in a release build
    // (issue #902). Grouped by line and indexed, 700 records (65 KB, one
    // CLI read and one incremental unit) take a few milliseconds optimized,
    // so the budget below is orders of magnitude from either side.
    const RECORD: &str = "client_ip=192.0.2.1 email=test@example.com \
                          iban=GB82WEST12345698765432 card 4111111111111111 ";
    const RECORDS: usize = 700;
    const DECLARED_MS: u128 = 500;
    let _isolation = timed();

    let input = RECORD.repeat(RECORDS);
    assert!(!input.contains('\n'));
    let limits = IncrementalLimits::new(
        input.len(),
        IncrementalLimits::minimum_buffered_bytes(input.len(), input.len()),
        input.len(),
        input.len(),
    )
    .unwrap();
    for selector in ["pii:global", "pii:us"] {
        let selection = PiiSelection::parse(&[selector]).unwrap();
        let registry = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();

        let started_at = Instant::now();
        let whole = scan_and_redact(
            &input,
            &registry,
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .unwrap();
        let elapsed = started_at.elapsed().as_millis();
        let budget = runtime_budget_ms(DECLARED_MS);
        assert!(
            elapsed <= budget,
            "{selector}: whole-input scan of {} bytes took {elapsed}ms, above the {budget}ms budget",
            input.len(),
        );
        // The documentation address, reserved domain and published test card
        // are suppressed; each record's IBAN is the one finding.
        assert_eq!(whole.findings().len(), RECORDS, "{selector}: findings");

        let started_at = Instant::now();
        let mut session = IncrementalSanitizer::with_built_in_and_pii(limits, &selection).unwrap();
        let mut text = String::new();
        let mut findings = 0;
        for chunk in chunked(&input, 64 * 1_024) {
            let result = session.append(chunk).unwrap();
            text.push_str(result.text());
            findings += result.findings().len();
        }
        let result = session.finalize().unwrap();
        text.push_str(result.text());
        findings += result.findings().len();
        let elapsed = started_at.elapsed().as_millis();
        assert!(
            elapsed <= budget,
            "{selector}: incremental session took {elapsed}ms, above the {budget}ms budget",
        );
        assert_eq!(text, whole.text(), "{selector}: incremental text");
        assert_eq!(findings, RECORDS, "{selector}: incremental findings");
    }
}
