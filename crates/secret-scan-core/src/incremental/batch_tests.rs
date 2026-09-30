//! Differential tests for batching closed units (issue #985): a session that
//! processes every line closed in one `append` together must release exactly
//! what the same session releases when it processes each unit as soon as it
//! closes — the same text, findings, error, and callback calls in the same
//! order. Every value is synthetic.
//!
//! These drive the crate-private parts: the unbatched reference mode, custom
//! registries, and the retention peak. The conformance corpora run through
//! the public API in `tests/incremental_batching.rs`, since core sources may
//! not include files.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::rc::Rc;

use super::*;
use crate::error::DetectorFailure;
use crate::types::{Candidate, Confidence, Detector, DetectorContext};

type Outcome = Result<(String, Vec<Finding>), SecretScanErrorCode>;

fn drive(mut sanitizer: IncrementalSanitizer, chunks: &[&str]) -> Outcome {
    let mut text = String::new();
    let mut findings = Vec::new();
    for chunk in chunks {
        let result = sanitizer.append(chunk).map_err(SecretScanError::code)?;
        text.push_str(result.text());
        findings.extend_from_slice(result.findings());
    }
    let result = sanitizer.finalize().map_err(SecretScanError::code)?;
    text.push_str(result.text());
    findings.extend_from_slice(result.findings());
    Ok((text, findings))
}

fn unbatched(mut sanitizer: IncrementalSanitizer) -> IncrementalSanitizer {
    sanitizer.unbatched = true;
    sanitizer
}

/// Splits `input` into chunks of at least `bytes` bytes on char boundaries.
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

fn limits() -> IncrementalLimits {
    IncrementalLimits::new(
        1 << 26,
        IncrementalLimits::minimum_buffered_bytes(1 << 16, 1 << 16),
        1 << 16,
        1 << 16,
    )
    .unwrap()
}

fn full() -> IncrementalSanitizer {
    IncrementalSanitizer::new(limits()).unwrap()
}

/// Runs `input` in chunks of each size through a batched and an unbatched
/// session and requires identical outcomes.
fn assert_batching_is_invisible(
    make: &dyn Fn() -> IncrementalSanitizer,
    label: &str,
    input: &str,
    chunk_sizes: &[usize],
) {
    for &size in chunk_sizes {
        let chunks = chunked(input, size);
        let expected = drive(unbatched(make()), &chunks);
        let actual = drive(make(), &chunks);
        assert_eq!(actual, expected, "{label}, {size}-byte chunks");
    }
}

/// Emits one fixed candidate per `tie-` line, at a span and confidence
/// chosen so that, within the line, the two disjoint pairs {`d0`, `d3`} and
/// {`d1`, `d2`} tie on every overlap-resolution key but emission order. A
/// `pre-<n>` line gives only detector `n` a candidate, which moves that
/// detector's emission order on every later line of the same scan.
struct TieDetector {
    id: &'static str,
    role: usize,
}

impl Detector for TieDetector {
    fn id(&self) -> &str {
        self.id
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        // (start, end, confidence) inside a `tie-` line: a1 = d0, b1 = d1,
        // b2 = d2, a2 = d3. Severity follows confidence (High redacts,
        // Medium warns), so each pair holds one of each.
        let spans = [
            (2, 8, Confidence::High),
            (0, 4, Confidence::Medium),
            (6, 12, Confidence::High),
            (10, 14, Confidence::Medium),
        ];
        let mut candidates = Vec::new();
        let mut line_start = 0;
        for line in input.split_inclusive('\n') {
            let (start, end, confidence) = if line.starts_with("tie-") {
                spans[self.role]
            } else if line.starts_with(&format!("pre-{}", self.role)) {
                (0, 4, Confidence::High)
            } else {
                line_start += line.len();
                continue;
            };
            candidates.push(Candidate::new(
                "synthetic_tie",
                confidence,
                ByteRange::new(line_start + start, line_start + end).ok_or(DetectorFailure)?,
            ));
            line_start += line.len();
        }
        Ok(candidates)
    }
}

fn tie_registry() -> DetectorRegistry {
    let mut registry = DetectorRegistry::default();
    for (role, id) in ["tie-d0", "tie-d1", "tie-d2", "tie-d3"]
        .into_iter()
        .enumerate()
    {
        registry
            .register(Box::new(TieDetector { id, role }))
            .unwrap();
    }
    registry
}

fn tie_session() -> IncrementalSanitizer {
    IncrementalSanitizer::from_registry(
        tie_registry(),
        limits(),
        Box::new(DefaultPolicy),
        Box::new(default_placeholder_formatter),
    )
}

#[test]
fn an_exact_overlap_tie_resolves_as_in_its_own_unit_when_batched() {
    let registry = tie_registry();
    let unit = "tie-line-0000\n";
    let alone = detect(unit, &registry, None).unwrap();
    assert_eq!(alone.len(), 2, "the tie line resolves to one of two pairs");

    let mut whole_input_flipped = false;
    for role in 0..4 {
        let earlier = format!("pre-{role}-line\n");
        let input = format!("{earlier}{unit}");
        let unit_ends = [earlier.len(), input.len()];

        // Batched: the tie line's findings are exactly its own.
        let batched = detect_units(&input, 0, &registry, &unit_ends, None)
            .unwrap()
            .expect("every candidate is inside one unit");
        let tie_findings: Vec<_> = batched
            .iter()
            .filter(|found| found.range().start() >= earlier.len())
            .map(|found| {
                (
                    found.detector().to_owned(),
                    found.range().start() - earlier.len(),
                )
            })
            .collect();
        let expected: Vec<_> = alone
            .iter()
            .map(|found| (found.detector().to_owned(), found.range().start()))
            .collect();
        assert_eq!(tie_findings, expected, "pre-{role}");

        // Scanned as one input, emission order counts across lines, so an
        // earlier line can flip the tie: the gap batching must not inherit.
        let whole: Vec<_> = detect(&input, &registry, None)
            .unwrap()
            .iter()
            .filter(|found| found.range().start() >= earlier.len())
            .map(|found| {
                (
                    found.detector().to_owned(),
                    found.range().start() - earlier.len(),
                )
            })
            .collect();
        whole_input_flipped |= whole != expected;

        assert_batching_is_invisible(&tie_session, "tie", &input, &[usize::MAX]);
    }
    assert!(
        whole_input_flipped,
        "the fixture must hold a tie that emission order across lines decides",
    );
}

/// Records every policy and formatter call, failing on the configured
/// finding ids.
fn recording_session(
    fail_policy_on: Option<&'static str>,
    fail_formatter_on: Option<&'static str>,
    limits: IncrementalLimits,
    log: &Rc<RefCell<Vec<String>>>,
) -> IncrementalSanitizer {
    let policy_log = Rc::clone(log);
    let policy = move |finding: &DetectedFinding, context: &IncrementalPolicyContext| {
        policy_log.borrow_mut().push(format!(
            "policy {} {} {:?}",
            finding.id(),
            context.finding_index(),
            finding.range()
        ));
        if fail_policy_on == Some(finding.id()) {
            return Err(PolicyFailure);
        }
        Policy::evaluate(&DefaultPolicy, finding, &PolicyContext::new(0, 0))
    };
    let formatter_log = Rc::clone(log);
    let formatter = move |finding: &Finding, context: &PlaceholderContext| {
        formatter_log.borrow_mut().push(format!(
            "format {} {} {:?}",
            finding.id(),
            context.placeholder_index(),
            finding.range()
        ));
        if fail_formatter_on == Some(finding.id()) {
            return Err(FormatterFailure);
        }
        default_placeholder_formatter(finding, context)
    };
    IncrementalSanitizer::with_policy_and_formatter(limits, Box::new(policy), Box::new(formatter))
        .unwrap()
}

/// Which finding the policy and the formatter fail on, the session limits,
/// and the chunks.
type FailureCase = (
    Option<&'static str>,
    Option<&'static str>,
    IncrementalLimits,
    Vec<String>,
);

#[test]
fn failures_and_callbacks_keep_the_unbatched_order() {
    let secret = |n: usize| format!("api_key=SYNTHETICq8vN3xR7tLm2Kp9W{n:02}\n");
    let many: String = (0..8).map(secret).collect();
    // Room for a few secret lines at a time, not for all of `many`.
    let tight = IncrementalLimits::new(1 << 20, 256, 64, 64).unwrap();
    assert!(many.len() > tight.max_buffered_bytes());
    let cases: Vec<FailureCase> = vec![
        // A formatter failure on the first finding comes before a policy
        // failure on the second, as when each line was processed alone.
        (
            Some("finding-2"),
            Some("finding-1"),
            limits(),
            vec![many.clone()],
        ),
        (Some("finding-4"), None, limits(), vec![many.clone()]),
        (None, Some("finding-5"), limits(), vec![many.clone()]),
        (None, None, limits(), vec![many.clone()]),
        // Closed lines are processed before a limit failure later in the
        // same chunk, so their callbacks run and their failure wins.
        (
            None,
            None,
            tight,
            vec![format!("{}{}", secret(0), "x".repeat(100))],
        ),
        (
            Some("finding-1"),
            None,
            tight,
            vec![format!("{}{}", secret(0), "x".repeat(100))],
        ),
        (
            None,
            Some("finding-2"),
            tight,
            vec![format!("{}{}{}", secret(0), secret(1), "y".repeat(100))],
        ),
        // A small buffer flushes the batch in the middle of a chunk.
        (None, None, tight, vec![many.clone()]),
        (Some("finding-3"), None, tight, vec![many]),
    ];
    for (policy, formatter, limits, chunks) in cases {
        let chunks: Vec<&str> = chunks.iter().map(String::as_str).collect();
        let expected_log = Rc::new(RefCell::new(Vec::new()));
        let expected = drive(
            unbatched(recording_session(policy, formatter, limits, &expected_log)),
            &chunks,
        );
        let actual_log = Rc::new(RefCell::new(Vec::new()));
        let actual = drive(
            recording_session(policy, formatter, limits, &actual_log),
            &chunks,
        );
        let label = format!("policy {policy:?}, formatter {formatter:?}, {limits:?}");
        assert_eq!(actual, expected, "{label}");
        assert_eq!(*actual_log.borrow(), *expected_log.borrow(), "{label}");
    }
}

/// Fails detection with an invalid candidate on `bad` lines only.
struct FailingOnLine;

impl Detector for FailingOnLine {
    fn id(&self) -> &'static str {
        "failing-on-line"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        // A candidate whose text is its own type name is rejected as
        // malformed by the pipeline.
        Ok(input
            .match_indices("synthetic_bad")
            .filter_map(|(start, matched)| {
                ByteRange::new(start, start + matched.len())
                    .map(|range| Candidate::new("synthetic_bad", Confidence::High, range))
            })
            .collect())
    }
}

#[test]
fn a_detection_failure_in_a_batch_is_met_in_unit_order() {
    for fail_policy in [false, true] {
        let make = |log: &Rc<RefCell<Vec<String>>>| {
            let mut registry = DetectorRegistry::with_built_in([]).unwrap();
            registry.register(Box::new(FailingOnLine)).unwrap();
            let policy_log = Rc::clone(log);
            let policy = move |finding: &DetectedFinding, _: &IncrementalPolicyContext| {
                policy_log.borrow_mut().push(finding.id().to_owned());
                if fail_policy {
                    Err(PolicyFailure)
                } else {
                    Ok(Action::Redact)
                }
            };
            IncrementalSanitizer::from_registry(
                registry,
                limits(),
                Box::new(policy),
                Box::new(default_placeholder_formatter),
            )
        };
        let input = "api_key=SYNTHETICq8vN3xR7tLm2Kp9Wd\nplain\nsynthetic_bad\n";
        let expected_log = Rc::new(RefCell::new(Vec::new()));
        let expected = drive(unbatched(make(&expected_log)), &[input]);
        let actual_log = Rc::new(RefCell::new(Vec::new()));
        let actual = drive(make(&actual_log), &[input]);
        assert_eq!(actual, expected);
        assert_eq!(*actual_log.borrow(), *expected_log.borrow());
        let expected_code = if fail_policy {
            SecretScanErrorCode::PolicyFailure
        } else {
            SecretScanErrorCode::InvalidCandidate
        };
        assert_eq!(actual, Err(expected_code));
    }
}

#[test]
fn closed_lines_in_one_append_are_detected_together() {
    // Guards the tests above against a batch that silently falls back to
    // per-unit scanning: a plain multi-line chunk takes the batched path.
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = "first line\napi_key=SYNTHETICq8vN3xR7tLm2Kp9Wd\nlast line\n";
    let unit_ends = [11, 46, input.len()];
    let batched = detect_units(input, 0, &registry, &unit_ends, None).unwrap();
    assert_eq!(batched.map(|found| found.len()), Some(1));

    let mut sanitizer = full();
    sanitizer.append(input).unwrap();
    assert_eq!(sanitizer.batched_units, 3);
}

#[test]
fn closed_units_waiting_in_a_batch_never_outgrow_the_buffer_limit() {
    let limits = IncrementalLimits::new(1 << 20, 256, 64, 64).unwrap();
    let mut input = String::new();
    for n in 0..64 {
        writeln!(input, "line {n:02} api_key=SYNTHETICq8vN3xR7tLm2Kp{n:02}").unwrap();
    }
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    sanitizer.append(&input).unwrap();
    assert!(sanitizer.batched_units > 1, "the chunk was batched");
    assert!(
        sanitizer.peak_retained <= limits.max_buffered_bytes(),
        "{} bytes retained",
        sanitizer.peak_retained,
    );
}
