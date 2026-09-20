//! Incremental sanitizer session tests, grouped by the areas the deliverable
//! calls out: session-state, limit-boundary, open-construct, multiline,
//! progressive-emission, final-findings, incremental-policy,
//! callback-failure, and no-plaintext-diagnostics.
//!
//! Every input is synthetic; no test embeds a credential-shaped value that
//! is not obviously a revoked fixture.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::rc::Rc;

use redact_secret::{
    Action, DefaultPolicy, DetectedFinding, DetectorRegistry, Finding, FormatterFailure,
    IncrementalLimits, IncrementalPolicy, IncrementalPolicyContext, IncrementalResult,
    IncrementalSanitizer, MAX_PLACEHOLDER_LENGTH, PlaceholderContext, PlaceholderFormatter,
    PolicyFailure, SecretScanError, SecretScanErrorCode, SessionState,
    default_placeholder_formatter, redact, scan, typed_placeholder_formatter,
};

/// Generous limits for tests that are not exercising a specific boundary.
fn generous_limits() -> IncrementalLimits {
    IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap()
}

fn session() -> IncrementalSanitizer {
    IncrementalSanitizer::new(generous_limits()).unwrap()
}

/// A session with generous limits and a caller-supplied policy and
/// placeholder formatter.
fn session_with(
    policy: Box<dyn IncrementalPolicy>,
    formatter: Box<dyn PlaceholderFormatter>,
) -> IncrementalSanitizer {
    IncrementalSanitizer::with_policy_and_formatter(generous_limits(), policy, formatter).unwrap()
}

/// The whole-input reference result: the synchronous pipeline over the same
/// input with the default policy and the default placeholder formatter.
fn whole_input(input: &str) -> (String, Vec<Finding>) {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let findings = scan(input, &registry, &DefaultPolicy).unwrap();
    let text = redact(input, &findings, &default_placeholder_formatter).unwrap();
    (text, findings)
}

// ---------------------------------------------------------------------------
// session-state
// ---------------------------------------------------------------------------

#[test]
fn starts_accepting() {
    let sanitizer = session();
    assert_eq!(sanitizer.state(), SessionState::Accepting);
}

#[test]
fn finalize_is_single_use() {
    let mut sanitizer = session();
    sanitizer.finalize().unwrap();
    assert_eq!(sanitizer.state(), SessionState::Finalized);

    let error = sanitizer.finalize().unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
    assert_eq!(sanitizer.state(), SessionState::Finalized);
}

#[test]
fn abort_rejects_every_later_call() {
    let mut sanitizer = session();
    sanitizer
        .append("api_key=SYNTHETIC_REVOKED_ABORT_FIXTURE")
        .unwrap();
    sanitizer.abort().unwrap();
    assert_eq!(sanitizer.state(), SessionState::Aborted);

    let error = sanitizer.append("ignored").unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
    assert_eq!(sanitizer.state(), SessionState::Aborted);

    let error = sanitizer.finalize().unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
    assert_eq!(sanitizer.state(), SessionState::Aborted);

    let error = sanitizer.abort().unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
    assert_eq!(sanitizer.state(), SessionState::Aborted);
}

#[test]
fn abort_precedes_finalize() {
    let mut sanitizer = session();
    sanitizer.abort().unwrap();
    let error = sanitizer.finalize().unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
    assert_eq!(sanitizer.state(), SessionState::Aborted);
}

#[test]
fn finalize_after_abort_stays_rejected() {
    let mut sanitizer = session();
    sanitizer.abort().unwrap();
    assert!(sanitizer.finalize().is_err());
    assert_eq!(sanitizer.state(), SessionState::Aborted);
}

#[test]
fn a_failure_discards_retained_text_and_rejects_every_later_call() {
    let limits = IncrementalLimits::new(1_000_000, 160, 32, 32).unwrap();
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();

    let error = sanitizer.append(&"x".repeat(33)).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::TokenLimitExceeded);
    assert_eq!(sanitizer.state(), SessionState::Failed);

    let error = sanitizer.append("ignored").unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
    let error = sanitizer.finalize().unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
    let error = sanitizer.abort().unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidState);
    assert_eq!(sanitizer.state(), SessionState::Failed);
}

#[test]
fn a_finding_free_session_finalizes_with_empty_text() {
    let mut sanitizer = session();
    let result = sanitizer.finalize().unwrap();
    assert_eq!(result.text(), "");
    assert!(result.findings().is_empty());
}

// ---------------------------------------------------------------------------
// limit-boundary
// ---------------------------------------------------------------------------

#[test]
fn limits_require_every_value_to_be_positive() {
    for limits in [
        (0, 200, 32, 32),
        (200, 0, 32, 32),
        (200, 200, 0, 32),
        (200, 200, 32, 0),
    ] {
        let error = IncrementalLimits::new(limits.0, limits.1, limits.2, limits.3).unwrap_err();
        assert_eq!(
            error.code(),
            SecretScanErrorCode::InvalidLimits,
            "{limits:?}"
        );
    }
}

#[test]
fn limits_require_token_and_multiline_within_input() {
    let error = IncrementalLimits::new(100, 300, 101, 32).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidLimits);

    let error = IncrementalLimits::new(100, 300, 32, 101).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidLimits);
}

#[test]
fn limits_require_buffered_to_accommodate_the_construct_limit_and_reserve() {
    // construct_max = 100, so buffered must be at least 100 + 128 = 228.
    let error = IncrementalLimits::new(1_000, 227, 100, 64).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidLimits);

    let limits = IncrementalLimits::new(1_000, 228, 100, 64).unwrap();
    assert_eq!(limits.max_buffered_bytes(), 228);
}

#[test]
fn valid_limits_round_trip_through_their_accessors() {
    let limits = IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap();
    assert_eq!(limits.max_input_bytes(), 1_000_000);
    assert_eq!(limits.max_buffered_bytes(), 16_512);
    assert_eq!(limits.max_token_bytes(), 8_192);
    assert_eq!(limits.max_multiline_bytes(), 16_384);
}

#[test]
fn input_limit_exceeded_fails_safely_with_no_output() {
    let limits = IncrementalLimits::new(10, 200, 10, 10).unwrap();
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    let error = sanitizer.append(&"x".repeat(11)).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InputLimitExceeded);
    assert_eq!(sanitizer.state(), SessionState::Failed);
}

#[test]
fn token_limit_exceeded_fails_before_emitting_any_byte() {
    let limits = IncrementalLimits::new(1_000_000, 160, 32, 32).unwrap();
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    let error = sanitizer.append(&"x".repeat(33)).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::TokenLimitExceeded);
    assert_eq!(sanitizer.state(), SessionState::Failed);
}

#[test]
fn multiline_limit_exceeded_fails_before_emitting_any_byte() {
    let limits = IncrementalLimits::new(1_000_000, 192, 64, 64).unwrap();
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    let chunk = format!("-----BEGIN PRIVATE KEY-----\n{}", "A".repeat(100));
    let error = sanitizer.append(&chunk).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::MultilineLimitExceeded);
    assert_eq!(sanitizer.state(), SessionState::Failed);
}

/// fixture: lifecycle-token-construct-accepted-at-exact-limit
#[test]
fn an_open_token_construct_exactly_at_its_limit_is_accepted() {
    let limits = IncrementalLimits::new(512, 192, 32, 64).unwrap();
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    let chunk = "x".repeat(limits.max_token_bytes());

    assert_eq!(sanitizer.append(&chunk).unwrap().text(), "");
    let result = sanitizer.finalize().unwrap();

    assert_eq!(result.text(), chunk);
    assert_eq!(sanitizer.state(), SessionState::Finalized);
}

#[test]
fn an_open_multiline_construct_exactly_at_its_limit_is_accepted() {
    let limits = IncrementalLimits::new(512, 256, 64, 128).unwrap();
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    let chunk = format!("-----BEGIN PRIVATE KEY-----\n{}", "A".repeat(100));
    assert_eq!(chunk.len(), limits.max_multiline_bytes());

    assert_eq!(sanitizer.append(&chunk).unwrap().text(), "");
    let result = sanitizer.finalize().unwrap();

    assert_eq!(result.text(), chunk);
    assert_eq!(sanitizer.state(), SessionState::Finalized);
}

// ---------------------------------------------------------------------------
// open-construct
// ---------------------------------------------------------------------------

#[test]
fn a_bearer_header_split_across_a_physical_line_stays_open() {
    let mut sanitizer = session();
    let held = sanitizer.append("Authorization:\n").unwrap();
    assert_eq!(held.text(), "");
    assert!(held.findings().is_empty());

    let resolved = sanitizer
        .append("Bearer SYNTHETIC_REVOKED_BEARER_VALUE_1234567890\n")
        .unwrap();
    assert_eq!(resolved.findings().len(), 1);
    assert_eq!(resolved.findings()[0].type_name(), "bearer_token");
}

#[test]
fn a_contextual_assignment_name_without_its_operator_stays_open() {
    let mut sanitizer = session();
    let held = sanitizer.append("api_key\n").unwrap();
    assert_eq!(held.text(), "");
    assert!(held.findings().is_empty());

    let resolved = sanitizer
        .append("=SYNTHETIC_REVOKED_CONTEXT_VALUE\n")
        .unwrap();
    assert_eq!(resolved.findings().len(), 1);
    assert_eq!(resolved.findings()[0].type_name(), "contextual_secret");
}

#[test]
fn an_unrelated_open_line_does_not_block_flushing_a_prior_closed_line() {
    let mut sanitizer = session();
    let result = sanitizer.append("plain line\napi_key\n").unwrap();
    assert_eq!(result.text(), "plain line\n");
    assert!(result.findings().is_empty());

    let resolved = sanitizer
        .append("=SYNTHETIC_REVOKED_CONTEXT_VALUE\n")
        .unwrap();
    assert_eq!(resolved.findings().len(), 1);
}

// ---------------------------------------------------------------------------
// mid-exclusion-prefix (issue #480 part B; see
// docs/decisions/2026-09-20-connection-string-and-jwt-need-no-retention-hint.md)
//
// None of these three constructs need a dedicated retention hint: the
// incremental scanner only runs detection once a line closes
// (`append_retained(..., closes_line = true)` in `src/incremental.rs`), so a
// bare, un-terminated prefix is always still buffered, never judged early,
// regardless of whether a hint exists for it.
// ---------------------------------------------------------------------------

#[test]
fn a_mid_exclusion_prefix_never_reaches_the_exclusion_predicate_early() {
    let cases: [(&str, &str); 3] = [
        (
            "secret = SecretManagerServiceClient.access_secret_",
            "version(req)\n",
        ),
        ("postgres://app:$DB_PASS", "WORD@db.internal:5432/example\n"),
        (
            "Authorization: Bearer xxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
        ),
    ];
    for (prefix, rest) in cases {
        let mut sanitizer = session();
        let held = sanitizer.append(prefix).unwrap();
        assert_eq!(
            held.text(),
            "",
            "{prefix:?}: prefix alone must release nothing"
        );
        assert!(
            held.findings().is_empty(),
            "{prefix:?}: prefix alone must not be judged yet",
        );

        let completed = sanitizer.append(rest).unwrap();
        let whole = format!("{prefix}{rest}");
        let (expected_text, expected_findings) = whole_input(&whole);
        assert_eq!(completed.text(), expected_text, "{whole:?}: completed text");
        assert_eq!(
            completed.findings().len(),
            expected_findings.len(),
            "{whole:?}: completed finding count",
        );
    }
}

// ---------------------------------------------------------------------------
// multiline
// ---------------------------------------------------------------------------

#[test]
fn a_pem_block_stays_retained_until_its_delimiter_stack_resolves() {
    let mut sanitizer = session();
    let held = sanitizer.append("-----BEGIN PRIVATE KEY-----\n").unwrap();
    assert_eq!(held.text(), "");

    let held = sanitizer
        .append(&"U1lOVEhFVElDX1JFVk9LRUQ=\n".repeat(2))
        .unwrap();
    assert_eq!(held.text(), "");

    let held = sanitizer.append("-----END PRIVATE KEY-----").unwrap();
    assert_eq!(held.text(), "");

    let result = sanitizer.finalize().unwrap();
    assert_eq!(result.findings().len(), 1);
    assert_eq!(result.findings()[0].type_name(), "private_key");
    assert_eq!(result.findings()[0].action(), Action::Block);
}

#[test]
fn a_pem_block_split_one_byte_at_a_time_still_resolves_to_one_finding() {
    let mut sanitizer = session();
    let input = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        "U1lOVEhFVElDX1JFVk9LRUQ=".repeat(4)
    );
    let mut text = String::new();
    let mut findings = Vec::new();
    for byte_chunk in input.as_bytes().chunks(1) {
        let piece = std::str::from_utf8(byte_chunk).unwrap();
        let result = sanitizer.append(piece).unwrap();
        text.push_str(result.text());
        findings.extend(result.findings().to_vec());
    }
    let result = sanitizer.finalize().unwrap();
    text.push_str(result.text());
    findings.extend(result.findings().to_vec());

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].type_name(), "private_key");
    assert_eq!(text.matches("<SECRET_1>").count(), 1);
}

// ---------------------------------------------------------------------------
// progressive-emission
// ---------------------------------------------------------------------------

#[test]
fn ordinary_closed_lines_emit_immediately_without_finalize() {
    let mut sanitizer = session();
    let result = sanitizer.append("line one\nline two\n").unwrap();
    assert_eq!(result.text(), "line one\nline two\n");
    assert!(result.findings().is_empty());
    assert_eq!(sanitizer.state(), SessionState::Accepting);
}

#[test]
fn placeholder_numbering_advances_across_append_calls() {
    let mut sanitizer = session();
    let first = sanitizer
        .append("api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE_ONE\n")
        .unwrap();
    let second = sanitizer
        .append("api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE_TWO\n")
        .unwrap();
    assert_eq!(first.findings()[0].id(), "finding-1");
    assert_eq!(second.findings()[0].id(), "finding-2");
    assert!(first.text().contains("<SECRET_1>"));
    assert!(second.text().contains("<SECRET_2>"));
}

/// Runs `chunks` through a fresh session (`append` for each chunk, then
/// `finalize`), returning the concatenated text and the flattened findings
/// in call order.
fn run(chunks: &[&str]) -> (String, Vec<Finding>) {
    let mut sanitizer = session();
    let mut text = String::new();
    let mut findings = Vec::new();
    let mut collect = |result: IncrementalResult| {
        let (chunk_text, chunk_findings) = result.into_parts();
        text.push_str(&chunk_text);
        findings.extend(chunk_findings);
    };
    for chunk in chunks {
        collect(sanitizer.append(chunk).unwrap());
    }
    collect(sanitizer.finalize().unwrap());
    (text, findings)
}

#[test]
fn whole_input_acceptance_is_independent_of_chunk_partitioning() {
    let input = "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE\n";
    let (baseline_text, baseline_findings) = run(&[input]);
    assert_eq!(baseline_findings.len(), 1);

    for split in 0..=input.len() {
        let (text, findings) = run(&[&input[..split], &input[split..]]);
        assert_eq!(text, baseline_text, "split at {split}");
        assert_eq!(findings, baseline_findings, "split at {split}");
    }

    let one_byte_at_a_time: Vec<&str> = (0..input.len())
        .map(|index| &input[index..=index])
        .collect();
    let (text, findings) = run(&one_byte_at_a_time);
    assert_eq!(text, baseline_text);
    assert_eq!(findings, baseline_findings);
}

#[test]
fn whole_input_acceptance_is_independent_of_partitioning_for_a_multi_detector_input() {
    let input = concat!(
        "Authorization: Bearer SYNTHETIC_REVOKED_BEARER_VALUE_1234567890\n",
        "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE\n",
        "ordinary line with nothing secret in it\n",
        "-----BEGIN PRIVATE KEY-----\n",
        "U1lOVEhFVElDX1JFVk9LRUQ=\n",
        "-----END PRIVATE KEY-----\n",
    );
    let (baseline_text, baseline_findings) = run(&[input]);
    assert_eq!(baseline_findings.len(), 3);

    let by_line: Vec<&str> = input.split_inclusive('\n').collect();
    let (text, findings) = run(&by_line);
    assert_eq!(text, baseline_text);
    assert_eq!(findings, baseline_findings);

    let midpoint = input.len() / 2;
    let mut cut = midpoint;
    while !input.is_char_boundary(cut) {
        cut += 1;
    }
    let (text, findings) = run(&[&input[..cut], &input[cut..]]);
    assert_eq!(text, baseline_text);
    assert_eq!(findings, baseline_findings);
}

// ---------------------------------------------------------------------------
// final-findings
// ---------------------------------------------------------------------------

#[test]
fn final_findings_reproduce_the_synchronous_ids_ordering_and_absolute_ranges() {
    let chunks = [
        "Authorization: Bearer SYNTHETIC_REVOKED_BEARER_VALUE_1234567890\n",
        "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE\n",
        "-----BEGIN PRIVATE KEY-----\n",
        "U1lOVEhFVElDX1JFVk9LRUQ=\n",
        "-----END PRIVATE KEY-----\n",
    ];
    let (expected_text, expected_findings) = whole_input(&chunks.concat());

    let (text, findings) = run(&chunks);

    assert_eq!(text, expected_text);
    assert_eq!(findings, expected_findings);
    let ids: Vec<&str> = findings.iter().map(Finding::id).collect();
    assert_eq!(ids, ["finding-1", "finding-2", "finding-3"]);
}

/// `select_optimal_disjoint_set` (issue #451) replaced the pipeline's
/// greedy overlap-acceptance walk with a dynamic program, run once per
/// closed unit exactly as the greedy pass was
/// (`crate::incremental::process_unit` calls the same
/// `run_detector_pipeline` a whole-input `scan` does). Partition equivalence
/// for that change follows from the same invariant that already covered the
/// greedy walk: no candidate ever crosses a closed-unit boundary, so each
/// unit's optimal selection is decided entirely from that unit's own
/// candidates, independent of anything in an earlier or later unit.
///
/// This fixture exercises exactly that: the first line alone is a closed
/// unit carrying a genuine overlap (`bearer_token` outranks the wider
/// `contextual_secret` reading of the same quoted value, resolved and
/// flushed as `finding-1` as soon as the line closes), and only afterwards
/// does a multi-chunk PEM block open and close as its own, later unit. The
/// earlier unit's overlap winner is already finalized by the time the PEM
/// construct even starts, let alone closes — the one incremental-specific
/// shape the two-unit, single-shot `final_findings_reproduce_the_synchronous_ids_ordering_and_absolute_ranges`
/// case above does not cover, because none of its lines contain an overlap.
#[test]
fn a_construct_closes_after_an_earlier_units_overlap_winner_was_already_emitted() {
    let chunks = [
        "auth = \"Bearer SYNTHETIC_REVOKED_BEARER_OVERLAP_1234\"\n",
        "-----BEGIN PRIVATE KEY-----\n",
        "U1lOVEhFVElDX1JFVk9LRUQ=\n",
        "-----END PRIVATE KEY-----\n",
    ];
    let (expected_text, expected_findings) = whole_input(&chunks.concat());
    assert_eq!(
        expected_findings.len(),
        2,
        "the fixture must carry exactly the overlap winner and the private key"
    );
    assert_eq!(expected_findings[0].detector(), "bearer-token");

    let (text, findings) = run(&chunks);
    assert_eq!(text, expected_text);
    assert_eq!(findings, expected_findings);

    // Splitting the PEM block byte by byte cannot change the already-closed
    // first line's overlap winner.
    let pem = chunks[1..].concat();
    let one_byte_at_a_time: Vec<&str> = (0..pem.len()).map(|i| &pem[i..=i]).collect();
    let mut split_chunks = vec![chunks[0]];
    split_chunks.extend(one_byte_at_a_time);
    let (split_text, split_findings) = run(&split_chunks);
    assert_eq!(split_text, expected_text);
    assert_eq!(split_findings, expected_findings);
}

/// `connection_string::is_placeholder` gained the same non-secret-reference
/// exclusions `generic-token` already applied (issue #469). `connection_string`
/// has no incremental-specific retention hint at all -- unlike
/// `generic_token`'s `has_open_contextual_assignment` -- so nothing about
/// splitting one of these reference forms across a chunk boundary should be
/// able to change the outcome: a whole-input scan and a byte-by-byte
/// incremental scan of the identical text must still agree.
#[test]
fn connection_string_interpolation_references_agree_between_whole_input_and_incremental() {
    for password in [
        "${DB_PASSWORD}",
        "$DB_PASSWORD",
        "$env:DB_PASSWORD",
        "$(db_password)",
        "{{db_password}}",
        "{env:DB_PASSWORD}",
        "%DB_PASSWORD%",
    ] {
        let input = format!("postgres://app:{password}@db.internal:5432/example\n");
        let (expected_text, expected_findings) = whole_input(&input);
        assert_eq!(
            expected_findings,
            Vec::new(),
            "expected no findings for {input:?}"
        );

        let one_byte_at_a_time: Vec<&str> = (0..input.len()).map(|i| &input[i..=i]).collect();
        let (text, findings) = run(&one_byte_at_a_time);

        assert_eq!(text, expected_text, "byte-split mismatch for {input:?}");
        assert_eq!(
            findings, expected_findings,
            "byte-split mismatch for {input:?}"
        );
    }
}

#[test]
fn absolute_ranges_are_offsets_into_the_whole_session_input() {
    let first = "ordinary line\n";
    let second = "api_key=SYNTHETIC_REVOKED_ABSOLUTE_VALUE\n";
    let value = "SYNTHETIC_REVOKED_ABSOLUTE_VALUE";

    let (_, findings) = run(&[first, second]);

    let start = first.len() + second.find(value).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].range().start(), start);
    assert_eq!(findings[0].range().end(), start + value.len());
}

#[test]
fn absolute_ranges_count_utf8_bytes_and_not_characters() {
    // Two characters, five UTF-8 bytes: a character-counting offset would
    // report the finding three positions early.
    let prefix = "🧪 ";
    assert_eq!(prefix.len(), 5);
    assert_eq!(prefix.chars().count(), 2);
    let line = format!("{prefix}api_key=SYNTHETIC_REVOKED_ASTRAL_VALUE\n");
    let value = "SYNTHETIC_REVOKED_ASTRAL_VALUE";

    let (_, findings) = run(&[&line]);

    let byte_start = line.find(value).unwrap();
    let character_start = line.chars().take_while(|&c| c != 'S').count();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].range().start(), byte_start);
    assert_ne!(findings[0].range().start(), character_start);
    assert_eq!(findings[0].range().end(), byte_start + value.len());
}

// ---------------------------------------------------------------------------
// incremental-policy
// ---------------------------------------------------------------------------

/// What a recording callback observed, in call order.
type CallbackLog<T> = Rc<RefCell<Vec<T>>>;

/// One policy evaluation: the finding id, its absolute byte range, and the
/// finalized index its context carried.
type PolicyEvaluation = (String, usize, usize, usize);

/// A policy that records what it is handed and always redacts.
fn recording_policy() -> (Box<dyn IncrementalPolicy>, CallbackLog<PolicyEvaluation>) {
    let seen: CallbackLog<PolicyEvaluation> = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&seen);
    let policy = move |finding: &DetectedFinding, context: &IncrementalPolicyContext| {
        sink.borrow_mut().push((
            finding.id().to_string(),
            finding.range().start(),
            finding.range().end(),
            context.finding_index(),
        ));
        Ok(Action::Redact)
    };
    (Box::new(policy), seen)
}

#[test]
fn the_policy_sees_every_final_finding_once_with_its_finalized_index() {
    let (policy, seen) = recording_policy();
    let mut sanitizer = session_with(policy, Box::new(default_placeholder_formatter));
    let first = "api_key=SYNTHETIC_REVOKED_POLICY_ONE\n";
    let second = "password=SYNTHETIC_REVOKED_POLICY_TWO";

    sanitizer.append(first).unwrap();
    sanitizer.append(second).unwrap();
    sanitizer.finalize().unwrap();

    assert_eq!(
        *seen.borrow(),
        vec![
            (
                "finding-1".to_string(),
                first.find("SYNTHETIC").unwrap(),
                first.len() - 1,
                0,
            ),
            (
                "finding-2".to_string(),
                first.len() + second.find("SYNTHETIC").unwrap(),
                first.len() + second.len(),
                1,
            ),
        ]
    );
}

#[test]
fn the_policy_is_evaluated_once_per_finding_however_the_input_is_partitioned() {
    let input = "api_key=SYNTHETIC_REVOKED_PARTITION_ONE\npassword=SYNTHETIC_REVOKED_PARTITION_TWO";
    for split in 0..=input.len() {
        if !input.is_char_boundary(split) {
            continue;
        }
        let (policy, seen) = recording_policy();
        let mut sanitizer = session_with(policy, Box::new(default_placeholder_formatter));
        sanitizer.append(&input[..split]).unwrap();
        sanitizer.append(&input[split..]).unwrap();
        sanitizer.finalize().unwrap();

        let indices: Vec<usize> = seen.borrow().iter().map(|entry| entry.3).collect();
        assert_eq!(indices, [0, 1], "split at {split}");
    }
}

#[test]
fn the_policy_receives_only_safe_metadata() {
    let value = "SYNTHETIC_REVOKED_METADATA_VALUE";
    let rendered: CallbackLog<String> = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&rendered);
    let policy = move |finding: &DetectedFinding, context: &IncrementalPolicyContext| {
        sink.borrow_mut().push(format!("{finding:?}|{context:?}"));
        Ok(Action::Redact)
    };
    let mut sanitizer = session_with(Box::new(policy), Box::new(default_placeholder_formatter));

    sanitizer.append(&format!("api_key={value}\n")).unwrap();

    let rendered = rendered.borrow();
    assert_eq!(rendered.len(), 1);
    assert!(!rendered[0].contains(value));
    assert!(rendered[0].contains("finding-1"));
    assert!(rendered[0].contains("contextual_secret"));
}

#[test]
fn the_incremental_policy_context_carries_nothing_but_the_finalized_index() {
    let context = IncrementalPolicyContext::new(7);
    assert_eq!(context.finding_index(), 7);
    assert_eq!(
        format!("{context:?}"),
        "IncrementalPolicyContext { finding_index: 7 }"
    );
}

#[test]
fn the_default_incremental_policy_matches_the_default_whole_input_policy() {
    let input = "api_key=SYNTHETIC_REVOKED_DEFAULT_POLICY\n-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDX1JFVk9LRUQ=\n-----END PRIVATE KEY-----\n";
    let (expected_text, expected_findings) = whole_input(input);

    let (text, findings) = run(&[input]);

    assert_eq!(text, expected_text);
    assert_eq!(
        findings.iter().map(Finding::action).collect::<Vec<_>>(),
        expected_findings
            .iter()
            .map(Finding::action)
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// placeholder
// ---------------------------------------------------------------------------

#[test]
fn placeholder_numbering_continues_from_append_into_finalize() {
    let mut sanitizer = session();

    let appended = sanitizer
        .append("api_key=SYNTHETIC_REVOKED_PLACEHOLDER_ONE\n")
        .unwrap();
    let finalized = sanitizer
        .append("password=SYNTHETIC_REVOKED_PLACEHOLDER_TWO")
        .unwrap();
    assert_eq!(finalized.text(), "");
    let finalized = sanitizer.finalize().unwrap();

    assert_eq!(appended.text(), "api_key=<SECRET_1>\n");
    assert_eq!(finalized.text(), "password=<SECRET_2>");
    assert_eq!(finalized.findings()[0].id(), "finding-2");
}

#[test]
fn warn_and_allow_findings_keep_their_text_without_consuming_placeholder_numbers() {
    let policy = |finding: &DetectedFinding, _: &IncrementalPolicyContext| {
        Ok(match finding.id() {
            "finding-1" => Action::Warn,
            "finding-2" => Action::Allow,
            _ => Action::Redact,
        })
    };
    let mut sanitizer = session_with(Box::new(policy), Box::new(default_placeholder_formatter));

    let warned = sanitizer
        .append("api_key=SYNTHETIC_REVOKED_WARNED_VALUE\n")
        .unwrap();
    let allowed = sanitizer
        .append("password=SYNTHETIC_REVOKED_ALLOWED_VALUE\n")
        .unwrap();
    let redacted = sanitizer
        .append("client_secret=SYNTHETIC_REVOKED_REDACTED_VALUE\n")
        .unwrap();

    assert_eq!(warned.text(), "api_key=SYNTHETIC_REVOKED_WARNED_VALUE\n");
    assert_eq!(allowed.text(), "password=SYNTHETIC_REVOKED_ALLOWED_VALUE\n");
    assert_eq!(redacted.text(), "client_secret=<SECRET_1>\n");
}

#[test]
fn the_formatter_receives_the_global_finding_and_the_session_placeholder_index() {
    let seen: CallbackLog<(String, usize, usize)> = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&seen);
    let formatter = move |finding: &Finding, context: &PlaceholderContext| {
        sink.borrow_mut().push((
            finding.id().to_string(),
            finding.range().start(),
            context.placeholder_index(),
        ));
        Ok(format!("<REMOVED_{}>", context.placeholder_index()))
    };
    let mut sanitizer = session_with(Box::new(DefaultPolicy), Box::new(formatter));
    let first = "api_key=SYNTHETIC_REVOKED_FORMATTER_ONE\n";
    let second = "password=SYNTHETIC_REVOKED_FORMATTER_TWO\n";

    assert_eq!(
        sanitizer.append(first).unwrap().text(),
        "api_key=<REMOVED_1>\n"
    );
    assert_eq!(
        sanitizer.append(second).unwrap().text(),
        "password=<REMOVED_2>\n"
    );

    assert_eq!(
        *seen.borrow(),
        vec![
            ("finding-1".to_string(), first.find("SYNTHETIC").unwrap(), 1),
            (
                "finding-2".to_string(),
                first.len() + second.find("SYNTHETIC").unwrap(),
                2,
            ),
        ]
    );
}

#[test]
fn a_typed_formatter_numbers_placeholders_across_the_whole_session() {
    let mut sanitizer = session_with(
        Box::new(DefaultPolicy),
        Box::new(typed_placeholder_formatter),
    );

    let first = sanitizer
        .append("api_key=SYNTHETIC_REVOKED_TYPED_ONE\n")
        .unwrap();
    let second = sanitizer
        .append("password=SYNTHETIC_REVOKED_TYPED_TWO\n")
        .unwrap();

    assert_eq!(first.text(), "api_key=<CONTEXTUAL_SECRET_1>\n");
    assert_eq!(second.text(), "password=<CONTEXTUAL_SECRET_2>\n");
}

// ---------------------------------------------------------------------------
// callback-failure
// ---------------------------------------------------------------------------

/// The value a failing callback is handed and must never leak back out.
const CALLBACK_FAILURE_VALUE: &str = "SYNTHETIC_REVOKED_CALLBACK_FAILURE_VALUE";

/// One failing-callback session, named by the failure class it provokes.
fn failing_callback_sessions() -> Vec<(&'static str, SecretScanErrorCode, IncrementalSanitizer)> {
    vec![
        (
            "policy failure",
            SecretScanErrorCode::PolicyFailure,
            session_with(
                Box::new(|_: &DetectedFinding, _: &IncrementalPolicyContext| Err(PolicyFailure)),
                Box::new(default_placeholder_formatter),
            ),
        ),
        (
            "formatter failure",
            SecretScanErrorCode::PlaceholderFailure,
            session_with(
                Box::new(DefaultPolicy),
                Box::new(|_: &Finding, _: &PlaceholderContext| Err(FormatterFailure)),
            ),
        ),
        (
            "placeholder reproducing the matched value",
            SecretScanErrorCode::InvalidPlaceholder,
            session_with(
                Box::new(DefaultPolicy),
                Box::new(|_: &Finding, _: &PlaceholderContext| {
                    Ok(CALLBACK_FAILURE_VALUE.to_string())
                }),
            ),
        ),
        (
            "empty placeholder",
            SecretScanErrorCode::InvalidPlaceholder,
            session_with(
                Box::new(DefaultPolicy),
                Box::new(|_: &Finding, _: &PlaceholderContext| Ok(String::new())),
            ),
        ),
        (
            "oversized placeholder",
            SecretScanErrorCode::InvalidPlaceholder,
            session_with(
                Box::new(DefaultPolicy),
                Box::new(|_: &Finding, _: &PlaceholderContext| {
                    Ok("x".repeat(MAX_PLACEHOLDER_LENGTH + 1))
                }),
            ),
        ),
    ]
}

#[test]
fn a_failing_callback_fails_the_session_with_its_own_code() {
    for (name, code, mut sanitizer) in failing_callback_sessions() {
        let error = sanitizer
            .append(&format!("api_key={CALLBACK_FAILURE_VALUE}\n"))
            .unwrap_err();

        assert_eq!(error.code(), code, "{name}");
        assert_eq!(sanitizer.state(), SessionState::Failed, "{name}");
        assert_eq!(
            sanitizer.append("ignored").unwrap_err().code(),
            SecretScanErrorCode::InvalidState,
            "{name}"
        );
        assert_eq!(
            sanitizer.finalize().unwrap_err().code(),
            SecretScanErrorCode::InvalidState,
            "{name}"
        );
        assert_eq!(
            sanitizer.abort().unwrap_err().code(),
            SecretScanErrorCode::InvalidState,
            "{name}"
        );
    }
}

#[test]
fn a_callback_that_fails_at_finalize_never_releases_the_retained_unit() {
    for (name, code, mut sanitizer) in failing_callback_sessions() {
        // No line terminator: the construct stays open until finalize.
        let held = sanitizer
            .append(&format!("api_key={CALLBACK_FAILURE_VALUE}"))
            .unwrap();
        assert_eq!(held.text(), "", "{name}");
        assert!(held.findings().is_empty(), "{name}");

        let error = sanitizer.finalize().unwrap_err();

        assert_eq!(error.code(), code, "{name}");
        assert_eq!(sanitizer.state(), SessionState::Failed, "{name}");
    }
}

// ---------------------------------------------------------------------------
// no-plaintext-diagnostics
// ---------------------------------------------------------------------------

#[test]
fn no_callback_failure_diagnostic_carries_the_value_it_was_handed() {
    for (name, _, mut sanitizer) in failing_callback_sessions() {
        let input = format!("api_key={CALLBACK_FAILURE_VALUE}\n");

        let error = sanitizer.append(&input).unwrap_err();

        for rendered in [
            error.to_string(),
            format!("{error:?}"),
            error.message().to_string(),
            format!("{sanitizer:?}"),
        ] {
            assert!(
                !rendered.contains(CALLBACK_FAILURE_VALUE),
                "{name}: {rendered}"
            );
            assert!(!rendered.contains(&input), "{name}: {rendered}");
        }
    }
}

/// The documented failure classes of an incremental session, each with its
/// own code. Extending this list is a public-contract change.
const INCREMENTAL_FAILURE_CODES: [SecretScanErrorCode; 10] = [
    SecretScanErrorCode::DetectorFailure,
    SecretScanErrorCode::PolicyFailure,
    SecretScanErrorCode::PlaceholderFailure,
    SecretScanErrorCode::InvalidPlaceholder,
    SecretScanErrorCode::InvalidLimits,
    SecretScanErrorCode::InputLimitExceeded,
    SecretScanErrorCode::BufferLimitExceeded,
    SecretScanErrorCode::TokenLimitExceeded,
    SecretScanErrorCode::MultilineLimitExceeded,
    SecretScanErrorCode::InvalidState,
];

#[test]
fn every_incremental_failure_class_has_its_own_fixed_input_free_code() {
    let mut distinct = INCREMENTAL_FAILURE_CODES;
    distinct.sort_unstable();
    let mut deduplicated = distinct.to_vec();
    deduplicated.dedup();
    assert_eq!(deduplicated.len(), INCREMENTAL_FAILURE_CODES.len());

    for code in INCREMENTAL_FAILURE_CODES {
        let error = SecretScanError::new(code);
        assert_eq!(error.code(), code);
        assert!(!error.message().is_empty());
        assert_eq!(error.to_string(), code.message());
        // The error is its code and nothing else, so no diagnostic can carry
        // input, a candidate, or a matched value.
        assert_eq!(std::mem::size_of_val(&error), 1);
    }
}

#[test]
fn each_failing_callback_reports_one_of_the_documented_failure_codes() {
    for (name, code, _) in failing_callback_sessions() {
        assert!(INCREMENTAL_FAILURE_CODES.contains(&code), "{name}");
    }
}

/// Replays `chunks` through a fresh session with `limits` and then finalizes
/// it, returning the text emitted up to the first failure, that failure's
/// code (`None` when the whole replay succeeded), and the terminal state.
fn run_until_failure(
    limits: IncrementalLimits,
    chunks: &[&str],
) -> (String, Option<SecretScanErrorCode>, SessionState) {
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    let mut emitted = String::new();
    for chunk in chunks {
        match sanitizer.append(chunk) {
            Ok(result) => emitted.push_str(result.text()),
            Err(error) => return (emitted, Some(error.code()), sanitizer.state()),
        }
    }
    match sanitizer.finalize() {
        Ok(result) => emitted.push_str(result.text()),
        Err(error) => return (emitted, Some(error.code()), sanitizer.state()),
    }
    (emitted, None, sanitizer.state())
}

#[test]
fn a_limit_failure_emits_the_same_safe_error_however_the_input_is_partitioned() {
    let limits = IncrementalLimits::new(512, 192, 64, 64).unwrap();
    let input = format!("ordinary\r\napi_key=SYNTHETIC_REVOKED_{}", "X".repeat(48));

    let mut partitions: Vec<Vec<&str>> = (0..=input.len())
        .filter(|&split| input.is_char_boundary(split))
        .map(|split| vec![&input[..split], &input[split..]])
        .collect();
    partitions.push(
        (0..input.len())
            .map(|index| &input[index..=index])
            .collect(),
    );

    for chunks in partitions {
        let (emitted, code, state) = run_until_failure(limits, &chunks);

        assert_eq!(code, Some(SecretScanErrorCode::TokenLimitExceeded));
        assert_eq!(state, SessionState::Failed);
        // A failing `append` returns no text at all, so how much of the
        // already-closed prefix was handed back depends on which chunk
        // failed. What may never vary is that only closed prefix bytes are
        // ever emitted.
        assert!("ordinary\r\n".starts_with(&emitted), "emitted {emitted:?}");
        assert!(!emitted.contains("SYNTHETIC_REVOKED_"));
    }
}

/// `IncrementalLimits::new` refuses any `max_buffered_bytes` below
/// `IncrementalLimits::minimum_buffered_bytes(token, multiline)`, which is
/// always strictly greater than both construct limits. That ordering is what
/// makes `SecretScanErrorCode::BufferLimitExceeded` a defense-in-depth
/// backstop rather than a reachable outcome of today's built-in detector set:
/// an open construct's own token or multiline limit always trips first, no
/// matter how the input is partitioned. This proves the backstop's
/// deterministic safety the same way the other declared limits are proved
/// above — by driving every partition of an over-limit input to failure and
/// asserting the same construct-limit code every time, never a silent
/// overrun of `max_buffered_bytes` and never `BufferLimitExceeded` itself.
#[test]
fn a_multiline_limit_failure_fires_before_the_buffered_backstop_however_the_input_is_partitioned() {
    let (token, multiline) = (64, 64);
    let buffered = IncrementalLimits::minimum_buffered_bytes(token, multiline);
    assert!(
        buffered > token.max(multiline),
        "the buffered limit must stay strictly above both construct limits",
    );
    let limits = IncrementalLimits::new(100_000, buffered, token, multiline).unwrap();

    // The retained bytes below (29 + 130 = 159) sit comfortably under the
    // buffered limit (64 + 128 = 192) but well past the multiline limit
    // (64): if the buffered backstop could ever fire first, it would fire
    // here.
    let input = format!("-----BEGIN PRIVATE KEY-----\n{}", "A".repeat(130));
    assert!(input.len() > multiline);
    assert!(input.len() < buffered);

    let mut partitions: Vec<Vec<&str>> = (0..=input.len())
        .filter(|&split| input.is_char_boundary(split))
        .map(|split| vec![&input[..split], &input[split..]])
        .collect();
    partitions.push(
        (0..input.len())
            .map(|index| &input[index..=index])
            .collect(),
    );

    for chunks in partitions {
        let (emitted, code, state) = run_until_failure(limits, &chunks);

        assert_eq!(code, Some(SecretScanErrorCode::MultilineLimitExceeded));
        assert_eq!(state, SessionState::Failed);
        assert!(emitted.is_empty(), "emitted {emitted:?}");
    }
}

#[test]
fn an_aborted_session_never_emits_the_construct_it_was_holding() {
    let value = "SYNTHETIC_REVOKED_ABORTED_VALUE";
    let mut sanitizer = session();

    let emitted = sanitizer.append("ordinary line\n").unwrap();
    let held = sanitizer.append(&format!("api_key={value}")).unwrap();
    sanitizer.abort().unwrap();

    assert_eq!(emitted.text(), "ordinary line\n");
    assert_eq!(held.text(), "");
    assert!(held.findings().is_empty());
    assert_eq!(sanitizer.state(), SessionState::Aborted);
    for rendered in [
        format!("{sanitizer:?}"),
        sanitizer.finalize().unwrap_err().to_string(),
    ] {
        assert!(!rendered.contains(value), "{rendered}");
    }
}
