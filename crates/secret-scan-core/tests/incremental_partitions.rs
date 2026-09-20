//! Partition invariance for the canonical incremental corpus.
//!
//! Every fixture in `conformance/fixtures/incremental-corpus.json` is run
//! through a bounded incremental session at every UTF-8 byte boundary and
//! every applicable host-native (`&str` char) boundary of its input, and the
//! concatenated text, findings, actions, order, IDs, absolute ranges, and
//! placeholder numbering are compared against the whole-input reference.
//!
//! This is the Rust consumer of the canonical contract required by
//! `decision-govern-cross-language-conformance`: fixture values are read
//! from the corpus, never copied into this file. Every fixture input is
//! synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::cell::RefCell;
use std::rc::Rc;

use redact_secret::{
    Action, ByteRange, Candidate, Confidence, DefaultPolicy, DetectedFinding, Detector,
    DetectorContext, DetectorFailure, DetectorRegistry, Finding, IncrementalPolicyContext,
    IncrementalSanitizer, Policy, PolicyContext, PolicyFailure, default_placeholder_formatter,
    redact, scan,
};
use support::{
    CanonicalIncrementalFixture, SessionRun, as_chunks, char_boundary_partitions,
    incremental_corpus, run, single_byte_partition, single_char_partition, utf8_byte_partitions,
    whole_input,
};

/// The whole-input reference for a fixture, cross-checked against the
/// canonical `text` and `expected` the corpus declares.
fn reference(fixture: &CanonicalIncrementalFixture) -> (String, Vec<Finding>) {
    let (text, findings) = whole_input(&fixture.input);
    assert_eq!(text, fixture.text, "{}: redacted text", fixture.id);
    assert_eq!(
        findings.len(),
        fixture.expected.len(),
        "{}: finding count",
        fixture.id,
    );
    for (index, expected) in fixture.expected.iter().enumerate() {
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
        assert!(
            finding.range().is_char_aligned_in(&fixture.input),
            "{label} range splits a code point",
        );
    }
    (text, findings)
}

/// Asserts a session run reproduces the whole-input reference in every
/// dimension the deliverable names.
fn assert_matches_reference(
    label: &str,
    run: &SessionRun,
    expected_text: &str,
    expected_findings: &[Finding],
) {
    let text = run.text();
    let findings = run.findings();
    assert_eq!(text, expected_text, "{label}: concatenated text");
    assert_eq!(
        findings.len(),
        expected_findings.len(),
        "{label}: finding count"
    );
    for (index, expected) in expected_findings.iter().enumerate() {
        let finding = &findings[index];
        // `Finding`'s equality covers id, detector, type, confidence, action,
        // and range together; the field assertions below name the dimension
        // that failed.
        assert_eq!(finding.id(), expected.id(), "{label}: finding {index} id");
        assert_eq!(
            finding.detector(),
            expected.detector(),
            "{label}: finding {index} detector",
        );
        assert_eq!(
            finding.action(),
            expected.action(),
            "{label}: finding {index} action",
        );
        assert_eq!(
            finding.range(),
            expected.range(),
            "{label}: finding {index} absolute range",
        );
        assert_eq!(finding, expected, "{label}: finding {index}");
    }
    // Placeholder numbering is observable only through the redacted text,
    // which the text assertion above already pins, but assert the count of
    // distinct placeholders too so a renumbering that happens to produce the
    // same length still fails.
    assert_eq!(
        placeholder_numbers(&text),
        placeholder_numbers(expected_text),
        "{label}: placeholder numbering",
    );
}

/// The ordered placeholder ordinals in `text`, as emitted by the default
/// `<SECRET_n>` formatter.
fn placeholder_numbers(text: &str) -> Vec<usize> {
    let mut numbers = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<SECRET_") {
        rest = &rest[start + "<SECRET_".len()..];
        let Some(end) = rest.find('>') else { break };
        if let Ok(number) = rest[..end].parse::<usize>() {
            numbers.push(number);
        }
        rest = &rest[end + 1..];
    }
    numbers
}

// ---------------------------------------------------------------------------
// criteria 1 and 2: enumerate every boundary; equal the whole-input reference
// ---------------------------------------------------------------------------

#[test]
fn the_canonical_incremental_corpus_is_loaded_in_full() {
    let corpus = incremental_corpus();
    assert!(
        corpus.len() >= 16,
        "the canonical incremental corpus shrank to {} fixtures",
        corpus.len(),
    );
    for fixture in &corpus {
        assert!(!fixture.id.is_empty());
        assert!(!fixture.input.is_empty());
    }
}

#[test]
fn every_fixture_reproduces_the_canonical_whole_input_reference() {
    for fixture in incremental_corpus() {
        reference(&fixture);
    }
}

#[test]
fn every_host_native_string_boundary_reproduces_the_whole_input_reference() {
    for fixture in incremental_corpus() {
        let (text, findings) = reference(&fixture);
        for (index, chunks) in char_boundary_partitions(&fixture.input).iter().enumerate() {
            let label = format!("{} char boundary #{index}", fixture.id);
            assert_matches_reference(&label, &run(chunks), &text, &findings);
        }
        let per_character = single_char_partition(&fixture.input);
        assert_matches_reference(
            &format!("{} one chunk per character", fixture.id),
            &run(&per_character),
            &text,
            &findings,
        );
    }
}

#[test]
fn every_utf8_byte_boundary_reproduces_the_whole_input_reference() {
    for fixture in incremental_corpus() {
        let (text, findings) = reference(&fixture);
        let partitions = utf8_byte_partitions(&fixture.input);
        assert_eq!(
            partitions.len(),
            fixture.input.len() + 1,
            "{}: every UTF-8 byte boundary must be enumerated",
            fixture.id,
        );
        for (index, pieces) in partitions.iter().enumerate() {
            let label = format!("{} UTF-8 byte boundary #{index}", fixture.id);
            assert_matches_reference(&label, &run(&as_chunks(pieces)), &text, &findings);
        }
        let per_byte = single_byte_partition(&fixture.input);
        assert_matches_reference(
            &format!("{} one chunk per UTF-8 byte", fixture.id),
            &run(&as_chunks(&per_byte)),
            &text,
            &findings,
        );
    }
}

#[test]
fn a_multi_byte_partition_is_enumerated_inside_the_code_point() {
    // The astral fixture is the case where a byte boundary can fall inside a
    // code point at all; assert the enumeration really covers those indices
    // rather than silently skipping to the next char boundary.
    let fixture = incremental_corpus()
        .into_iter()
        .find(|fixture| {
            fixture
                .input
                .chars()
                .any(|character| character.len_utf8() > 1)
        })
        .expect("the corpus must carry a multi-byte fixture");
    let interior: Vec<usize> = (0..=fixture.input.len())
        .filter(|index| !fixture.input.is_char_boundary(*index))
        .collect();
    assert!(
        !interior.is_empty(),
        "{}: expected at least one interior byte index",
        fixture.id,
    );
    assert_eq!(
        char_boundary_partitions(&fixture.input).len() + interior.len(),
        utf8_byte_partitions(&fixture.input).len(),
        "{}: byte enumeration must add exactly the interior indices",
        fixture.id,
    );
}

// ---------------------------------------------------------------------------
// part D (issue #480): redaction integrity for the #467-#475 exclusion
// shapes -- an excluded value's literal text must survive untouched, with
// no stranded partial-value remnant, in both whole-input and every
// incremental partition of these fixtures. #467's original report was
// exactly this failure mode: a value boundary that stopped early left
// ` key: pem })` stranded on the line.
// ---------------------------------------------------------------------------

/// Fixture id, paired with the excluded line(s) whose literal text must
/// survive unredacted end to end. Scoped deliberately to the #467-#475
/// exclusion-shape fixtures rather than the whole corpus: a corpus-wide
/// version of this check would misfire on the deliberate, documented
/// interpolation-fragment residual
/// (`docs/decisions/2026-09-20-exclude-closed-call-code-expressions-as-contextual-values.md`'s
/// "Known residual, out of scope" clause), which strands `}_CONTEXT_VALUE`
/// by design and belongs to #266/#279, not to this issue.
const EXCLUDED_LINE_FIXTURES: &[(&str, &[&str])] = &[
    (
        "contextual-closed-call-code-expressions",
        &[
            "secret = SecretManagerServiceClient.access_secret_version(req)",
            "secret = getSecretOrThrow(SECRET_NAME_CONSTANT)",
            "secret = django.core.signing.get_cookie_signer(salt=SALT)",
            "secret = crypto.createPrivateKey({ key: pem })",
            "api_key = rsa.generate_private_key(public_exponent=65537)",
        ],
    ),
    (
        "bearer-token-filler-and-placeholder-exclusion-boundary",
        &["Authorization: Bearer xxxxxxxxxxxxxxxxxxxx"],
    ),
    (
        "bearer-token-whole-value-placeholder-exclusion-boundary",
        &["Authorization: Bearer PASSWORD_SECRET_EXAMPLE"],
    ),
    (
        "connection-string-interpolation-reference-exclusion-boundary",
        &["postgres://app:$DB_PASSWORD@db.internal:5432/example"],
    ),
    (
        "jwt-legacy-supabase-anon-service-role-discriminating-boundary",
        &[
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN5bnRocHJvaiIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3OTk5OTk5OTl9.SYNTHETIC_REVOKED_SUPABASE_LEGACY_JWT_SIGNATURE",
        ],
    ),
];

#[test]
fn an_excluded_value_survives_unstranded_in_the_whole_input_reference() {
    let corpus = incremental_corpus();
    for (id, excluded_lines) in EXCLUDED_LINE_FIXTURES {
        let fixture = corpus
            .iter()
            .find(|fixture| &fixture.id == id)
            .unwrap_or_else(|| panic!("fixture {id} must exist in the incremental corpus"));
        let (text, _) = reference(fixture);
        for excluded_line in *excluded_lines {
            assert!(
                text.contains(excluded_line),
                "{id}: excluded value {excluded_line:?} must survive unstranded in {text:?}",
            );
        }
    }
}

#[test]
fn an_excluded_value_survives_unstranded_at_every_incremental_partition_boundary() {
    let corpus = incremental_corpus();
    for (id, excluded_lines) in EXCLUDED_LINE_FIXTURES {
        let fixture = corpus
            .iter()
            .find(|fixture| &fixture.id == id)
            .unwrap_or_else(|| panic!("fixture {id} must exist in the incremental corpus"));
        for chunks in char_boundary_partitions(&fixture.input) {
            let run = run(&chunks);
            for excluded_line in *excluded_lines {
                assert!(
                    run.text().contains(excluded_line),
                    "{id}: excluded value {excluded_line:?} must survive unstranded at every partition boundary, got {:?}",
                    run.text(),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// criterion 3: acceptance is unchanged when safe output accumulates in one call
// ---------------------------------------------------------------------------

#[test]
fn acceptance_is_unchanged_when_finalized_safe_output_accumulates_in_one_append() {
    for fixture in incremental_corpus() {
        let (text, findings) = reference(&fixture);

        // The whole input in a single `append`: every unit that closes is
        // finalized and accumulated inside that one call.
        let accumulated = run(&[&fixture.input]);
        assert_matches_reference(
            &format!("{} single append", fixture.id),
            &accumulated,
            &text,
            &findings,
        );

        // The append/finalize split itself is invariant: only the
        // distribution across calls changes, never what is accepted. Compare
        // the maximally fragmented run — where output is released one call at
        // a time — against the accumulating single-append run.
        let per_byte = single_byte_partition(&fixture.input);
        let fragmented = run(&as_chunks(&per_byte));
        assert_eq!(
            fragmented.appended_text, accumulated.appended_text,
            "{}: append-phase safe output",
            fixture.id,
        );
        assert_eq!(
            fragmented.finalized_text, accumulated.finalized_text,
            "{}: finalize-phase safe output",
            fixture.id,
        );
        assert_eq!(
            fragmented.appended_findings, accumulated.appended_findings,
            "{}: append-phase findings",
            fixture.id,
        );
        assert_eq!(
            fragmented.finalized_findings, accumulated.finalized_findings,
            "{}: finalize-phase findings",
            fixture.id,
        );

        // And the accumulation is real: the single-append run releases its
        // safe output in no more calls than the fragmented run needs.
        assert!(
            accumulated.emitting_calls <= fragmented.emitting_calls,
            "{}: a single append must not fragment emission ({} > {})",
            fixture.id,
            accumulated.emitting_calls,
            fragmented.emitting_calls,
        );
        assert!(
            accumulated.emitting_calls <= 2,
            "{}: a single append plus finalize can emit at most twice",
            fixture.id,
        );
    }
}

#[test]
fn no_partition_ever_emits_a_detected_value() {
    for fixture in incremental_corpus() {
        let (_, findings) = reference(&fixture);
        let values: Vec<&str> = findings
            .iter()
            .filter(|finding| finding.action().replaces_text())
            .map(|finding| &fixture.input[finding.range().start()..finding.range().end()])
            .collect();
        if values.is_empty() {
            continue;
        }
        for chunks in char_boundary_partitions(&fixture.input) {
            let mut sanitizer = IncrementalSanitizer::new(support::generous_limits()).unwrap();
            for chunk in chunks {
                let emitted = sanitizer.append(chunk).unwrap();
                for value in &values {
                    assert!(
                        !emitted.text().contains(value),
                        "{}: a provisional append released a detected value",
                        fixture.id,
                    );
                }
            }
            let emitted = sanitizer.finalize().unwrap();
            for value in &values {
                assert!(
                    !emitted.text().contains(value),
                    "{}: finalize released a detected value",
                    fixture.id,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// criterion 5: unsupported extensions stay outside the incremental API
// ---------------------------------------------------------------------------

/// A custom synchronous detector. It is deliberately trivial: the point is
/// that a whole-input registry can carry it and an incremental session
/// cannot.
struct MarkerDetector;

const MARKER: &str = "SYNTHETIC_REVOKED_CUSTOM_MARKER";

impl Detector for MarkerDetector {
    fn id(&self) -> &'static str {
        "custom-marker"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(input
            .match_indices(MARKER)
            .filter_map(|(start, matched)| {
                ByteRange::new(start, start + matched.len())
                    .map(|range| Candidate::new("custom_marker", Confidence::High, range))
            })
            .collect())
    }
}

#[test]
fn a_custom_synchronous_detector_remains_outside_the_incremental_api() {
    let input = format!("marker={MARKER}");

    // A whole-input registry accepts the custom detector and reports it.
    let extended =
        DetectorRegistry::with_built_in([Box::new(MarkerDetector) as Box<dyn Detector>]).unwrap();
    assert!(extended.contains("custom-marker"));
    let extended_findings = scan(&input, &extended, &DefaultPolicy).unwrap();
    assert!(
        extended_findings
            .iter()
            .any(|finding| finding.detector() == "custom-marker"),
        "the whole-input registry must report the custom detector",
    );

    // `IncrementalSanitizer` has no constructor that accepts a registry, so
    // an incremental session always runs the built-in detectors only. Its
    // result equals the built-in-only whole-input reference, never the
    // extended one.
    let (built_in_text, built_in_findings) = whole_input(&input);
    let session = run(&[&input]);
    assert_eq!(session.text(), built_in_text);
    assert_eq!(session.findings(), built_in_findings);
    assert!(
        !session
            .findings()
            .iter()
            .any(|finding| finding.detector() == "custom-marker"),
        "an incremental session must never run a custom detector",
    );

    let extended_text = redact(&input, &extended_findings, &default_placeholder_formatter).unwrap();
    assert_ne!(
        session.text(),
        extended_text,
        "the fixture must actually distinguish the two registries",
    );
}

/// A whole-input policy whose action depends on the total finding count —
/// the class of policy that cannot be evaluated progressively.
struct CountDependentPolicy;

impl Policy for CountDependentPolicy {
    fn evaluate(
        &self,
        _finding: &DetectedFinding,
        context: &PolicyContext,
    ) -> Result<Action, PolicyFailure> {
        Ok(if context.finding_count() > 1 {
            Action::Block
        } else {
            Action::Redact
        })
    }
}

#[test]
fn a_whole_input_count_dependent_policy_has_no_incremental_equivalent() {
    let input = format!(
        "api_key={}\npassword={}",
        "SYNTHETIC_REVOKED_COUNT_FIRST_VALUE", "SYNTHETIC_REVOKED_COUNT_SECOND_VALUE",
    );
    let registry = DetectorRegistry::with_built_in([]).unwrap();

    // Whole-input: the count is known, so every finding blocks.
    let whole = scan(&input, &registry, &CountDependentPolicy).unwrap();
    assert_eq!(whole.len(), 2);
    assert!(
        whole
            .iter()
            .all(|finding| finding.action() == Action::Block)
    );

    // Incremental: `IncrementalPolicyContext` carries only the finalized
    // index, so the closest adaptation cannot see a total and must decide
    // from the index alone. It reaches a different, documented result.
    let observed: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&observed);
    let adapted = move |_finding: &DetectedFinding,
                        context: &IncrementalPolicyContext|
          -> Result<Action, PolicyFailure> {
        sink.borrow_mut().push(context.finding_index());
        // The only count available progressively is "findings so far", which
        // is `finding_index + 1` and is never the whole-input total for any
        // finding but the last.
        Ok(if context.finding_index() + 1 > 1 {
            Action::Block
        } else {
            Action::Redact
        })
    };
    let mut sanitizer = IncrementalSanitizer::with_policy_and_formatter(
        support::generous_limits(),
        Box::new(adapted),
        Box::new(default_placeholder_formatter),
    )
    .unwrap();
    let mut findings = sanitizer.append(&input).unwrap().into_parts().1;
    findings.extend(sanitizer.finalize().unwrap().into_parts().1);

    assert_eq!(*observed.borrow(), vec![0, 1]);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].action(), Action::Redact);
    assert_eq!(findings[1].action(), Action::Block);
    assert_ne!(
        findings.iter().map(Finding::action).collect::<Vec<_>>(),
        whole.iter().map(Finding::action).collect::<Vec<_>>(),
        "a count-dependent policy must not appear to survive the adaptation",
    );
}

#[test]
fn the_incremental_policy_context_exposes_no_total_finding_count() {
    // The contract is structural: the incremental context is exactly the
    // finalized index, whereas the whole-input context also carries the
    // total. A count-dependent policy therefore has nowhere to read a total
    // from inside an incremental session.
    let incremental = IncrementalPolicyContext::new(3);
    assert_eq!(incremental.finding_index(), 3);
    assert_eq!(
        std::mem::size_of::<IncrementalPolicyContext>(),
        std::mem::size_of::<usize>(),
        "IncrementalPolicyContext must carry the index and nothing else",
    );
    assert_eq!(
        std::mem::size_of::<PolicyContext>(),
        2 * std::mem::size_of::<usize>(),
        "PolicyContext must carry the index and the total",
    );
    assert_eq!(PolicyContext::new(3, 7).finding_count(), 7);
}

#[test]
fn the_default_policy_is_count_independent_so_it_partitions_safely() {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let input = format!(
        "api_key={}\npassword={}",
        "SYNTHETIC_REVOKED_DEFAULT_FIRST_VALUE", "SYNTHETIC_REVOKED_DEFAULT_SECOND_VALUE",
    );
    let findings = scan(&input, &registry, &DefaultPolicy).unwrap();
    assert_eq!(findings.len(), 2);
    for (index, finding) in findings.iter().enumerate() {
        let with_total = Policy::evaluate(
            &DefaultPolicy,
            finding.detected(),
            &PolicyContext::new(index, findings.len()),
        )
        .unwrap();
        let without_total = redact_secret::IncrementalPolicy::evaluate(
            &DefaultPolicy,
            finding.detected(),
            &IncrementalPolicyContext::new(index),
        )
        .unwrap();
        assert_eq!(with_total, without_total);
        assert_eq!(with_total, finding.action());
    }
}
