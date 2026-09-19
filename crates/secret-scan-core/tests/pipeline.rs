//! Focused pipeline tests: validation, tie breakers, large finding sets,
//! Unicode byte boundaries, determinism, and sanitized failures.
//!
//! Every input is synthetic; no test embeds a credential-shaped value.

// Integration tests are outside `#[cfg(test)]`, so the test-only relaxation in
// `clippy.toml` does not apply; these helpers may unwrap and panic on purpose.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unnecessary_literal_bound
)]

use redact_secret::{
    Action, ByteRange, Candidate, Confidence, DetectedFinding, Detector, DetectorContext,
    DetectorFailure, DetectorRegistry, Finding, Policy, PolicyContext, PolicyFailure,
    SecretScanError, SecretScanErrorCode, Specificity, run_detector_pipeline, scan,
};

/// A detector that emits a fixed candidate list regardless of input.
struct Fixed {
    id: &'static str,
    candidates: Vec<Candidate>,
}

impl Detector for Fixed {
    fn id(&self) -> &str {
        self.id
    }

    fn detect(&self, _: &str, _: &DetectorContext) -> Result<Vec<Candidate>, DetectorFailure> {
        Ok(self.candidates.clone())
    }
}

struct Failing;

impl Detector for Failing {
    fn id(&self) -> &str {
        "failing"
    }

    fn detect(&self, _: &str, _: &DetectorContext) -> Result<Vec<Candidate>, DetectorFailure> {
        Err(DetectorFailure)
    }
}

/// Records the context it was called with so the test can assert on it.
struct ContextProbe {
    seen: std::cell::RefCell<Vec<usize>>,
}

impl Detector for ContextProbe {
    fn id(&self) -> &str {
        "probe"
    }

    fn detect(
        &self,
        input: &str,
        context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        assert_eq!(context.input_len(), input.len());
        self.seen.borrow_mut().push(context.input_len());
        Ok(Vec::new())
    }
}

fn range(start: usize, end: usize) -> ByteRange {
    ByteRange::new(start, end).unwrap()
}

fn candidate(
    type_name: &str,
    confidence: Confidence,
    specificity: Specificity,
    start: usize,
    end: usize,
) -> Candidate {
    Candidate::new(type_name, confidence, range(start, end)).with_specificity(specificity)
}

fn registry(detectors: Vec<Box<dyn Detector>>) -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();
    for detector in detectors {
        registry.register(detector).unwrap();
    }
    registry
}

fn single(id: &'static str, candidates: Vec<Candidate>) -> DetectorRegistry {
    registry(vec![Box::new(Fixed { id, candidates })])
}

fn summary(findings: &[DetectedFinding]) -> Vec<(&str, &str, &str, usize, usize)> {
    findings
        .iter()
        .map(|f| {
            (
                f.id(),
                f.type_name(),
                f.detector(),
                f.range().start(),
                f.range().end(),
            )
        })
        .collect()
}

fn warn_policy() -> impl Policy {
    |_: &DetectedFinding, _: &PolicyContext| Ok(Action::Warn)
}

const INPUT: &str = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz";

/// A finding type whose default action is `Redact` at every confidence
/// (it is in the crate's internal `ALWAYS_REDACT_TYPES`). Overlap resolution
/// ranks by resolved-action severity before specificity, confidence, or span
/// (`decision-resolve-overlap-precedence-by-resolved-action-severity`), so a
/// test isolating one of those later keys gives both compared candidates
/// this type name to pin their severity equal and keep severity out of the
/// comparison.
const ALWAYS_REDACT_TYPE_NAME: &str = "jwt";

// --- validation ------------------------------------------------------------

#[test]
fn empty_input_runs_no_detector() {
    let registry = registry(vec![Box::new(Failing)]);
    assert_eq!(run_detector_pipeline("", &registry).unwrap(), Vec::new());
}

#[test]
fn detector_receives_byte_length_context() {
    let probe = ContextProbe {
        seen: std::cell::RefCell::new(Vec::new()),
    };
    let mut registry = DetectorRegistry::new();
    registry.register(Box::new(probe)).unwrap();
    run_detector_pipeline("a😀b", &registry).unwrap();
    // "a😀b" is 6 bytes. The probe asserted the context; nothing else to see.
    let _ = registry;
}

#[test]
fn rejects_candidate_range_past_end_of_input() {
    let registry = single(
        "d",
        vec![candidate(
            "t",
            Confidence::High,
            Specificity::Provider,
            0,
            INPUT.len() + 1,
        )],
    );
    let error = run_detector_pipeline(INPUT, &registry).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::InvalidCandidate);
}

#[test]
fn accepts_candidate_ending_exactly_at_end_of_input() {
    let registry = single(
        "d",
        vec![candidate(
            "t",
            Confidence::High,
            Specificity::Provider,
            70,
            INPUT.len(),
        )],
    );
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(summary(&findings), [("finding-1", "t", "d", 70, 72)]);
}

#[test]
fn rejects_malformed_candidate_types() {
    for type_name in [
        "", "Token", "1token", "token-", "to--ken", "tok en", "tökén",
    ] {
        let registry = single(
            "d",
            vec![candidate(
                type_name,
                Confidence::High,
                Specificity::Provider,
                0,
                4,
            )],
        );
        let error = run_detector_pipeline(INPUT, &registry).unwrap_err();
        assert_eq!(
            error.code(),
            SecretScanErrorCode::InvalidCandidate,
            "{type_name:?}"
        );
    }
    let long = "a".repeat(65);
    let registry = single(
        "d",
        vec![candidate(
            &long,
            Confidence::High,
            Specificity::Provider,
            0,
            4,
        )],
    );
    assert_eq!(
        run_detector_pipeline(INPUT, &registry).unwrap_err().code(),
        SecretScanErrorCode::InvalidCandidate
    );
}

#[test]
fn rejects_candidate_whose_text_equals_its_type_or_detector_id() {
    let input = "prefix token suffix mydet end";
    // "token" occupies bytes 7..12 and equals the candidate type.
    let registry = single(
        "mydet",
        vec![candidate(
            "token",
            Confidence::High,
            Specificity::Provider,
            7,
            12,
        )],
    );
    assert_eq!(
        run_detector_pipeline(input, &registry).unwrap_err().code(),
        SecretScanErrorCode::InvalidCandidate
    );
    // "mydet" occupies bytes 20..25 and equals the detector id.
    let registry = single(
        "mydet",
        vec![candidate(
            "token",
            Confidence::High,
            Specificity::Provider,
            20,
            25,
        )],
    );
    assert_eq!(
        run_detector_pipeline(input, &registry).unwrap_err().code(),
        SecretScanErrorCode::InvalidCandidate
    );
    // A superset span is fine.
    let registry = single(
        "mydet",
        vec![candidate(
            "token",
            Confidence::High,
            Specificity::Provider,
            7,
            13,
        )],
    );
    assert_eq!(run_detector_pipeline(input, &registry).unwrap().len(), 1);
}

#[test]
fn first_invalid_candidate_fails_the_whole_scan() {
    let registry = registry(vec![
        Box::new(Fixed {
            id: "good",
            candidates: vec![candidate(
                "t",
                Confidence::High,
                Specificity::Provider,
                0,
                4,
            )],
        }),
        Box::new(Fixed {
            id: "bad",
            candidates: vec![candidate(
                "t",
                Confidence::High,
                Specificity::Provider,
                0,
                1000,
            )],
        }),
    ]);
    assert_eq!(
        run_detector_pipeline(INPUT, &registry).unwrap_err().code(),
        SecretScanErrorCode::InvalidCandidate
    );
}

// --- Unicode byte boundaries ----------------------------------------------

#[test]
fn rejects_ranges_inside_a_multibyte_character() {
    // 'a' (1) + '😀' (4) + 'é' (2) + 'b' (1) = 8 bytes.
    let input = "a😀éb";
    assert_eq!(input.len(), 8);
    for (start, end) in [(0, 2), (2, 5), (1, 4), (5, 6), (6, 8), (0, 3), (4, 7)] {
        let registry = single(
            "d",
            vec![candidate(
                "t",
                Confidence::High,
                Specificity::Provider,
                start,
                end,
            )],
        );
        let error = run_detector_pipeline(input, &registry).unwrap_err();
        assert_eq!(
            error.code(),
            SecretScanErrorCode::InvalidCandidate,
            "{start}..{end}"
        );
    }
}

#[test]
fn accepts_ranges_on_character_boundaries_and_reports_bytes() {
    let input = "a😀éb";
    for (start, end) in [(0, 1), (1, 5), (5, 7), (7, 8), (0, 8), (1, 7)] {
        let registry = single(
            "d",
            vec![candidate(
                "t",
                Confidence::High,
                Specificity::Provider,
                start,
                end,
            )],
        );
        let findings = run_detector_pipeline(input, &registry).unwrap();
        assert_eq!(summary(&findings), [("finding-1", "t", "d", start, end)]);
    }
}

#[test]
fn astral_characters_before_inside_and_after_a_finding_keep_byte_offsets() {
    let input = "😀😀x😀y😀😀";
    // x is at byte 8, the inner emoji 9..13, y at 13; span x..y inclusive.
    let registry = single(
        "d",
        vec![candidate(
            "t",
            Confidence::High,
            Specificity::Provider,
            8,
            14,
        )],
    );
    let findings = run_detector_pipeline(input, &registry).unwrap();
    assert_eq!(&input[8..14], "x😀y");
    assert_eq!(summary(&findings), [("finding-1", "t", "d", 8, 14)]);
}

// --- overlap precedence and tie breakers -----------------------------------

/// Issue #450: a candidate that would resolve to a weaker action must not
/// displace an overlapping candidate that would resolve to a stricter one,
/// even when the weaker candidate has higher specificity. Neither type name
/// is in `ALWAYS_REDACT_TYPES`, so each resolves by confidence alone
/// (`decision-resolve-overlap-precedence-by-resolved-action-severity`): the
/// medium-confidence provider candidate would only warn, and the
/// high-confidence contextual candidate would redact, so the redacting one
/// must win despite its lower specificity.
#[test]
fn resolved_action_severity_outranks_specificity() {
    let registry = registry(vec![
        Box::new(Fixed {
            id: "weak-provider",
            candidates: vec![candidate(
                "unlisted_provider_type",
                Confidence::Medium,
                Specificity::Provider,
                0,
                10,
            )],
        }),
        Box::new(Fixed {
            id: "strong-contextual",
            candidates: vec![candidate(
                "unlisted_contextual_type",
                Confidence::High,
                Specificity::Contextual,
                0,
                10,
            )],
        }),
    ]);
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [(
            "finding-1",
            "unlisted_contextual_type",
            "strong-contextual",
            0,
            10
        )]
    );
}

/// The same shape as [`resolved_action_severity_outranks_specificity`], but
/// via `private_key`'s unconditional `Block` rather than a confidence-driven
/// `Redact`: `Block` outranks every other action, so even a `PrivateKey`-
/// specificity candidate loses to it once resolved severity is the first
/// key.
#[test]
fn a_blocking_candidate_outranks_a_higher_specificity_non_blocking_one() {
    let registry = registry(vec![
        Box::new(Fixed {
            id: "weak-private-key-shaped",
            candidates: vec![candidate(
                "unlisted_type",
                Confidence::High,
                Specificity::PrivateKey,
                0,
                10,
            )],
        }),
        Box::new(Fixed {
            id: "blocking",
            candidates: vec![candidate(
                "private_key",
                Confidence::Low,
                Specificity::Entropy,
                0,
                10,
            )],
        }),
    ]);
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [("finding-1", "private_key", "blocking", 0, 10)]
    );
}

#[test]
fn higher_specificity_wins_over_confidence_and_span() {
    // Both candidates share `ALWAYS_REDACT_TYPE_NAME` so they resolve equal
    // severity; only specificity, confidence, and span differ.
    let registry = registry(vec![
        Box::new(Fixed {
            id: "entropy",
            candidates: vec![candidate(
                ALWAYS_REDACT_TYPE_NAME,
                Confidence::High,
                Specificity::Entropy,
                0,
                4,
            )],
        }),
        Box::new(Fixed {
            id: "provider",
            candidates: vec![candidate(
                ALWAYS_REDACT_TYPE_NAME,
                Confidence::Low,
                Specificity::Provider,
                0,
                20,
            )],
        }),
    ]);
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [("finding-1", ALWAYS_REDACT_TYPE_NAME, "provider", 0, 20)]
    );
}

#[test]
fn specificity_ladder_is_private_key_provider_structural_contextual_entropy() {
    let ladder = [
        Specificity::PrivateKey,
        Specificity::Provider,
        Specificity::Structural,
        Specificity::Contextual,
        Specificity::Entropy,
    ];
    for pair in ladder.windows(2) {
        let (weaker, stronger) = (pair[1], pair[0]);
        // Weaker registered first, higher confidence, narrower span: still
        // loses. Both share `ALWAYS_REDACT_TYPE_NAME` so severity ties and
        // specificity alone decides.
        let registry = registry(vec![
            Box::new(Fixed {
                id: "first",
                candidates: vec![candidate(
                    ALWAYS_REDACT_TYPE_NAME,
                    Confidence::High,
                    weaker,
                    2,
                    6,
                )],
            }),
            Box::new(Fixed {
                id: "second",
                candidates: vec![candidate(
                    ALWAYS_REDACT_TYPE_NAME,
                    Confidence::Low,
                    stronger,
                    0,
                    10,
                )],
            }),
        ]);
        let findings = run_detector_pipeline(INPUT, &registry).unwrap();
        assert_eq!(
            summary(&findings),
            [("finding-1", ALWAYS_REDACT_TYPE_NAME, "second", 0, 10)]
        );
    }
}

#[test]
fn omitted_specificity_ranks_as_entropy() {
    // "custom" and "ctx" overlap and both use `ALWAYS_REDACT_TYPE_NAME` so
    // they resolve equal severity, isolating the specificity comparison
    // (omitted defaults to `Entropy`, weaker than `Contextual`). "custom2"
    // is disjoint and keeps an arbitrary type name.
    let registry = registry(vec![
        Box::new(Fixed {
            id: "unclassified",
            candidates: vec![Candidate::new(
                ALWAYS_REDACT_TYPE_NAME,
                Confidence::High,
                range(0, 5),
            )],
        }),
        Box::new(Fixed {
            id: "contextual",
            candidates: vec![candidate(
                ALWAYS_REDACT_TYPE_NAME,
                Confidence::Low,
                Specificity::Contextual,
                0,
                30,
            )],
        }),
        Box::new(Fixed {
            id: "other-unclassified",
            candidates: vec![Candidate::new("custom2", Confidence::High, range(40, 45))],
        }),
    ]);
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [
            ("finding-1", ALWAYS_REDACT_TYPE_NAME, "contextual", 0, 30),
            ("finding-2", "custom2", "other-unclassified", 40, 45),
        ]
    );
}

#[test]
fn same_specificity_higher_confidence_wins() {
    let registry = registry(vec![
        Box::new(Fixed {
            id: "a",
            candidates: vec![candidate(
                "medium",
                Confidence::Medium,
                Specificity::Provider,
                0,
                4,
            )],
        }),
        Box::new(Fixed {
            id: "b",
            candidates: vec![candidate(
                "high",
                Confidence::High,
                Specificity::Provider,
                2,
                40,
            )],
        }),
        Box::new(Fixed {
            id: "c",
            candidates: vec![candidate(
                "low",
                Confidence::Low,
                Specificity::Provider,
                39,
                41,
            )],
        }),
    ]);
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(summary(&findings), [("finding-1", "high", "b", 2, 40)]);
}

#[test]
fn same_specificity_and_confidence_narrower_span_wins() {
    let registry = registry(vec![
        Box::new(Fixed {
            id: "wide",
            candidates: vec![candidate(
                "wide",
                Confidence::High,
                Specificity::Structural,
                0,
                30,
            )],
        }),
        Box::new(Fixed {
            id: "narrow",
            candidates: vec![candidate(
                "narrow",
                Confidence::High,
                Specificity::Structural,
                10,
                12,
            )],
        }),
    ]);
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [("finding-1", "narrow", "narrow", 10, 12)]
    );
}

#[test]
fn equal_keys_fall_back_to_registration_order() {
    let make = |id: &'static str, type_name: &'static str| {
        Box::new(Fixed {
            id,
            candidates: vec![candidate(
                type_name,
                Confidence::High,
                Specificity::Structural,
                5,
                15,
            )],
        }) as Box<dyn Detector>
    };
    let findings = run_detector_pipeline(
        INPUT,
        &registry(vec![make("zeta", "z"), make("alpha", "a")]),
    )
    .unwrap();
    assert_eq!(summary(&findings), [("finding-1", "z", "zeta", 5, 15)]);
    let findings = run_detector_pipeline(
        INPUT,
        &registry(vec![make("alpha", "a"), make("zeta", "z")]),
    )
    .unwrap();
    assert_eq!(summary(&findings), [("finding-1", "a", "alpha", 5, 15)]);
}

#[test]
fn equal_keys_within_one_detector_fall_back_to_emission_order() {
    let registry = single(
        "d",
        vec![
            candidate(
                "second-emitted-later",
                Confidence::High,
                Specificity::Structural,
                20,
                30,
            ),
            candidate(
                "first-emitted-earlier",
                Confidence::High,
                Specificity::Structural,
                25,
                35,
            ),
        ],
    );
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [("finding-1", "second-emitted-later", "d", 20, 30)]
    );
}

#[test]
fn identical_candidates_from_two_detectors_keep_the_first_registered() {
    let registry = registry(vec![
        Box::new(Fixed {
            id: "one",
            candidates: vec![candidate(
                "same",
                Confidence::High,
                Specificity::Provider,
                3,
                9,
            )],
        }),
        Box::new(Fixed {
            id: "two",
            candidates: vec![candidate(
                "same",
                Confidence::High,
                Specificity::Provider,
                3,
                9,
            )],
        }),
    ]);
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(summary(&findings), [("finding-1", "same", "one", 3, 9)]);
}

#[test]
fn a_loser_does_not_block_a_later_disjoint_candidate() {
    // Wide low-priority span loses to a narrow high-priority one; the space
    // it would have covered remains available to a third candidate.
    let registry = registry(vec![
        Box::new(Fixed {
            id: "wide",
            candidates: vec![candidate(
                "wide",
                Confidence::Low,
                Specificity::Entropy,
                0,
                40,
            )],
        }),
        Box::new(Fixed {
            id: "narrow",
            candidates: vec![candidate(
                "narrow",
                Confidence::High,
                Specificity::Provider,
                10,
                20,
            )],
        }),
        Box::new(Fixed {
            id: "tail",
            candidates: vec![candidate(
                "tail",
                Confidence::Medium,
                Specificity::Contextual,
                30,
                36,
            )],
        }),
    ]);
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [
            ("finding-1", "narrow", "narrow", 10, 20),
            ("finding-2", "tail", "tail", 30, 36)
        ]
    );
}

#[test]
fn adjacent_spans_do_not_overlap() {
    let registry = single(
        "d",
        vec![
            candidate("b", Confidence::High, Specificity::Provider, 10, 20),
            candidate("a", Confidence::High, Specificity::Provider, 0, 10),
            candidate("c", Confidence::High, Specificity::Provider, 20, 21),
        ],
    );
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [
            ("finding-1", "a", "d", 0, 10),
            ("finding-2", "b", "d", 10, 20),
            ("finding-3", "c", "d", 20, 21),
        ]
    );
}

// --- determinism and large sets -------------------------------------------

#[test]
fn findings_are_ordered_by_offset_and_numbered_from_one() {
    let registry = single(
        "d",
        vec![
            candidate("third", Confidence::Low, Specificity::Entropy, 50, 55),
            candidate("first", Confidence::High, Specificity::Provider, 0, 5),
            candidate(
                "second",
                Confidence::Medium,
                Specificity::Contextual,
                20,
                25,
            ),
        ],
    );
    let findings = run_detector_pipeline(INPUT, &registry).unwrap();
    assert_eq!(
        summary(&findings),
        [
            ("finding-1", "first", "d", 0, 5),
            ("finding-2", "second", "d", 20, 25),
            ("finding-3", "third", "d", 50, 55),
        ]
    );
    assert_eq!(findings[0].confidence(), Confidence::High);
    assert_eq!(findings[2].confidence(), Confidence::Low);
}

#[test]
fn identical_input_and_configuration_are_reproducible() {
    let build = || {
        registry(vec![
            Box::new(Fixed {
                id: "p",
                candidates: vec![
                    candidate("x", Confidence::High, Specificity::Provider, 0, 8),
                    candidate("y", Confidence::Low, Specificity::Provider, 4, 12),
                ],
            }),
            Box::new(Fixed {
                id: "q",
                candidates: vec![candidate(
                    "z",
                    Confidence::Medium,
                    Specificity::Contextual,
                    30,
                    40,
                )],
            }),
        ])
    };
    let first = run_detector_pipeline(INPUT, &build()).unwrap();
    for _ in 0..10 {
        assert_eq!(run_detector_pipeline(INPUT, &build()).unwrap(), first);
    }
}

#[test]
fn large_finding_set_resolves_and_numbers_deterministically() {
    // 20_000 non-overlapping 3-byte candidates emitted in reverse, each
    // shadowed by a lower-priority overlapping 5-byte candidate and by an
    // exact duplicate from a later detector. Every winner must be the
    // first-registered narrow candidate, ordered by offset.
    let count = 20_000usize;
    let input = "x".repeat(count * 5);
    let mut narrow = Vec::with_capacity(count);
    let mut wide = Vec::with_capacity(count);
    for index in (0..count).rev() {
        let base = index * 5;
        narrow.push(candidate(
            "narrow",
            Confidence::High,
            Specificity::Provider,
            base,
            base + 3,
        ));
        wide.push(candidate(
            "wide",
            Confidence::High,
            Specificity::Provider,
            base,
            base + 5,
        ));
    }
    let registry = registry(vec![
        Box::new(Fixed {
            id: "narrow",
            candidates: narrow.clone(),
        }),
        Box::new(Fixed {
            id: "duplicate",
            candidates: narrow,
        }),
        Box::new(Fixed {
            id: "wide",
            candidates: wide,
        }),
    ]);
    let findings = run_detector_pipeline(&input, &registry).unwrap();
    assert_eq!(findings.len(), count);
    for (index, finding) in findings.iter().enumerate() {
        assert_eq!(finding.id(), format!("finding-{}", index + 1));
        assert_eq!(finding.detector(), "narrow");
        assert_eq!(finding.type_name(), "narrow");
        assert_eq!(finding.range().start(), index * 5);
        assert_eq!(finding.range().end(), index * 5 + 3);
    }
    let again = run_detector_pipeline(&input, &registry).unwrap();
    assert_eq!(again, findings);
}

#[test]
fn overlap_resolution_stays_within_a_time_budget_at_a_large_candidate_count() {
    // `select_optimal_disjoint_set` (`crates/secret-scan-core/src/pipeline.rs`)
    // is documented as `O(n log n)` in the pipeline's own candidate count,
    // which `run_detector_pipeline` never externally bounds —
    // `decision-bound-whole-input-operations-by-default` deliberately leaves
    // `n` itself unbounded, applying `WholeInputLimits` only at the
    // `scan`/`redact`/`scan_and_redact` entry points. This is the
    // adversarial case for that bound: a candidate count no fixture or unit
    // test above reaches, built so every candidate overlaps several
    // neighbors and every predecessor lookup does real binary-search work,
    // run once through the whole pipeline and timed. A regression to a
    // quadratic (or worse) selection strategy blows this budget by orders
    // of magnitude; `O(n log n)` does not.
    //
    // `select_optimal_disjoint_set` is private, and `std::time` is forbidden
    // inside the core crate's `src/` boundary (`check-rust-workspace.py`'s
    // `FORBIDDEN_SOURCE` — the core performs no runtime I/O, clock reads
    // included), so this measures the whole pipeline through the public
    // `run_detector_pipeline` entry point from this integration test crate
    // instead of the selection function alone. Candidate collection and
    // validation add their own (linear) cost on top of selection's, but at
    // this candidate count selection dominates.
    //
    // Debug builds (`cargo test`'s default) run this several times slower
    // than an optimized build, and hosted CI runners add further variance
    // under load; `adversarial_bounds.rs`'s runtime-cap tests document the
    // same tradeoff for the whole-pipeline case there, at a 250ms release
    // cap needing up to a 16x debug allowance to absorb loaded-runner
    // variance. Measured locally (unloaded), this test takes ~6ms in a
    // release build and ~57ms in an unoptimized build; the budgets below
    // give both over an order of magnitude of headroom, enough to absorb
    // hosted-runner variance while still catching an asymptotic regression,
    // which would miss it by more than an order of magnitude, not a small
    // multiple.
    const COUNT: usize = 60_000;
    const DEBUG_RUNTIME_BUDGET_MS: u128 = 2_000;
    const RELEASE_RUNTIME_BUDGET_MS: u128 = 200;

    // Width 5, stride 1: each candidate overlaps its several neighbors, so
    // the end-sorted order interleaves heavily and predecessor searches do
    // not degenerate into "always the immediately preceding index".
    let input = "x".repeat(COUNT + 5);
    let mut candidates = Vec::with_capacity(COUNT);
    for index in 0..COUNT {
        candidates.push(candidate(
            "wide",
            Confidence::High,
            Specificity::Provider,
            index,
            index + 5,
        ));
    }
    let registry = single("wide", candidates);

    let started_at = std::time::Instant::now();
    let findings = run_detector_pipeline(&input, &registry).unwrap();
    let elapsed = started_at.elapsed().as_millis();
    let budget = if cfg!(debug_assertions) {
        DEBUG_RUNTIME_BUDGET_MS
    } else {
        RELEASE_RUNTIME_BUDGET_MS
    };
    assert!(
        elapsed <= budget,
        "run_detector_pipeline took {elapsed}ms for {COUNT} overlapping candidates, above the {budget}ms budget",
    );

    // Pairwise disjoint, the defining property regardless of candidate
    // count.
    assert!(!findings.is_empty());
    for pair in findings.windows(2) {
        assert!(
            pair[0].range().end() <= pair[1].range().start(),
            "finding {} and {} overlap",
            pair[0].id(),
            pair[1].id(),
        );
    }
}

#[test]
fn many_nested_candidates_leave_exactly_one_winner() {
    // Every span nests inside the previous one; ties are broken by narrower
    // span, so the innermost candidate wins whatever emission order says.
    let count = 5_000usize;
    let input = "y".repeat(count * 2 + 2);
    let candidates: Vec<Candidate> = (0..count)
        .map(|index| {
            candidate(
                "nested",
                Confidence::High,
                Specificity::Structural,
                index,
                input.len() - index,
            )
        })
        .collect();
    let findings = run_detector_pipeline(&input, &single("d", candidates)).unwrap();
    assert_eq!(
        summary(&findings),
        [(
            "finding-1",
            "nested",
            "d",
            count - 1,
            input.len() - count + 1
        )]
    );
}

// --- policy ----------------------------------------------------------------

#[test]
fn scan_evaluates_policy_with_index_and_count() {
    let registry = single(
        "d",
        vec![
            candidate("a", Confidence::High, Specificity::Provider, 0, 4),
            candidate("b", Confidence::Low, Specificity::Entropy, 10, 14),
            candidate("c", Confidence::Medium, Specificity::Contextual, 20, 24),
        ],
    );
    let policy = |finding: &DetectedFinding, context: &PolicyContext| {
        assert_eq!(context.finding_count(), 3);
        assert_eq!(
            finding.id(),
            format!("finding-{}", context.finding_index() + 1)
        );
        Ok(match (context.finding_index(), finding.confidence()) {
            (0, _) => Action::Block,
            (_, Confidence::Low) => Action::Allow,
            _ => Action::Redact,
        })
    };
    let findings = scan(INPUT, &registry, &policy).unwrap();
    let actions: Vec<Action> = findings.iter().map(Finding::action).collect();
    assert_eq!(actions, [Action::Block, Action::Allow, Action::Redact]);
    assert_eq!(findings[2].id(), "finding-3");
    assert_eq!(findings[2].detected().type_name(), "c");
}

#[test]
fn scan_with_no_findings_never_calls_policy() {
    let policy = |_: &DetectedFinding, _: &PolicyContext| -> Result<Action, PolicyFailure> {
        panic!("policy must not run without findings")
    };
    let registry = single("d", Vec::new());
    assert!(scan(INPUT, &registry, &policy).unwrap().is_empty());
    assert!(scan("", &registry, &policy).unwrap().is_empty());
}

// --- sanitized failures ----------------------------------------------------

#[test]
fn detector_failure_is_reported_with_a_fixed_code_and_no_payload() {
    let registry = registry(vec![Box::new(Failing)]);
    let error = run_detector_pipeline("synthetic-input-must-not-appear", &registry).unwrap_err();
    assert_eq!(
        error,
        SecretScanError::new(SecretScanErrorCode::DetectorFailure)
    );
    assert_eq!(error.to_string(), "A secret detector failed.");
    assert_eq!(error.code().as_str(), "DETECTOR_FAILURE");
    assert!(!format!("{error:?}").contains("synthetic"));
}

#[test]
fn policy_failure_is_reported_with_a_fixed_code_and_no_payload() {
    let registry = single(
        "d",
        vec![candidate(
            "t",
            Confidence::High,
            Specificity::Provider,
            0,
            4,
        )],
    );
    let policy = |_: &DetectedFinding, _: &PolicyContext| Err(PolicyFailure);
    let error = scan(INPUT, &registry, &policy).unwrap_err();
    assert_eq!(error.code(), SecretScanErrorCode::PolicyFailure);
    assert_eq!(error.to_string(), "The secret policy failed.");
    assert!(!format!("{error:?}").contains(INPUT));
}

#[test]
fn invalid_candidate_errors_never_echo_input_or_candidate_fields() {
    let secret_looking = "zz-synthetic-value-9f8e7d6c";
    let input = format!("token={secret_looking}");
    let registry = single(
        "leaky-detector",
        vec![candidate(
            "Leaky Type",
            Confidence::High,
            Specificity::Provider,
            6,
            input.len(),
        )],
    );
    let error = run_detector_pipeline(&input, &registry).unwrap_err();
    let rendered = format!("{error} {error:?} {}", error.code());
    assert!(!rendered.contains(secret_looking));
    assert!(!rendered.contains("Leaky"));
    assert!(!rendered.contains("leaky-detector"));
    assert_eq!(
        rendered,
        "A secret detector returned an invalid candidate. SecretScanError { code: InvalidCandidate } INVALID_CANDIDATE"
    );
}

#[test]
fn public_findings_carry_metadata_only() {
    let secret_looking = "zz-synthetic-value-9f8e7d6c";
    let input = format!("token={secret_looking}");
    let registry = single(
        "d",
        vec![candidate(
            "t",
            Confidence::High,
            Specificity::Provider,
            6,
            input.len(),
        )],
    );
    let findings = scan(&input, &registry, &warn_policy()).unwrap();
    let rendered = format!("{findings:?}");
    assert!(!rendered.contains(secret_looking));
    assert_eq!(findings[0].range(), range(6, input.len()));
}

#[test]
fn error_implements_std_error_without_source() {
    let error: Box<dyn std::error::Error> =
        Box::new(SecretScanError::new(SecretScanErrorCode::InvalidInput));
    assert!(error.source().is_none());
    assert_eq!(error.to_string(), "Secret scan input must be a string.");
}
