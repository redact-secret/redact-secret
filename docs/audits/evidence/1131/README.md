# #1131 — Reuse bounded Azure connection-string segment parsing

Product judgement. Final record for
[#1131](https://github.com/redact-secret/redact-secret/issues/1131) (parent #1068,
epic #1065). Adopted: a behavior-preserving internal change to
`azure_storage_candidate` in
`crates/secret-scan-core/src/detectors/connection_string.rs`.

## Change

- `Vec<AzureField>` per anchor is replaced by four borrowed first-occurrence
  slots (`AzureFields`); the first duplicate key still wins, and parsing stops
  once all four are found.
- `detect` keeps one private `Option<AzureSegment>` per call holding only
  offsets (segment start, end, optional account-key range). No input text, no
  `Candidate` clone, no static or global state.
- Per-anchor eligibility is preserved exactly. The cached extent is the true
  terminator-bounded segment. A later anchor reuses it only when it lies inside
  that segment and still satisfies the same per-direction 8,192-byte bound
  (`anchor - start <= 8192` and `end - anchor <= 8192`, equivalent to
  `azure_segment_bounds` returning `Some`). Otherwise the segment is recomputed.
  A failed bounds computation caches nothing, so a later eligible anchor in the
  same text is never skipped.
- The negative parse result of a successfully bounded segment is cached; the
  `Candidate` is rebuilt per anchor with the same signals, specificity,
  confidence and order.

## Differential evidence

The old implementation is kept verbatim as a test-only oracle
(`ref_azure_storage_candidate`, `reference_azure_candidates`). The tests compare
the `Debug` form of the entire Azure `Candidate` vector (span, type, confidence,
signals, order, multiplicity):

- `azure_segment_reuse_matches_the_reference_on_generated_inputs`: 4,000
  deterministic inputs built from valid/invalid/duplicate/missing fields,
  empty and no-`=` pairs, Unicode keys and values, and mixed separators
  (`;`, space, newline, quote).
- `azure_segment_reuse_matches_the_reference_at_the_segment_limit`: filler
  widths 8,000 to 16,385 around the 8,192 per-direction bound, with the anchor
  before, after and between valid segments, an invalid-first / valid-second
  duplicate key, 40 independent lines, 99 repeated anchors, and a mixed line.

The existing production tests still pass unchanged (`cargo test -p
redact-secret --locked`: 2,366 passed, 1 ignored measurement test), including
the canonical corpus, whole/incremental paths and `adversarial_bounds`.

## Timing (exploratory, not a release claim)

Measured on a shared, loaded macOS host (not the Linux Xeon of the research
comment), release profile, alternating AB/BA rounds, min of 15 rounds of 200
calls each, per call of the Azure loop only. Run:
`cargo test --release -p redact-secret --lib azure_segment_reuse_timing_report -- --ignored --nocapture`.

| Workload | reference us | reused us | change |
|---|---|---|---|
| single | 0.472 to 0.982 | 0.431 to 0.913 | about -7% to -10% |
| 100 independent lines | 46.9 to 110.5 | 43.2 to 94.7 | about -8% to -14% |
| duplicate x100 in one segment | 877 to 1,900 | 205 to 465 | about -75% |
| benign (no anchor) | 0.86 to 2.28 | identical to reference (see below) | none |

Absolute values drift with host load between runs; the ratios were consistent
in every run. The research comment's own gain (-96% to -97% on the duplicate
workload) came from a quieter VM; this host leaves a larger residual because
each candidate still allocates its signal vector.

Benign caveat: the first timing runs showed the new function about 0.4 to 0.7 us
slower on the 27 KB benign input although it executes the same single
`find_literal` call. A byte-for-byte copy of the new loop placed in the test
module measured identical to the reference (0.95 vs 0.95 us and 1.12 vs 1.12
us), so that gap is code layout of the one specific function, not work added on
the ordinary path. Whole-`detect()` timing for ordinary inputs could not be
resolved on this loaded host; the benign path performs no additional operation.

## Allocation

Not re-measured here (the allocation meter needs an `unsafe` global allocator,
which core and harness code must not add). The research comment's meter counts
for the prototype (duplicate x100: 946 to 382 allocation calls, 977,508 to
29,988 requested bytes; single: 6 to 5) apply by construction: this change
removes the per-anchor `Vec<AzureField>` and repeated parse the same way.

## Verdict

Adopt. Same-segment repetition gets a large, consistent reduction; single and
independent-line workloads move only slightly. No general connection-detector
speedup is claimed. Observable behavior is unchanged, so no changelog entry.

## Reproducing the timing

The ignored timing test(s) named above were removed before merge: `npm run rust:check` forbids clock and stdout names (`std::time`, `println!`) anywhere in `secret-scan-core/src`, test modules included. The removed code is kept verbatim as `removed-timing-harness.patch.txt` (a reverse patch: apply it to a checkout of the merged commit with `git apply -R` to restore the harness locally, then run the `cargo test --release ... --ignored --nocapture` command quoted above). Do not commit it back into `src/`.
