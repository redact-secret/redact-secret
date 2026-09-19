---
decision_id: decision-select-optimal-disjoint-candidates-by-total-evidence-weight
status: accepted
scope: workspace
title: Select optimal disjoint candidates by total evidence weight
decided_at: 2026-09-19
---

# Select optimal disjoint candidates by total evidence weight

## Context

Issue [#451](https://github.com/redact-secret/redact-secret/issues/451) is
sub-issue **B** of [#440](https://github.com/redact-secret/redact-secret/issues/440),
gated on **A** (issue [#450](https://github.com/redact-secret/redact-secret/issues/450),
merged in PR #456), which decided that resolved-action severity is the
dominant overlap-precedence key
(`decision-resolve-overlap-precedence-by-resolved-action-severity`). #451
reuses that objective rather than inventing a new one.

`try_accept` (`crates/secret-scan-core/src/pipeline.rs`) ranked every
candidate by a fixed priority tuple (resolved severity, specificity,
confidence, narrower span, detector registration order, emission order),
sorted descending, and walked the list greedily: accept a candidate if its
range is disjoint from everything already accepted. This is deterministic
but not optimal — whenever an accepted candidate overlaps two or more
candidates that are mutually disjoint from each other, greedy keeps the
single highest-ranked span and discards the pair, even when the pair carries
more total evidence than the single span.

#440's research comment
(https://github.com/redact-secret/redact-secret/issues/440#issuecomment-5741906215)
found that issue #440's own motivating example (a wide contextual span
suppressing two provider tokens inside it) does not reproduce: specificity
already favors the narrower, more specific candidates in that shape, so
greedy already keeps the pair. It also established the review-cost-bounding
technique this decision's measurement uses.

## Measurement (run before writing the algorithm)

Per the research comment's method, `try_accept`'s walk was instrumented
(temporarily, in `pipeline.rs`'s own test module) to record, for every
accepted candidate that blocked one or more overlapping, lower-priority
candidates, whether two or more of the blocked candidates were mutually
disjoint from each other — the exact shape an optimal pass could
outrank a single greedy winner with. Run once over the full canonical
synchronous corpus (`conformance/fixtures/synchronous-corpus.json`, 1233
fixtures across every declared tier):

```
fixtures evaluated: 1233, fixtures with >=2 mutually-disjoint discards: 0, total shape occurrences: 0
```

Zero. No fixture in the corpus exercises this shape today, so replacing
greedy with an optimal pass is correctness hardening with no conformance
expectation churn — confirmed empirically afterward by running the full
corpus (`cargo test --test canonical_corpus` and the whole crate's test
suite) against the implementation below: every existing test passes
unchanged, byte-for-byte.

A best-effort search for a *reachable* real-detector shape (nested
GitHub-token-style pairs inside a JSON-ish context, and other constructions
in the spirit of #440's own attempts) did not find one either, consistent
with #440's research. No conformance fixture demonstrating disagreement is
added for that reason; see "Conformance coverage" below for what stands in
its place.

## Decision

`run_detector_pipeline` selects the disjoint-range subset of ranked
candidates that maximizes total weight, via the classical `O(n log n)`
weighted-interval-scheduling dynamic program (`select_optimal_disjoint_set`
in `pipeline.rs`): sort candidates by range end, and for each one in that
order take `max(skip it, take it + the best total among candidates ending at
or before its start)`, the predecessor found by binary search over the
(already end-sorted) end offsets.

### The weight: reused ranking inputs, not a new signal

`EvidenceWeight` is a six-field, per-candidate contribution, summed
component-wise across a selection and compared lexicographically
(struct-field declaration order controls `#[derive(Ord)]`), covering exactly
`RankedCandidate::priority`'s existing keys in the same dominance order:
resolved severity, specificity, confidence, narrower span, detector
registration order, emission order. Lexicographic order over vectors is
compatible with component-wise addition (`a > b ⟹ a + c > b + c`), the one
property the weighted-interval-scheduling optimality proof needs from a
scalar weight, so that proof carries over unchanged to this vector weight.

**Severity, specificity, and confidence are exponential in rank, not
linear.** A first draft summed the bare rank (0-3 for severity, and so on).
That draft broke an existing pipeline test
(`same_specificity_higher_confidence_wins`): two `Warn`-severity candidates
(rank 1 each, summing to 2) outranked one `Redact`-severity candidate (rank
2), even though `Redact` is the strictly stricter action
(`decision-resolve-overlap-precedence-by-resolved-action-severity`) and,
critically, the two `Warn` candidates were much narrower than the `Redact`
one — selecting them left most of the `Redact` candidate's span with no
finding at all, not merely a weaker one. That is a real regression for a
tool whose value is failing closed, and it is not what "more total evidence"
should mean: two weaker, narrower findings are not more protective than one
stronger, wider one.

The fix: each of these three tiers uses `base.pow(rank)` as the
per-candidate contribution, where `base` is one more than the candidate
count for this call (`select_optimal_disjoint_set`'s `n + 1`, recomputed per
call). With `base > n`, no combination of at most `n` candidates at a lower
rank can sum past one candidate at the next rank up — their sum is at most
`n * base^(rank-1) < base * base^(rank-1) = base^rank`. Each tier therefore
behaves as true dominance, reproducing today's "never displace a stricter
one" rule exactly, while candidates that *tie* on a tier still correctly
out-total a single one there via the lower tiers — the legitimate "more
total evidence" case this issue asks for. `narrowness` and the two order
fields stay linear: there is no dominance to protect there, and more
matched, better-registered evidence covering more of the input is exactly
the improvement wanted.

`same_specificity_higher_confidence_wins` and every other existing Rust and
conformance test passes unchanged against this design (see "Measurement"
above).

### Complexity bound

`O(n log n)` in `n`, the candidate count for one `run_detector_pipeline`
call: one `O(n log n)` sort, `n` `O(log n)` binary-searched predecessor
lookups, one `O(n)` forward dynamic-programming pass, one `O(n)` backward
reconstruction. The same complexity class as the previous sort-plus-
`BTreeMap` walk. `run_detector_pipeline` has no separate, externally imposed
bound on `n` to lean on — `decision-bound-whole-input-operations-by-default`
deliberately keeps it unbounded, applying `WholeInputLimits` only at the
`scan`/`redact`/`scan_and_redact` entry points, specifically so a caller's
explicit, larger limit is never silently overridden inside a primitive whose
whole design point is "no environment-derived or silent defaults." The bound
here is therefore stated in `n` alone, exactly as the previous algorithm's
was.

### Ties and determinism

The sort key candidates are ordered by before the dynamic program runs is
total: `range.end()` first, then the full existing `RankedCandidate::priority`
comparator as a tie-break, whose own final two keys (`detector_order`,
`candidate_order`) are already unique per candidate. So the sorted order —
and therefore every predecessor lookup and every dynamic-programming value —
is fixed regardless of the standard library's unstable-sort implementation.
Where two candidate subsets' total weight ties exactly (not observed
anywhere in the canonical corpus), the recurrence keeps the previously
computed ("exclude") state: a rule fixed by the code, not by iteration order
over an unordered collection, so a rerun and every binding built on this
core reproduce the identical selection.

### Incremental partition equivalence

`IncrementalSanitizer::process_unit` calls the same `run_detector_pipeline`
— including `select_optimal_disjoint_set` — once per closed unit that a
whole-input `scan` calls once over the whole input; there is exactly one
selection algorithm, not two to keep in sync. The pre-existing invariant
that carried greedy's partition equivalence carries this algorithm's too: no
candidate crosses a closed-unit boundary, so a closed unit's optimal
selection is decided entirely from that unit's own candidates, independent
of anything in an earlier or later unit.

One new consideration this algorithm introduces: `EvidenceWeight`'s `base`
is derived from the *local* candidate count `n` of whichever
`run_detector_pipeline` call is running — the whole input's count for
`scan`, one closed unit's count for `process_unit`. These differ whenever an
input is split into more than one unit, so the two paths can compute
different `base` values for what is, from the unit's own perspective, the
same candidate set. This does not change which candidates a unit selects:
`base` only has to exceed the number of candidates actually summed in one
tier of one comparison (the dominance argument above), and for any two valid
choices of `base` exceeding that count, comparing two `base^rank` power sums
reduces to comparing their highest-degree term — a base-independent result
once `base` clears that threshold. Whole-input and per-unit `base` values
both clear it for that unit's own candidates, so they agree on every
comparison. `crates/secret-scan-core/tests/incremental.rs`'s
`a_construct_closes_after_an_earlier_units_overlap_winner_was_already_emitted`
exercises the accompanying incremental-specific shape this issue calls out
— a construct (a multi-chunk PEM block) that only closes after an earlier,
already-closed unit's overlap winner has been resolved and emitted — and
confirms the incremental result still matches the whole-input reference,
byte for byte and finding for finding, at every partition of the later
construct. The full existing incremental-partition test suite (every
canonical incremental fixture, replayed at every UTF-8 byte boundary and
every host-native string boundary) re-verifies this for the algorithm
change generally; all of it passes unchanged.

### Conformance coverage

No corpus fixture demonstrates greedy and optimal disagreeing (see
"Measurement"): the shape is not reachable from the current built-in
detector set. In its place, `pipeline.rs`'s own test module gained direct,
synthetic-candidate unit tests of `select_optimal_disjoint_set` covering
both outcomes deliberately: a single higher-weight candidate winning when no
disjoint combination beats it
(`select_optimal_disjoint_set_prefers_a_higher_weight_single_candidate_when_no_combination_beats_it`),
and two disjoint, same-severity candidates correctly outranking a single
overlapping one that individually outranks each of them
(`select_optimal_disjoint_set_prefers_two_disjoint_candidates_over_one_higher_priority_overlapper`).
These test the algorithm directly rather than through detector text, since
constructing detector text for this exact shape is, per the measurement and
the #440 research, not currently possible.

## Consequences

- `try_accept` and its `BTreeMap`-based walk are removed;
  `select_optimal_disjoint_set` replaces it as `run_detector_pipeline`'s
  only overlap-resolution step.
- No conformance fixture's `expected` array changes. No fixture in the
  canonical corpus exercises the shape this issue fixes.
- `ARCHITECTURE.md`'s overlap-resolution paragraph is updated from "A
  deterministic greedy pass accepts only mutually disjoint ranges" to
  describe optimal weighted-interval selection.
- A future built-in detector emitting a wide candidate whose specificity or
  confidence exceeds two or more narrower, mutually disjoint candidates it
  overlaps, at the *same* resolved severity, will now correctly select the
  narrower pair instead of the wide candidate — the intended effect of this
  change, not yet reachable but no longer foreclosed by the algorithm.
