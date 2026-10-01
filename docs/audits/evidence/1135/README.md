# #1135 - sparse-overlap DP partitioning without per-cluster allocation

Product judgement. Final record for
[#1135](https://github.com/redact-secret/redact-secret/issues/1135) (parent
#1068, epic #1065). Verdict: **adopted** as a gated, allocation-free
component split, behavior-preserving; the issue's unconditional per-component
prototype stays rejected. Baseline: the #1134 commit on this branch. All inputs
are synthetic; no value is printed.

## Finding

Beyond the disjoint fast path (#1094), a single overlap sent every candidate
through the global weighted-interval DP, which builds an `EvidenceWeight`
(six `u128` fields, 96 bytes, several `saturating_pow`) for each. The issue's
prototype split the end-sorted candidates into independent components but
cloned the ranked vector and allocated a table set per component: -86% to -89%
on sparse overlap, but +17% to +22% on dense overlap and 15,003 allocations on
pairs.

## Change (`crates/secret-scan-core/src/pipeline.rs`)

- After the unchanged sort and disjoint fast path, **one backward pass** fills
  `ends` (which the unsplit DP built anyway) and finds closing points from the
  running minimum start of the later candidates. A prefix `..=i` of the
  end-sorted set is closed when `ranked[i]` ends at or before every later start;
  every earlier candidate ends no later than `ranked[i]`, so nothing in the
  prefix conflicts with anything after it.
- Each component is solved the moment it closes (in reverse order, which is
  immaterial because components do not interact) by `DpWorkspace::solve`: a
  one-candidate component is selected without any table; otherwise the
  **unchanged recurrence** runs over the component's slice with tables held in
  a per-call `DpWorkspace` and reused, so there is no per-component `Vec`.
- The weight `base` stays the **whole set's** `n + 1`. Equal-weight ties keep
  the previously computed (excluding) state because the comparison is the same
  `with_candidate > without_candidate`, and adding the constant that earlier
  components contribute to both sides cannot change a lexicographic comparison.
  Sorting, tie ordering, the final output order, ids, metadata and every error
  are unchanged. Nothing is borrowed from or retained beyond the call.
- A set with no closing point (dense overlap) is one component: the same DP
  with the same tables, plus one comparison and one `min` per candidate in the
  pass that already filled `ends`.
- No new dependency, no unsafe code, no public-API change.

## Equivalence

`select_global_oracle` (the resolver as shipped before this change: disjoint
fast path, then `select_dp_oracle`, the pre-#1094 full DP) is compared with
the new resolver by selected `(detector_order, candidate_order, start, end)` in
order:

- 3,000 structured sets of 1 to 12 clusters separated by gaps and by exact
  adjacency, with singletons, pairs and clusters of up to 40, mixed severity,
  specificity and confidence;
- 2,000 random sets of up to 600 candidates over spans of up to 4,000;
- named shapes: single, identical ranges (three copies), a tie followed by a
  singleton, containment, adjacent clusters, "pair beats single" across
  clusters, "two disjoint beat one overlapper", a 200-link chain, 200 pairs, one
  300-candidate dense cluster, and one dense cluster among 100 singletons;
- the existing 6,000-set test against the full DP and the existing
  disjoint/adjacent/equal-endpoint cases.

A mutation check confirmed the tests have power: replacing the whole-set base
with a constant 2 makes two of them fail. Changing the closing rule to also
split at exactly adjacent ranges (`>=`) is, as the reasoning predicts,
equivalent and passes; making the production tie rule `>=` is not detected,
because exact weight ties between different subsets need equal sums in all six
weight fields and the generators essentially never produce one (the tie rule is
byte-for-byte the same code as before). Empty ranges cannot occur
(`ByteRange::new` rejects them).

## Measurement

Apple M4, macOS arm64, `rustc` 1.98.1, release profile, **a shared and loaded
host**. Ignored test `measure_overlap_1135`: old resolver vs new in the same
process, alternating A/B over 41 batches, minimum reported, with an A/A control
(the old resolver again). The candidate vector is cloned for both, so the clone
and the output collection are common to both (as in the issue's method) and
dilute the ratios. Two process runs agree to within 1-2 points:

| workload (n) | baseline -> new | A/A |
|---|---|---|
| disjoint, 5,000 | 11.4 -> 11.4 us (-0.3% to +0.8%) | +0.2% to +0.4% |
| sparse overlap: one overlap, 5,000 | 203 -> 35.5 us (-82.5%) | -0.2% to +0.2% |
| pairs, 5,000 | 250 -> 150 us (-40%) | -0.0% to +0.1% |
| clusters of 50, 5,000 | 118 -> 66 us (-44%) | +-0.2% |
| one dense cluster of 1,000 among 4,000 singletons | 268 -> 137 us (-49%) | +-0.2% |
| dense overlap (one component, trivial DP), 5,000 | 86.2 -> 81.7 us (-5%) | +-0.2% |
| one component, neighbours overlap (chain), 5,000 | 147 -> 145 us (-1% to -2%) | +-0.1% |
| mixed severity, one component, 5,000 | 197 -> 187 us (-5%) | +-0.3% |
| sparse overlap, 64 | 2.01 -> 0.86 us (-57%) | +-0.3% |
| pairs, 16 | 0.35 -> 0.29 us (-17%) | +-1.6% |
| dense overlap, 16 | 0.28 -> 0.27 us (-3%) | +-2% |
| overlapping pair, 2 | 0.10-0.11 -> 0.11 us (+3% to +7%, about 4-6 ns) | +-2% |

The only workload that does not improve or stay level is the two-candidate
overlap: about 5 ns on a ~110 ns call that includes the clone; I could not
remove it without a separate small-set path that measured no better. A call
this small happens once per closed line at most, inside scans that cost
microseconds to milliseconds. Dense overlap, the case the issue rejected the
prototype for, is level to 5% faster instead of 17-22% slower.

Whole scan (`benches/scan_cost.rs`, baseline built from the #1134 commit, 21
runs, three alternating rounds): unicode-invisible-64k 0.663-0.679 -> 0.667-0.671
ms whole; scale-logs-64k 0.701-0.715 -> 0.708-0.720 ms; provider-tables-64k
1.112-1.142 -> 1.110-1.113 ms; mixed-10m 113.1-113.7 -> 113.3-116.0 ms; incremental
paths within +-1%. These workloads rarely overlap, so no whole-scan change is
expected or visible. This is a stage result, not a release speedup.

## Allocation and live memory

Not instrumented here: the counting allocator in the maintainer examples
needs `unsafe`, which new harness code may not contain. By construction the
allocation count is unchanged: `ends`, mask, one `totals`, one `include`, the
output vector (five calls) for every set, because a component's tables are
reserved from the workspace and reused, never rebuilt (the prototype's 15,003
calls on pairs come from per-component vectors, which this does not have). Live
table memory falls from `96 * (n + 1)` bytes of `EvidenceWeight` (480 KB at
5,000) to `96 * (largest component + 1)`; for sparse overlap, pairs and
clusters that is a few hundred bytes to a few KB. For one dense component it is
unchanged.

## Reproduce

```
cargo test --release -p redact-secret --lib -- --ignored --nocapture measure_overlap
cargo bench -p redact-secret --bench scan_cost -- --no-detectors --runs 21 scale-logs-64k provider-tables-64k
```

## Reproducing the timing

The ignored timing test(s) named above were removed before merge: `npm run rust:check` forbids clock and stdout names (`std::time`, `println!`) anywhere in `secret-scan-core/src`, test modules included. The removed code is kept verbatim as `removed-timing-harness.patch.txt` (a reverse patch: apply it to a checkout of the merged commit with `git apply -R` to restore the harness locally, then run the `cargo test --release ... --ignored --nocapture` command quoted above). Do not commit it back into `src/`.
