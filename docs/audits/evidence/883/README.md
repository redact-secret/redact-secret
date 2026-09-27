# Evidence: #883, scoping the incremental per-line detector-dispatch redesign

**Result:** the root cause PR #872 identified reproduces exactly (983 `detect()`
calls for one 64 KiB `scale-logs-small-whole` input, not ~980 as an estimate —
983 measured). Of the ~232 ns marginal cost per detector per line, roughly
85–90 ns is pure per-call dispatch overhead (paid once per `detect()`
invocation, independent of what the detector actually scans) and the
remainder is real per-line pattern-matching work every detector already does
as cheaply as this codebase's no-regex, no-lazy_static convention allows.
Batching every line closed within one `append()` into a single `detect()`
call per detector would recover the dispatch-overhead share — an estimated
~38% of the incremental path's detector-invocation cost on this workload —
without a new dependency or a detection-semantics change, but requires a
line-by-line audit of every detector's contract (several are explicitly
single-line, e.g. `context_on_a_different_line_is_not_adjacent`) that is out
of this issue's scope. A combined multi-pattern prefilter (Aho-Corasick or
similar) targets the smaller remaining share, requires a new dependency in a
core crate whose only dependency today is `unicode-normalization`, and is not
recommended as a near-term follow-up. **Decision: do not implement a dispatch
redesign in this issue; recommend a scoped follow-up for the batching
direction only** (see "Decision" below). This issue is measurement and
scoping, not implementation, per its own text.

Issue [#883](https://github.com/redact-secret/redact-secret/issues/883),
parent epic [#774](https://github.com/redact-secret/redact-secret/issues/774).
Prior work: perf rounds 1–3
([#870](https://github.com/redact-secret/redact-secret/pull/870),
[#871](https://github.com/redact-secret/redact-secret/pull/871),
[#872](https://github.com/redact-secret/redact-secret/pull/872)), which cut
the `scale-logs` regression from ~13–31% to ~10–14% but did not clear the
benchmarks repo's 10% `scale-logs` processing-ratio budget on `cli`. Per
[`decision-move-performance-results-criteria-and-judgement-to-benchmarks`](../../../decisions/2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md),
the formal budget judgement stays in `redact-secret-benchmarks`; this record
holds only the internal micro-profiling this scoping decision rests on, taken
against `main` at `b73daad` with no product code changed.

## Method

Round 3 (#872) measured "isolated CLI stream time (`Instant`, interleaved)"
without committing the harness; its numbers are reported in the PR body only.
This record reproduces that method as a temporary `#[ignore]` unit test
inside `crates/secret-scan-core/src/pipeline.rs`'s existing private test
module (which already has a `built_in_registry()` helper), run once with
`cargo test --release -p redact-secret --lib pipeline::tests::probe_883_dispatch_cost_scaling -- --ignored --nocapture`,
then reverted (`git checkout --`) — it is exploratory, not a permanent
fixture, per
[DS0](../../../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md).
It is not part of this issue's commit.

The workload reproduces `assessment/fixtures/workload-profiles.json`'s
`scale-logs-small-whole` profile exactly: 64 KiB, "logs"-shaped filler lines
(`2026-09-12T00:00:00Z INFO fixture request completed status=200
latency_ms=12`), a synthetic secret line every ~13 lines (density 4/KiB). The
probe calls `run_detector_pipeline(line, &registry)` once per line — exactly
what `IncrementalSanitizer` does internally for each closed line, per #872's
own description of the CLI's stdin path — for two registries (the full
built-in set, and `DetectorRegistry::new()` with zero detectors), 15
interleaved rounds each, taking the median. It also times one whole-input
call with the full registry, reproducing rust-core's one-shot `scan()`
comparison point.

## Measured (macOS arm64, `cargo test --release`, one representative run)

| Quantity | Value |
| --- | --- |
| Lines in the 64 KiB workload | 983 |
| Built-in detector count | 79 |
| Per-line loop, full registry (983 × `detect()` over all 79 detectors) | 18.06 ms |
| Per-line loop, empty registry (983 × `detect()` over 0 detectors) | 42.7 µs |
| One whole-input call, full registry (rust-core's comparison point) | 11.23 ms |
| `detect()` calls, per-line loop vs. whole-input call | 79 × 983 ≈ 77,657 vs. 79 |
| Fixed per-line overhead (buffering/allocation, detector-count-independent) | ~43 ns/line |
| Marginal cost per detector per line | ~232 ns |
| — of which, call-count-multiplication tax (line-loop total minus whole-input total, divided by the ~77,578 extra calls) | ~88 ns/call |
| — of which, real per-line scan work (each detector's own cheap literal/prefix check, unavoidable per line regardless of call batching) | ~144 ns |

The 43 ns/line fixed overhead confirms candidate direction "reduce the
incremental pipeline's per-line overhead itself" has essentially no room: it
is already 0.24% of the full-registry per-line total. The ~88 ns/call
dispatch tax is an independent measurement that lands within the same order
of magnitude as #872's own reported ~85 ns/detector/line marginal cost for
its 9 added detectors — cross-validating both figures, though they are not
the identical quantity (#872 measured the marginal cost of *adding* 9
specific keyword-gated detectors via a real CLI binary + process harness;
this measurement isolates the *average* per-call tax across all 79 built-in
detectors via in-process timing).

## Per-candidate-direction ceiling

The issue names four candidate directions. Each is assessed against the
numbers above:

1. **Batch or share trigger/prefilter scanning across all detectors in one
   pass per line, instead of each detector independently prescanning.**
   Reframed by this measurement as: batch every line closed within one
   `append()` call into a single `detect()` invocation per detector, instead
   of one invocation per line. This targets the ~88 ns/call dispatch tax,
   worth an estimated 38% of the per-line-loop total (6.83 ms of 18.06 ms on
   this workload) — the highest-leverage, lowest-architectural-risk lever
   measured. It requires no new dependency and no change to any detector's
   matching logic. It does require verifying that every detector's contract
   is safe to evaluate over several already-independent closed lines handed
   to `detect()` in one call instead of one line at a time — most detectors
   scan by explicit line boundaries internally (e.g.
   `keyword_gated_keys::lines()`) and should be indifferent to how many
   lines share one call, but at least one family's tests assert a strictly
   single-line contract (`context_on_a_different_line_is_not_adjacent`,
   `a_pinecone_name_on_another_line_does_not_gate_a_uuid`) and would need a
   family-by-family audit before any implementation, not just this family —
   real engineering work spanning all ~79 detectors, out of this issue's
   scope.

2. **Reduce the incremental pipeline's per-line overhead itself (buffering,
   allocation), separately from per-detector cost.** Measured at ~43 ns/line,
   0.24% of the full-registry per-line total. Not a meaningful lever;
   dropped from further consideration.

3. **A single combined multi-pattern automaton (e.g. Aho-Corasick) across all
   keyword/prefix literals, gating dispatch to individual detectors.**
   Targets the remaining ~144 ns/detector/line real-scan share — a smaller
   ceiling than direction 1, and one this codebase cannot reach without
   either a new dependency (the core crate's only dependency today is
   `unicode-normalization`; PR #872 confirmed "this codebase has no
   regex/OnceLock/lazy_static") or a from-scratch multi-pattern matcher
   correctly handling this codebase's several distinct triggering shapes
   (plain ASCII-case-insensitive literals, `rsplit('_')`-segmented exact
   names, provider-specific windows). Either path is a new architectural
   dependency decision spanning every detector family — ADR-worthy on its
   own, not a same-issue add-on. Not recommended as a near-term follow-up
   given its smaller measured ceiling and materially higher implementation
   risk than direction 1.

4. **Reconsider whether `scale-logs-small-whole`'s CLI number should be
   benchmarked against the CLI's own incremental path rather than
   rust-core's one-shot `scan()`, if the harness comparison itself is the
   wrong shape.** Confirmed as a valid, orthogonal observation: the
   whole-input call (11.23 ms) and the per-line loop (18.06 ms) are measuring
   two genuinely different dispatch shapes, and 6.83 ms of the 18.06 ms is
   attributable to call-count multiplication, not to the CLI doing more real
   scanning work than rust-core's one-shot path does. This does not reduce
   any real CPU cost by itself, but it is a legitimate methodology question
   for the benchmarks repo, out of this issue's scope as the issue itself
   says ("worth flagging there too").

## Decision

Per this issue's own framing ("profile first ... quantify ... then decide
whether to implement" and "not a commitment to ship in Beta.10 or any
specific release"): **no dispatch redesign is implemented in this issue.**
The recommendation, backed by the measurements above:

- Open a separate, scoped follow-up issue for direction 1 (batch closed
  lines per `append()` call) — the only direction with both a large measured
  ceiling (~38%) and no new-dependency or grammar risk. Its scope is a
  detector-by-detector audit of the several-lines-per-call contract, not a
  new prefilter architecture.
- Do not pursue direction 3 (combined multi-pattern automaton) unless
  direction 1 alone fails to close the `cli` `scale-logs` budget — its
  ceiling is smaller and its cost (new dependency or custom implementation,
  spanning every detector family) is materially higher.
- Direction 2 is closed: no further investigation warranted.
- Direction 4 is flagged here for whoever next touches
  `redact-secret-benchmarks`'s `scale-logs` profile definition, but is not
  actioned by this repository.

No fixture, expectation, or detector grammar/prefix/shape changed. No new
dependency was added. Cross-runtime parity is unaffected because no product
code changed.

## Reproduce

```sh
# Apply the probe from this record's "Method" section as a temporary edit to
# crates/secret-scan-core/src/pipeline.rs's `mod tests`, then:
cargo test --release -p redact-secret --lib \
  pipeline::tests::probe_883_dispatch_cost_scaling -- --ignored --nocapture
# Revert afterward: git checkout -- crates/secret-scan-core/src/pipeline.rs
```
