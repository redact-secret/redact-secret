# #1133 - fuse normalized range translation and obfuscation seam lookup

Product judgement. Final record for
[#1133](https://github.com/redact-secret/redact-secret/issues/1133) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving. Baseline: `main`
at `be5fee95` (includes the Beta.13 perf batch #1136). All inputs are
synthetic; no value is printed.

## Finding

`validate_candidate` called `NormalizedInput::to_original(range)` and then
`contains_removed_run(range)`. Both partition the seam list at the same two
points (`seam.normalized <= start` and `seam.normalized < end`), so each
candidate paid for four binary searches where two give both answers.

## Change

`crates/secret-scan-core/src/normalize.rs` gains the crate-private
`NormalizedInput::translate(range) -> Option<(ByteRange, bool)>`: the original
range and "a removed run lies strictly inside", from one pair of searches, and
`(range, false)` directly when there are no seams. `to_original` delegates to
it (the PII identity evaluation still calls it). `contains_removed_run` had no
other caller and is now a test-only oracle. `validate_candidate` uses
`translate`; the `ByteRange` construction, the original-input alignment check,
the `InvalidCandidate` error and the rule that a detector-supplied obfuscation
signal is honored in addition to the pipeline's own check are unchanged.
`touches_removed_run` (`< start`, `<= end`) uses different boundaries and is
deliberately not folded in; a test pins that difference.

No public API, dependency, lifetime or unsafe code changed, and nothing is
cached across calls.

## Equivalence

`translate_equals_the_two_separate_searches_for_every_range` compares
`translate` and `to_original` with verbatim copies of the pre-change
implementations (`oracle_to_original`, `oracle_contains_removed_run`) for
**every** `start..=end` range over nine inputs: empty, plain, a lone removed
run, leading/trailing/interior runs, adjacent runs, boundary-adjacent runs,
multi-byte neighbours and clean non-ASCII (no seams). Existing tests for
candidate errors, exact spans, obfuscation metadata, host range conversion,
whole input and incremental partitions pass unchanged
(`cargo test -p redact-secret`).

## Measurement

Apple M4, macOS arm64, `rustc` 1.98.1, release profile. **The host was loaded
(load average about 8 on a shared machine)**, so only the within-run A/B ratio
is meaningful, not the absolute microseconds.

Stage (ignored test `measure_translate_1133` in `normalize.rs`; 4,096 ranges per
call, old pair of searches vs `translate` in the same binary, 15 alternating
AB/BA samples, median), three process runs:

| workload | run 1 | run 2 | run 3 |
|---|---|---|---|
| no seams | 3.7 -> 3.7 us (+1.5%) | 3.0 -> 2.9 us (-0.8%) | 2.9 -> 3.0 us (+1.2%) |
| 4,096 seams | 193.5 -> 106.7 us (-44.9%) | 194.9 -> 106.2 us (-45.5%) | 176.1 -> 97.9 us (-44.4%) |

The no-seam path is within noise (both return the range directly). Neither
variant allocates.

Whole scan (`benches/scan_cost.rs`, `unicode-invisible-64k`: 65,581 bytes, 269
findings, 41 runs, three alternating base/new rounds, the baseline built from
`main`):

| path | base | new |
|---|---|---|
| whole | 1.035 / 1.319 / 1.297 ms | 1.139 / 1.299 / 1.293 ms |
| incremental | 1.996 / 2.214 / 2.233 ms | 1.958 / 2.232 / 2.268 ms |

End to end the change is **not distinguishable from noise**: 269 candidates is
about 540 searches saved in a roughly 1 ms scan. The benefit is the isolated
translation loop for seam-heavy inputs with many candidates; do not read it as
a whole-scan speedup.

## Reproduce

```
cargo test --release -p redact-secret --lib -- --ignored --nocapture measure_translate
cargo bench -p redact-secret --bench scan_cost -- --no-detectors --runs 41 unicode-invisible
```

## Reproducing the timing

The ignored timing test(s) named above were removed before merge: `npm run rust:check` forbids clock and stdout names (`std::time`, `println!`) anywhere in `secret-scan-core/src`, test modules included. The removed code is kept verbatim as `removed-timing-harness.patch.txt` (a reverse patch: apply it to a checkout of the merged commit with `git apply -R` to restore the harness locally, then run the `cargo test --release ... --ignored --nocapture` command quoted above). Do not commit it back into `src/`.

**Update (#1152):** `removed-timing-harness.patch.txt` is kept as inert history, not built or scanned; it holds the only record of the private-helper timing harness. The separate measurement engine measures the public API only and established no timing direction for this card on a hosted 2-vCPU runner, so this patch is the sole way to re-run the private-helper timing. See [`../1152/README.md`](../1152/README.md).
