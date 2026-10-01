# #1134 - density-aware ASCII skipping in invisible-character normalization

Product judgement. Final record for
[#1134](https://github.com/redact-secret/redact-secret/issues/1134) (parent
#1068, epic #1065). Verdict: **adopted** as a density-aware dispatch,
behavior-preserving; the issue's unconditional prototype stays rejected.
Baseline: the #1133 commit on this branch (`main` at `be5fee95` plus #1133). All
inputs are synthetic; no value is printed.

## Finding

`NormalizedInput::new` already borrows an all-ASCII input and a clean Unicode
input. With any non-ASCII byte present it walked every character through
`is_invisible`. The issue's prototype (an iterator that skips ASCII eight bytes
at a time but emits every non-ASCII character and the ASCII character after
it) was -87% to -92% on sparse inputs and +48% to +79% on dense ones, so it was
rejected as an unconditional dispatch.

## First attempts, and why they were dropped

All kept the governed set and the output identical; each was measured with the
harness below before being replaced.

| design | sparse | dense |
|---|---|---|
| skip 64-byte all-ASCII blocks, per-block iterator | -77% to -91% | +16% to +39% |
| per-character ASCII-run counter, jump after 32 | -70% to -86% | +3% to +6%, but +50% to +80% on prose with ASCII runs just under the trigger |
| probe after every non-ASCII character | -73% to -82%, mixed prose -20% | +18% to +39% (probe cost per character) |
| same, throttled by exponential back-off | -78% to -85% | +9% to +40% |
| 256- and 1,024-byte windows | -67% to -78% | +0.7% to +7%, window overhead |

The lesson from all of them: any per-character bookkeeping, and any iterator
that is rebuilt often, costs more than it saves on text that has no long ASCII
stretch. The dispatch therefore has to act at coarse granularity and leave the
per-character walk byte-for-byte as it was.

## Change (`crates/secret-scan-core/src/normalize.rs`)

- The scan walks the input in windows of `WALK_WINDOW` = 4,096 bytes (extended
  to a character boundary), each with the original `char_indices` + `is_invisible`
  loop, unchanged.
- At the start of each window only, `ascii_stretch_end` looks at eight bytes.
  If all are ASCII it jumps over the whole ASCII stretch (four words per step,
  then one word to find the exact byte); otherwise it does nothing. Dense
  Unicode fails that first word, so it pays one load per 4,096 bytes.
- Phase one (find the first removed code point) and phase two (build the copy
  and seams, in `strip_removed`) use the same dispatch. In phase two a stretch
  is skipped only outside a removed run: inside a run the next character, ASCII
  or not, closes it, so it is always seen. A skipped stretch cannot open a run
  (no ASCII code point is removed) and leaves `kept_from` in place, so the
  text is copied later exactly as before. A run that ends just before an ASCII
  stretch closes at the same offset as before.
- No dependency, no unsafe code, no SIMD intrinsic (`u64::from_le_bytes`, so
  the result is endianness independent), no input-retaining state. The public
  API and every other function are unchanged. Dispatch decides which bytes are
  *examined*, never which code points are removed.

## Equivalence

`oracle_new` in the test module is the pre-change `NormalizedInput::new`
verbatim. `build(input, skip_ascii)` takes the dispatch as a parameter, and
every comparison runs it both on and off against the oracle (text, seams,
borrowed or owned):

- every governed range-boundary character and a stride over all 1,112,064
  scalars, each after 0..=140 ASCII bytes (before, on and after the 8- and
  32-byte steps), followed by ASCII and by a second removed character;
- the 4,096-byte window edge at +-12 bytes and at twice that, with a 1-, 2-, 3-
  and 4-byte character straddling it, a leading removed run, a trailing one and
  a dense Korean/emoji prefix;
- 4,000 generated mixed inputs (ASCII, Korean, emoji, removed code points,
  CRLF, long runs of up to 9,000 ASCII bytes);
- named shapes: leading, trailing and interior runs, a run just before and just
  after an ASCII stretch, input made only of removed code points.

Existing whole and incremental partition tests, the invisible-normalization
suite and the canonical corpus pass unchanged
(`cargo test -p redact-secret`: 1,908 passed in the targeted run).

## Measurement

Apple M4, macOS arm64, `rustc` 1.98.1, release profile. **The host was shared
and loaded**; the harness therefore compares two functions in the same process,
alternating A/B over 41 batches, and the table uses the minimum, which is
stable here. The ignored test `measure_normalize_1134` also runs an **A/A
control**: a second compiled copy of the *old* walk against the first. Absolute
microseconds are not comparable across runs.

Per-call time (68 KB-class inputs; baseline -> new, minimum of 41 batches;
three process runs where one range is shown):

| workload | what it is | change |
|---|---|---|
| ascii | whole-ASCII path, unchanged | +0.1% (A/A -0.2%) |
| sparse-unicode | 68 KB ASCII plus one emoji | -80.4% to -81.6% (19.0 -> 3.5-3.7 us) |
| sparse-invisible | 80 KB ASCII with one removed code point | -82.1% to -82.3% (33.3 -> 5.9 us) |
| sparse-emoji-log | an emoji about every 330 B | -2.4% to -2.7% |
| dense-unicode | Korean and emoji, short ASCII | +0.1% to +0.3% |
| kr-dense-prose | Korean log sentences | +0.3% to +0.9% |
| en-kr-mixed-prose | English and Korean alternating | -1.4% to +0.0% |
| emoji-every-line | an emoji every ~27 B | -2.1% to -1.0% in the latest runs; +2.3% to +3.4% in an earlier build of the same code |
| dense-invisible | a removed code point every ~8 B | +1.0% to +1.5% |

The A/A control (identical code, two compiled copies) differed by up to +1.6%
on dense-invisible and -2.8% on emoji-every-line, and the oracle's own time for
the same input moved 5% to 10% between builds (twice as long for one sparse
input in one build). The dense results are inside that
layout-only variation; the sparse ones are 30 to 80 times larger. Sparse gain is
below the prototype's -87% to -92% because the unchanged `input.is_ascii()`
pre-pass is part of the measured time and a stretch is found only at a window
start. Neither variant allocates.

Whole scan (`benches/scan_cost.rs`, baseline built from the #1133 commit, 21
runs, three alternating rounds):

| workload | path | base | new |
|---|---|---|---|
| unicode-invisible-64k | whole | 0.674 / 0.681 ms (first round 1.162, noisy) | 0.661 / 0.661 ms (1.012) |
| unicode-invisible-64k | incremental | 1.150 / 1.138 ms | 1.121 / 1.151 ms |
| mixed-10m (ASCII and Unicode fillers) | whole | 113.8 / 113.2 / 113.6 ms | 113.5 / 113.5 / 113.5 ms |
| mixed-10m | incremental | 177.0 / 177.1 / 177.3 ms | 177.3 / 177.4 / 177.3 ms |

Normalization is about 2% of a whole scan, so no whole-scan change is
distinguishable; the benefit is the stage on sparse inputs. Do not read this as
a release speedup.

## Residual risk

A dense workload is not measurably slower than the layout noise floor, but the
guarantee is a measurement, not a proof: the dispatch costs one eight-byte load
per 4,096 bytes of non-ASCII text, and the `+1.0%` to `+1.5%` on dense-invisible
persisted in every build. If a representative budget in
`redact-secret-benchmarks` shows a dense regression, reverting is a one-line
change (`build(input, false)` in `new`).

## Reproduce

```
cargo test --release -p redact-secret --lib -- --ignored --nocapture measure_normalize
cargo bench -p redact-secret --bench scan_cost -- --no-detectors --runs 21 unicode-invisible mixed-10m
```
