# Evidence: #950, recovering the processing-time regression against the beta.8 budgets

**Result:** the benchmarks performance evaluation rejected `main` at
`1127bf9` on all ten `latency/*/processing-ratio` rows (median ratios
1.13 to 1.42 against beta.8, `regression-budgets-v1`). Seven exact
optimizations on `beta11/950-perf-recovery` bring every latency row back
within budget: at `a1702684`, nine rows sit at 0.54 to 0.83 of beta.8 and
`browser-wasm/scale-logs-small-whole` at 1.23 (its allowance is 1.30). The
growth came from 22 more detectors (70 to 92), wider `connection-string` and
`generic-token` work, and older hot paths those detectors multiplied:
per-byte prefix scans, run-length tables built before any prefix was
found, and allocations on every per-line `detect()` call. No finding,
range, action, or output byte changed, and no dependency was added. The
#883 batching redesign was not needed and is not implemented; its remaining
ceiling is recorded below for the maintainer. WASM size is out of scope
(already decided).

Issue [#950](https://github.com/redact-secret/redact-secret/issues/950).
Prior scoping: [#883](../883/README.md). Per
[`decision-move-performance-results-criteria-and-judgement-to-benchmarks`](../../../decisions/2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md),
the formal budget judgement belongs to `redact-secret-benchmarks`. The
workflow runs are cited by id below, and their artifacts stay in that
repository. This record holds the internal attribution and profiling the
changes rest on.

## Rows that failed at `1127bf9`

Benchmarks run
[36463844435](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36463844435)
(candidate `1127bf9`, baseline beta.8 `3144bb3`, paired interleaved, 12
samples per side, `INTEL(R) XEON(R) PLATINUM 8573C`). All ten latency rows
regressed on the processing median ratio:

| Surface | Workload | Median ratio | Allowed |
| --- | --- | ---: | ---: |
| rust-core | scale-logs-small-whole | 1.186 | 1.10 |
| rust-core | scale-logs-medium-fixed4096 | 1.209 | 1.10 |
| python | scale-logs-small-whole | 1.139 | 1.10 |
| python | scale-logs-medium-fixed4096 | 1.183 | 1.10 |
| node | scale-logs-small-whole | 1.132 | 1.10 |
| node | scale-logs-medium-fixed4096 | 1.166 | 1.10 |
| browser-wasm | scale-logs-small-whole | 1.425 | 1.30 |
| browser-wasm | scale-logs-medium-fixed4096 | 1.239 | 1.10 |
| cli | scale-logs-small-whole | 1.239 | 1.10 |
| cli | scale-logs-medium-fixed4096 | 1.256 | 1.10 |

Initialization and memory rows were within budget. The size rows are out of
scope. The fixed RC acceptance criteria rejected only on
`browser-wasm … medium-fixed4096 initialization-p95` (68.9 ms against a
35 ms cap, one outlier sample).

Every surface shares the core scan, so the rows move together. The
`small-whole` rows of rust-core, python, node, and browser-wasm are one
whole-input `scan_and_redact`. `cli small-whole` and every
`medium-fixed4096` row run the incremental session, which calls every
detector once per closed line (983 lines per 64 KiB).

## Method

- **Probe.** A temporary example, `crates/secret-scan-core/examples/perf_probe.rs`
  ([posted on the issue](https://github.com/redact-secret/redact-secret/issues/950#issuecomment-5877533319),
  never committed), built the exact `assessment-filler-density-v1` logs
  workloads. It timed (a) whole-input `scan_and_redact` on 64 KiB, (b) an
  incremental session over the same 64 KiB as one chunk, (c) a session over
  256 KiB in 4096-byte chunks, and (d) every built-in detector's `detect()`
  alone, over the whole input and once per line. Each figure is a median of
  21 repetitions. Probe binaries were built at every commit compared.
- **Pairing.** Commits ran interleaved (A B B A …) on one loaded macOS arm64
  (Apple M4) host, with same-binary A/A controls. A/A spread was about ±5-8%
  under load, so single differences below that are noise.
- **Profiles.** macOS `sample` on a native probe looping one detector or one
  incremental session. `wasm32-wasip1` probes ran under Node 22 `node:wasi`.
  In Chromium (Playwright), the built browser artifact of each commit was
  timed and CPU-profiled over the CDP Profiler, with `--liftoff-only` and
  `--no-liftoff` variants.
- **Workflow.** The benchmarks performance workflow was dispatched on
  `develop` with `candidate_revision` set to each pushed branch head.

## Attribution: `3144bb3` (beta.8) to `1127bf9` (main)

Native probe medians, 4 interleaved rounds (ms, and ratio to beta.8):

| Commit | Detectors | Whole 64 KiB | Incremental 64 KiB | Incremental 256 KiB / 4096 |
| --- | ---: | ---: | ---: | ---: |
| beta.8 `3144bb3` | 70 | 6.25 (1.00) | 11.70 (1.00) | 48.21 (1.00) |
| beta.9 `f726f2f` | 70 | 6.60 (1.06) | 12.53 (1.07) | 50.44 (1.05) |
| beta.10 `af7f863` | 79 | 7.33 (1.17) | 14.13 (1.21) | 52.93 (1.10) |
| before Beta.11 detectors `b0be64b` | 79 | 6.89 (1.10) | 13.62 (1.16) | 54.44 (1.13) |
| after #938 `ea5c7bd` | 92 | 7.44 (1.19) | 15.25 (1.30) | 59.87 (1.24) |
| main `1127bf9` | 92 | 7.11 (1.14) | 14.72 (1.26) | 60.75 (1.26) |

Per-detector deltas between those points, as sums of each detector's own
`detect()` time (whole / per line, ms per 64 KiB). These are approximate,
because run-to-run noise between separate probe runs is about ±0.1 ms on
the sums:

- **beta.8 to beta.9:** `connection-string` +0.18 / +0.34. Issue #836 added
  the `http`, `https`, `ftp`, and `ftps` schemes to a scan that tried every
  scheme at every byte offset. `generic-token` +0.08 and `bearer-token` +0.05.
- **beta.9 to beta.10:** 9 new detectors (#868/#869 AWS Bedrock ×2,
  ElevenLabs, Together, Tavily, and the keyword-gated Mistral, Cohere, AI21,
  and Deepgram), +0.22 / +0.39.
- **Beta.11 detectors (#903-#917, via #938):** 13 new detectors,
  +0.48 / +1.12. The per-line cost is mostly fixed per call: a `detect()`
  that finds no prefix still paid for building its shape and run tables.
  `generic-token` added +0.13 (#911/#919 reference and composite checks).
- **#938 to main:** `generic-token` +0.10 (#941 `auth_token`), `mailchimp`
  +0.09, and `slack-token` +0.06 per line. The rest is within noise.
- **#933 previous-line retention:** the Twilio CLI table and Confluent
  properties checks in `has_open_single_line_construct` did not show up
  separately in the incremental profile (`twilio::is_twilio_cli_command`
  was about 0.6% of samples).
- **PII runtime when PII is off:** did not show up. The default registry
  links no PII detector, and the wasm default artifact has no PII runtime
  (#937).

Hot spots in main's profiles, most of them present before beta.8 and
multiplied by the new detectors:

| Where | Main cost (64 KiB) | Cause |
| --- | --- | --- |
| `slack-token` | 1.22 ms whole, 1.63 ms per line | 5 prefix passes, each building two input-length run tables and testing `ends_with`/`starts_with` (a `memcmp` call) at every byte |
| `generic-token` | 1.04 / 1.14 ms | every `name=value` (`status=200`, `latency_ms=12`) ran the value's reference, placeholder, and entropy checks before the name was known to be eligible |
| `connection-string` | 0.95 / 0.97 ms | 14 case-insensitive scheme comparisons at every byte offset |
| `pattern::scan_prefixed_shapes` (about 55 detectors) | 17% of incremental samples; 47% of Chromium wasm samples | a per-byte lead-byte test, then 3-4 table allocations per call before any prefix was known to occur |
| `pipeline::collect_candidates` | about 20% of incremental samples in allocation | `collect::<Result<Vec<_>>>` loses the size hint, so the 92-entry list regrew by doubling on every line |
| wasm `FindingJs::new` | quadratic in findings | each finding's UTF-16 offsets were counted from the start of the input |

The browser-wasm small-whole row stayed high after the native rows had
recovered. In Chromium, `scan_prefixed_shapes` alone was 47% of wasm scan
time: V8's wasm code has no SIMD, so the per-byte lead-byte loop costs far
more than it does natively. That surface-specific cost is why a word-at-a-time
lead-byte search was added.

## Optimizations

Each change is its own commit and gives byte-identical findings. Every
reordered check is pure, and every skipped offset is one the old loop
could only have rejected. Each commit that replaces a scan has an
equivalence test against the loop it replaced.

| Commit | Change | Native effect (whole / incr 64 KiB / incr 256 KiB, ratio to beta.8) |
| --- | --- | --- |
| main | — | 1.21 / 1.27 / 1.24 |
| `bc95cdd` | `slack-token`: search each prefix with `pattern::find_literal` and build the run tables on the first occurrence only | 1.00 / 1.12 / 1.12 |
| `a99c7da` | `connection-string`: jump to within `MAX_SCHEME_SPAN` bytes of the next `://`, and use `find_literal` for `AccountKey=` | 0.90 / 1.05 / 1.04 |
| `925bb0b` | `generic-token`: decide name eligibility before the value checks; `is_high_signal_name` runs once | 0.84 / 1.01 / 1.00 |
| `3f41875` | `scan_prefixed_shapes`/`scan_prefixed_runs`: return before building any table when no lead byte occurs, and build run tables only on a matched prefix | 0.83 / 0.69 / 0.69 |
| `5798052` | pipeline: size the per-detector list once, and skip overlap selection when there is no candidate | 0.83 / 0.68 / 0.67 |
| `60056bf` | wasm: convert a whole scan's finding ranges to UTF-16 in one pass (`Utf16Ranges`) | binding only |
| `a170268` | `LeadBytes`: find a prefixed scan's lead bytes (four or fewer) eight bytes at a time; compare prefixes byte by byte before `memcmp` | 0.69 / 0.69 / 0.66 |

Chromium (local, same harness, `scale-logs-small-whole`, second call):
beta.8 9.6 ms, final 6.5 ms (0.69). Steady state: 8.5 ms against 5.5 ms.
With `--liftoff-only`: 17.0 ms against 10.9 ms. With `--no-liftoff`:
10.3 ms against 5.6 ms. Under `node:wasi`, whole-input scan was
0.90 of beta.8 before `a170268`.

## Results (benchmarks performance workflow)

Median processing ratio against beta.8, per row:

| Row | `1127bf9` [36463844435](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36463844435) | `3f41875` [36472140044](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36472140044) | `aec7c01`¹ [36473719842](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36473719842) | `a170268` [36475754131](https://github.com/redact-secret/redact-secret-benchmarks/actions/runs/36475754131) |
| --- | ---: | ---: | ---: | ---: |
| rust-core small-whole | 1.186 ✗ | 0.727 | 0.708 | 0.543 |
| rust-core medium-fixed4096 | 1.209 ✗ | 0.836 | 0.814 | 0.792 |
| python small-whole | 1.139 ✗ | 0.736 | 0.701 | 0.559 |
| python medium-fixed4096 | 1.183 ✗ | 0.833 | 0.803 | 0.788 |
| node small-whole | 1.132 ✗ | 0.739 | 0.722 | 0.546 |
| node medium-fixed4096 | 1.166 ✗ | 0.849 | 0.840 | 0.786 |
| browser-wasm small-whole (allowed 1.30) | 1.425 ✗ | 1.181 | 1.382 ✗ | 1.232 |
| browser-wasm medium-fixed4096 | 1.239 ✗ | 0.801 | 0.833 | 0.792 |
| cli small-whole | 1.239 ✗ | 0.847 | 0.831 | 0.827 |
| cli medium-fixed4096 | 1.256 ✗ | 0.836 | 0.810 | 0.806 |
| Runner CPU | Xeon 8573C | Xeon 6973P-C | EPYC 7763 | EPYC 9V74 |
| Latency verdict | 10 regressions | 10 within budget | 1 regression² | 10 within budget |

¹ `aec7c01` is `60056bf` before a `cargo fmt` fixup. The trees differ only in
formatting.
² The `aec7c01` run also flagged `initialization/browser-wasm/scale-logs-small-whole`
(1.33, +2 ms). `a170268` passes every initialization row. RC acceptance
passed on all three branch runs.

## What remains

- **`browser-wasm/scale-logs-small-whole`** is the one row still above 1.0
  in CI (1.18, 1.38, 1.23 across three runners), while the same comparison
  measured locally in Chromium is 0.69. Its 12 samples per side spread over
  21-39 ms on the 4-vCPU runners, about 2.5x the local time. Each sample is
  the second call on a fresh page, so wasm compilation and tier-up of a
  module that is 29% larger compressed (the accepted size tradeoff) share
  the runner's 4 vCPUs with the measured call. The row's A/A median
  deviation reaches 0.147, which is where its 0.30 allowance comes from. The
  final commit passes. The earlier failure did not recur with more
  optimization and looks like tail noise on that runner class, but the row
  is the one to watch.
- **#883 batching** (one `detect()` per detector for all lines closed within
  one `append()`) was not needed and is not implemented. After these
  changes, the incremental path costs 7.48 ms per 64 KiB against 4.17 ms for
  the whole-input path (native). The ceiling for batching is therefore about
  44% of incremental time on these workloads, down from #883's measured
  dispatch-tax share. It still requires the detector-by-detector
  single-line contract audit #883 describes. It would not move the one row
  still above 1.0, which is whole-input.
- **A shared multi-detector prefilter** (one pass over the input for every
  detector's lead bytes) is the next structural lever, since about 55
  detectors each still make their own pass. It needs no dependency, but it
  changes how detectors are dispatched. #883 judged it ADR-worthy, and it is
  not attempted here.

## Checks

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked
-- -D warnings` (plus the wasm crate for `wasm32-unknown-unknown`,
`--no-default-features`, and `--features pii`), and `cargo test --workspace
--locked` all pass: the conformance corpus, `incremental_partitions` at
every UTF-8 and UTF-16 split, `adversarial_bounds`, and binding parity. The
wasm crate tests pass natively and under `wasm-bindgen-test-runner` (full,
common, and pii). `npm run ci` passes. `python3 scripts/run-sast.py`
reports 0 unresolved.

## Reproduce

```sh
# Probe (not committed): copy the example posted on the issue
# (https://github.com/redact-secret/redact-secret/issues/950#issuecomment-5877533319)
# into crates/secret-scan-core/examples/perf_probe.rs, then per commit:
cargo build --release -p redact-secret --example perf_probe
./target/release/examples/perf_probe totals   # whole / incremental medians
./target/release/examples/perf_probe per      # per-detector whole / per-line
# Benchmarks (in redact-secret-benchmarks):
gh workflow run performance-evaluation.yml --ref develop \
  -f candidate_revision=<40-hex product commit>
```
