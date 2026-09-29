# Evidence: #981, a committed scan-cost harness with per-detector attribution

**Result:** `crates/secret-scan-core/benches/scan_cost.rs` is a committed
harness. It times the whole-input and incremental paths on eight synthetic
workloads and attributes the cost to each of the 92 built-in detectors. It
adds no dependency (it is a `harness = false` binary; `serde_json` is already
a dev-dependency), uses only the public API, and keeps `std::time` out of
`src/`. `cargo package` ignores it. The baseline below was taken on `main`
at `04b3e212` (the branch changes no product code). It confirms the two
quadratics the #980 research found. On one line of minified JSON,
`generic-token` goes from 114 ms at 64 KiB to about 2 s at 256 KiB (#989). On
`API_KEY=` followed by 10,000 lines of eight spaces, the incremental session
takes 634 ms and the whole-input scan 9 ms (#986).

Issue [#981](https://github.com/redact-secret/redact-secret/issues/981),
parent [#980](https://github.com/redact-secret/redact-secret/issues/980).
The harness replaces the throwaway probes of [#883](../883/README.md) and
[#950](../950/README.md) with the same method. Release budget judgements stay
in `redact-secret-benchmarks`
([`decision-move-performance-results-criteria-and-judgement-to-benchmarks`](../../../decisions/2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md)).
`examples/assessment_adapter.rs`, which the benchmarks repository runs, is
unchanged.

## Usage

```bash
cargo bench -p redact-secret --bench scan_cost -- --list
cargo bench -p redact-secret --bench scan_cost                      # everything, 21 runs
cargo bench -p redact-secret --bench scan_cost -- open-assignment   # one workload (substring)
cargo bench -p redact-secret --bench scan_cost -- --runs 5 --no-detectors
cargo bench -p redact-secret --bench scan_cost -- --json > scan-cost.json
```

| Option | Meaning |
| --- | --- |
| `--runs N` | timed repetitions per figure, after one untimed warm-up (default 21); the median is reported, with min and max |
| `--filter S`, or a bare `S` | only workloads whose name contains `S` |
| `--no-detectors` | skip per-detector attribution (path totals only) |
| `--json` | one JSON document on stdout: every workload, path, and detector, with median/min/max ms and candidate counts |
| `--top K` | detector rows per text table (default 12; JSON always lists all) |
| `--list` | print workload names and descriptions |

Progress lines go to stderr, so `--json` output can be redirected as is. A
full default run takes about five minutes on an Apple M4. Most of that is
`mixed-10m` and `minified-json-256k`, so filter while iterating.

For a before/after comparison, build both commits on the same host, run them
back to back or interleaved, and cite the JSON medians. On a loaded host the
A/A spread was about ±5-8% in #950, so a smaller single difference is noise.

## What it measures

**Paths** (per workload):

- `whole`: one `scan_and_redact` with `DefaultPolicy` and the default
  placeholder formatter.
- `incremental-fixedN`: an `IncrementalSanitizer` fed in chunks of at most
  `N` bytes, split on character boundaries, then `finalize`. It uses the
  CLI's limits: 1 MiB token and multiline construct bounds, and the buffered
  bound derived by `IncrementalLimits::minimum_buffered_bytes`. `N` is 65536,
  the CLI's read size. `scale-logs-256k` also runs 4096, the benchmarks
  `medium-fixed4096` row. The assessment adapter uses smaller construct
  limits (8 KiB token), which would reject the one-line JSON workloads.

**Attribution:** the harness repeats `collect_candidates`
(`src/pipeline.rs`) by hand. For each entry of `DetectorRegistry::detectors()`,
it times `detector().detect(input, &DetectorContext::new(input.len()))` once
over the whole input, and once for every line from `split_inclusive('\n')`.
The per-line figure is the #883 approximation of the incremental unit split,
which is private. It is omitted for one-line inputs. The sum of detector
medians should come close to the `whole` path. The gap is the pipeline's own
work (normalization, overlap resolution, policy, redaction) plus noise.

**Workloads** (all synthetic, built in the bench; no fixture file):

| Name | Shape | Why |
| --- | --- | --- |
| `scale-logs-64k` | `assessment-filler-density-v1` logs at 4 secret lines/KiB, 64 KiB | the benchmarks `scale-logs-small-whole` input, byte for byte |
| `scale-logs-256k` | the same, 256 KiB | the `scale-logs-medium-fixed4096` input |
| `mixed-10m` | 10 MiB cycling the eight assessment fillers (logs, code, chat, prose; ASCII and Unicode), one detected secret line per KiB (GitHub token, quoted password assignment, bearer header) | large-input cost (#982, #988) |
| `minified-json-64k`, `minified-json-256k` | one line of `{"items":[{…},…]}` with no newline, a credential-named `"api_key"` pair in every 16th object | the long-line quadratic (#989, #984) |
| `provider-tables-64k` | a Heroku `authorizations:info` block, Confluent `schema.registry` properties and a 12-row Twilio CLI table, between log lines | the multi-line lookback constructs (#986) |
| `unicode-invisible-64k` | Hangul, CJK, Latin-1 and emoji text with U+200B, U+200C, U+200D, U+2060, U+FEFF and U+00AD, including a zero-width space inside a GitHub token | the normalization path |
| `open-assignment-whitespace-10k` | `API_KEY=` then 10,000 lines of eight spaces | the open-construct rescan (#986) |

The assessment secret line (`ghp_ASSESSMENTSYNTHETIC0…`) is a placeholder the
detectors reject, so both `scale-logs` workloads report zero findings. That is
how the benchmarks rows behave too; the harness keeps the input identical
instead of fixing it.

## Known limits

- **Raw input for attribution.** The pipeline hands detectors a normalized
  copy with invisible code points removed. `NormalizedInput` is private, so on
  `unicode-invisible-64k` the per-detector figures describe the raw text. If
  exact attribution is needed there, add a second target that compiles the
  core sources as modules, as `examples/shadow_evaluation.rs` does.
- **Wall clock.** Medians of wall-clock time on whatever else the host is
  doing. Use operation counts or adversarial tests, not these numbers, to
  pin a complexity bound in CI.
- **Native only.** The harness measures the native release build. WASM, Node
  and Python surfaces are measured by `redact-secret-benchmarks`.
- **MSRV and clippy.** `cargo clippy --all-targets` and the MSRV
  `cargo +1.88 check --all-targets` build the bench, so it must stay clean
  under both. `cargo test` does not build it.

## Baseline on `main` at `04b3e212`

Host: Apple M4 (macOS, aarch64), `rustc 1.98.1`, `cargo bench` release
profile. The host was shared with other agents (load average about 6.9), so
figures are noisier than on an idle machine. 21 runs per figure, medians in
ms, 92 detectors registered.

| Workload | Bytes | Lines | Findings | Whole ms | Incremental 64 KiB ms | Other path ms | Σ detect() whole ms | Σ detect() per line ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `scale-logs-64k` | 65554 | 983 | 0 | 4.92 | 8.50 | — | 5.09 | 7.32 |
| `scale-logs-256k` | 262154 | 3932 | 0 | 20.28 | 35.37 | 34.75 (fixed 4096) | 18.79 | 27.45 |
| `mixed-10m` | 10485773 | 209454 | 10239 | 695.41 | 1352.93 | — | 764.92 | 1196.42 |
| `minified-json-64k` | 65559 | 1 | 41 | 120.76 | 120.14 | — | 118.38 | n/a (one line) |
| `minified-json-256k` | 262184 | 1 | 162 | 1900.01 | 1892.91 | — | 2683.05 | n/a (one line) |
| `provider-tables-64k` | 66304 | 1456 | 112 | 5.99 | 9.68 | — | 5.59 | 8.93 |
| `unicode-invisible-64k` | 65581 | 1075 | 269 | 4.72 | 9.55 | — | 5.03 | 7.72 |
| `open-assignment-whitespace-10k` | 90009 | 10001 | 0 | 9.35 | 633.80 | — | 8.70 | 31.66 |

| Workload | Top detectors by whole-input median (ms; per line in parentheses) |
| --- | --- |
| `scale-logs-64k` | `generic-token` 0.741 (0.657), `telegram-bot-token` 0.224 (0.154), `microsoft-entra-client-secret` 0.181 (0.235), `bearer-token` 0.169 (0.150) |
| `scale-logs-256k` | `generic-token` 2.297 (2.656), `grafana-service-account-token` 0.767 (1.163), `twilio-auth-token` 0.647 (0.935), `bearer-token` 0.606 (0.583) |
| `mixed-10m` | `generic-token` 111.834 (116.254), `twilio-auth-token` 30.127 (38.773), `bearer-token` 25.974 (29.067), `twilio-api-key-secret` 24.863 (35.460) |
| `minified-json-64k` | `generic-token` 114.057, `new-relic-license-key` 0.266, `twilio-api-key-secret` 0.184, `bearer-token` 0.173 |
| `minified-json-256k` | `generic-token` 2665.872, `new-relic-license-key` 0.940, `bearer-token` 0.727, `twilio-api-key-secret` 0.677 |
| `provider-tables-64k` | `generic-token` 0.651 (0.724), `twilio-auth-token` 0.310 (0.316), `datadog-api-key` 0.268 (0.466), `bearer-token` 0.200 (0.188) |
| `unicode-invisible-64k` | `generic-token` 0.517 (0.566), `twilio-auth-token` 0.210 (0.273), `new-relic-license-key` 0.185 (0.196), `twilio-api-key-secret` 0.185 (0.265) |
| `open-assignment-whitespace-10k` | `generic-token` 1.130 (1.673), `twilio-auth-token` 0.477 (1.119), `twilio-api-key-secret` 0.476 (1.099), `pinecone-api-key` 0.433 (1.055) |

Reading the baseline:

- **Long single line (#989).** Four times the bytes cost about sixteen times
  the time: 114 ms to about 2 s, almost all in `generic-token`. The
  `minified-json-256k` `generic-token` median (2.67 s, min 1.98 s, max
  5.17 s) exceeds the whole path's 1.90 s. The host load caught that
  attribution pass; the whole path's min was 1.83 s.
- **Open construct over whitespace (#986).** The incremental session costs 68
  times the whole-input scan on the same bytes. Per-line detector work sums
  to only 32 ms, so the remaining ~600 ms is outside `detect()`, in the
  session's per-line retained-buffer rescan.
- **Everything else.** `generic-token` leads every workload, at 10-15% of
  the summed detector time on log-like text. On those workloads the per-line
  sums run 1.4-1.6 times the whole-input sums, which is the per-call cost #883 measured.
  `scale-logs-64k` whole (4.9 ms) matches the #981 research probe (4.1 ms on
  a quieter host) within load noise.

The full `--json` output of this run is not committed. It is 235 KB and
reproducible with the command above at `04b3e212`. Later issues rerun the
harness at their own base on their own host rather than comparing against
these absolute numbers.
