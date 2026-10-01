# Evidence: #1122, gating the remaining contextual provider scans

**Result:** rejected, no product code changed. The only reorder the grammar
proves safe covers one of the two Twilio detectors and removes a line scan
that only runs on lines the pipeline prefilter already reduced to ones
holding a 32-byte alphanumeric run. On the most hostile synthetic fixture it
saves a fraction of a millisecond per 256 KiB, under 1% of the whole scan,
and that is not separable from run-to-run noise on a shared machine. The
adopt gate in the issue asks for an end-to-end benefit; there is none to
report.

Issue [#1122](https://github.com/redact-secret/redact-secret/issues/1122),
parent #1068. Kind per DS0: product judgement. Baseline `44382b3f`.
Every input is the synthetic `scan_cost` workload set.

## What was examined

`detect_context_gated` in `crates/secret-scan-core/src/detectors/twilio.rs`
serves both `twilio-auth-token` and `twilio-api-key-secret`. For each line
from `for_each_long_run_line` (restricted by the shared `long_run_lines` span
list when a `ScanScope` is active, #1075) it runs, in order: bare 32-byte run
discovery, the paired identifier scan, the `twilio` keyword scan, and, for
the auth token only, the CLI-table lookback.

## Candidate change

Compute `line_context` (paired identifier, then keyword) before raw run
discovery, and return early when there is no context and no table fallback.

- Api-key secret (`cli_table = false`): the early return is exact. With no
  paired `SK` identifier and no `twilio` keyword the old code also returned
  before emitting anything, so no candidate or error is lost.
- Auth token (`cli_table = true`): a table cell can validate a line with no
  same-line context, so the early return cannot apply. Raw discovery has to
  run first, or the table lookback runs on every long-run line. The reorder
  therefore adds a paired-identifier plus keyword scan to every line and
  saves nothing.

So the safe gate covers one of the two detectors.

## Measurements (exploratory, not budgets)

`cargo bench -p redact-secret --bench scan_cost -- --runs 41 --json`,
serialized with the `/tmp/rs-bench.lock` lock, macOS arm64, workspace
toolchain. Per-detector figures call `detect()` directly, so they bypass the
prefilter and `ScanScope` and are not additive pipeline shares. Minimum of 41
runs in ms on `hex-heavy-log-256k` (every line holds a long run), baseline
vs candidate:

| Detector | whole base | whole cand | per-line base | per-line cand |
| --- | ---: | ---: | ---: | ---: |
| twilio-auth-token | 1.460 | 1.894 | 0.873 | 1.188 |
| twilio-api-key-secret | 0.699 | 0.260 | 0.734 | 0.302 |

`mixed-10m` minimum, whole, baseline vs candidate: auth token 23.96 vs
45.73, api-key secret 23.20 vs 12.14. The two runs saw different machine
load (other builds ran concurrently; the candidate's own median-to-min
spread was 2x), so only the sign pattern is informative: the auth token gets
slower or stays flat, the api-key secret gets faster in isolation.

Whole `scan_and_redact` of the hex-heavy fixture measured 15 to 45 ms
depending on load. The best case for the api-key gate is about 0.4 ms of
that. Wall-clock was not decisive. Allocation behavior is argued, not
measured: both orders allocate the raw-match `Vec` only when a match exists.

## Why the other gates were not pursued

- A blanket same-line keyword gate for the auth token would miss
  `twilio profiles:list` CLI table positives (the issue's own warning).
- `pattern::run_end` discovery is the same linear byte pass the context
  scans perform, so moving it later trades like for like.
- #1092 already shares `provider_word_mask`; a per-line cache for identical
  predicates was left out there, and the two Twilio predicates are not
  identical (different alphabets and prefixes).
- Other contextual providers (heroku, confluent, datadog, pinecone,
  mailchimp, new-relic) were not attributed further. The issue asks for
  attribution before widening, and the Twilio residual is already below
  noise on the hardest fixture.

## Decision

Reject for the beta.13 cycle. Revisit only if a pipeline-level attribution
(ScanScope active, quiet machine) shows Twilio above about 3% of a realistic
whole scan. No default coverage, public API, cache, WASM size or diagnostic
changed.
