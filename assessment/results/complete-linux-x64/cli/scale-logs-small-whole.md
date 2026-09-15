# Performance assessment — cli

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Host: linux-6.17.0-1022-azure / x64 / rustc 1.98.1 (48a229cea 2026-09-01)
- Command: `node scripts/assessment-cli-performance.mjs --binary target/release/redact-secret --profile scale-logs-small-whole --runs 5 --json-out assessment-output/cli/scale-logs-small-whole.json --markdown-out assessment-output/cli/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 2.441950999999989 | 2.535026000000016 | 2.7157459999999958 | 2.7157459999999958 | 2.559171599999999 | 0.09540139337053948 |
| Steady-state processing | milliseconds | 5 | 27.129925999999998 | 27.31266499999998 | 27.891756999999984 | 27.891756999999984 | 27.455343399999993 | 0.32532681808458264 |
| Throughput | bytes-per-second | 5 | 2350300.126306135 | 2400131.9534362555 | 2416298.518469973 | 2416298.518469973 | 2387993.0938938423 | 28188.672277867456 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 0 | — | — | The CLI is a native process, not a Node.js process.; No samples were available. |
| nodeRss | 0 | — | — | The CLI is a native process, not a Node.js process.; No samples were available. |
| nodeExternal | 0 | — | — | The CLI is a native process, not a Node.js process.; No samples were available. |
| browserJsHeap | 0 | — | — | The CLI is a native process, not a browser JavaScript environment.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The CLI is a native process and does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The CLI is a native process, not a Python allocator.; No samples were available. |
| processRss | 5 | 0 | 3088384 | available; A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory. |
| streamingBuffer | 0 | — | — | The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
