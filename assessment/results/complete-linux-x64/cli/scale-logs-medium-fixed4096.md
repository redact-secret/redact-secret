# Performance assessment — cli

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Host: linux-6.17.0-1022-azure / x64 / rustc 1.98.1 (48a229cea 2026-09-01)
- Command: `node scripts/assessment-cli-performance.mjs --binary target/release/redact-secret --profile scale-logs-medium-fixed4096 --runs 5 --json-out assessment-output/cli/scale-logs-medium-fixed4096.json --markdown-out assessment-output/cli/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 2.4792509999999766 | 2.5039079999999103 | 2.5969520000000017 | 2.5969520000000017 | 2.5215545999999818 | 0.04298565094821301 |
| Steady-state processing | milliseconds | 5 | 100.55897199999998 | 101.118408 | 102.13445000000002 | 102.13445000000002 | 101.3695378 | 0.6280004757464477 |
| Throughput | bytes-per-second | 5 | 2566753.920934611 | 2592544.771867848 | 2606967.7800604412 | 2606967.7800604412 | 2586221.2502753423 | 16007.717396726372 |

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
| processRss | 5 | 0 | 3121152 | available; A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory. |
| streamingBuffer | 0 | — | — | The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
