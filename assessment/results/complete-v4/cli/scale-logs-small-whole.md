# Performance assessment — cli

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.4`
- Commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Host: darwin-25.5.0 / arm64 / rustc 1.98.1 (48a229cea 2026-09-01)
- Command: `node scripts/assessment-cli-performance.mjs --binary target/release/redact-secret --profile scale-logs-small-whole --runs 5 --json-out assessment-output-v4-real/cli/scale-logs-small-whole.json --markdown-out assessment-output-v4-real/cli/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 3.9301670000000115 | 4.83016699999996 | 9.922874999999976 | 9.922874999999976 | 5.8200333999999945 | 2.1395522866896717 |
| Steady-state processing | milliseconds | 5 | 36.92783300000001 | 44.620082999999966 | 55.13733400000001 | 55.13733400000001 | 45.26735820000001 | 5.818503734895266 |
| Throughput | bytes-per-second | 5 | 1188922.1919942664 | 1469159.0779873729 | 1775192.1700902402 | 1775192.1700902402 | 1471840.4608487678 | 186456.1481315624 |

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
| processRss | 5 | 0 | 2375680 | available; A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory. |
| streamingBuffer | 0 | — | — | The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
