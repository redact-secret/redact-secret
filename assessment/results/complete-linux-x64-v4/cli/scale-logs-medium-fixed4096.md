# Performance assessment — cli

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.4`
- Commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Host: linux-6.17.0-1022-azure / x64 / rustc 1.98.1 (48a229cea 2026-09-01)
- Command: `node scripts/assessment-cli-performance.mjs --binary target/release/redact-secret --profile scale-logs-medium-fixed4096 --runs 5 --json-out assessment-output/cli/scale-logs-medium-fixed4096.json --markdown-out assessment-output/cli/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 1.96022099999999 | 1.9780040000000554 | 2.2328800000000086 | 2.2328800000000086 | 2.0292557999999956 | 0.10252987045422873 |
| Steady-state processing | milliseconds | 5 | 125.589568 | 126.05836599999998 | 127.47920899999997 | 127.47920899999997 | 126.37469099999998 | 0.7593364191800573 |
| Throughput | bytes-per-second | 5 | 2056445.1415759886 | 2079623.973548888 | 2087386.7485554211 | 2087386.7485554211 | 2074493.2514474248 | 12436.749554925605 |

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
| processRss | 5 | 0 | 3166208 | available; A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory. |
| streamingBuffer | 0 | — | — | The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
