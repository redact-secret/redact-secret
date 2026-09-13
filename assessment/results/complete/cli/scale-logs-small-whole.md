# Performance assessment — cli

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.1`
- Commit: `a356e702e59b03cf297e0af15ba0423bc8466d48`
- Host: darwin-25.5.0 / arm64 / rustc 1.98.1 (48a229cea 2026-09-01)
- Command: `node scripts/assessment-cli-performance.mjs --binary target/release/redact-secret --profile scale-logs-small-whole --runs 2 --json-out assessment/results/complete/cli/scale-logs-small-whole.json --markdown-out assessment/results/complete/cli/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 2 | 1.7936669999999992 | 1.9164165000000004 | 2.0391660000000016 | 2.0391660000000016 | 1.9164165000000004 | 0.12274950000000118 |
| Steady-state processing | milliseconds | 2 | 13.471499999999999 | 13.704396 | 13.937292 | 13.937292 | 13.704396 | 0.23289600000000021 |
| Throughput | bytes-per-second | 2 | 4703496.202849162 | 4784810.492398118 | 4866124.7819470735 | 4866124.7819470735 | 4784810.492398118 | 81314.28954895586 |

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
| processRss | 2 | 0 | 2146304 | available; A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory. |
| streamingBuffer | 0 | — | — | The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
