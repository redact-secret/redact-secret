# Performance assessment — cli

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.1`
- Commit: `3215b76e8d061d50bf9000af3445eef801009ccf`
- Host: darwin-25.5.0 / arm64 / rustc 1.98.1 (48a229cea 2026-09-01)
- Command: `node scripts/assessment-cli-performance.mjs --profile scale-logs-small-whole --runs 2 --json-out assessment/results/cli/scale-logs-small-whole.json --markdown-out assessment/results/cli/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 2 | 1.6259999999999977 | 1.7204584999999977 | 1.8149169999999977 | 1.8149169999999977 | 1.7204584999999977 | 0.0944585 |
| Steady-state processing | milliseconds | 2 | 12.262583 | 12.445125 | 12.627667000000002 | 12.627667000000002 | 12.445125 | 0.18254200000000154 |
| Throughput | bytes-per-second | 2 | 5191299.3904574765 | 5268577.576736248 | 5345855.76301502 | 5345855.76301502 | 5268577.576736248 | 77278.18627877161 |

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
