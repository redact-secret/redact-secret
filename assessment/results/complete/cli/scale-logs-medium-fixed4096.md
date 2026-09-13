# Performance assessment — cli

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.1`
- Commit: `a356e702e59b03cf297e0af15ba0423bc8466d48`
- Host: darwin-25.5.0 / arm64 / rustc 1.98.1 (48a229cea 2026-09-01)
- Command: `node scripts/assessment-cli-performance.mjs --binary target/release/redact-secret --profile scale-logs-medium-fixed4096 --runs 2 --json-out assessment/results/complete/cli/scale-logs-medium-fixed4096.json --markdown-out assessment/results/complete/cli/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 2 | 2.1267500000000155 | 2.1564170000000082 | 2.186084000000001 | 2.186084000000001 | 2.1564170000000082 | 0.029666999999992782 |
| Steady-state processing | milliseconds | 2 | 48.925250000000005 | 49.242375 | 49.5595 | 49.5595 | 49.242375 | 0.3171249999999972 |
| Throughput | bytes-per-second | 2 | 5289682.099294787 | 5323968.902852027 | 5358255.706409267 | 5358255.706409267 | 5323968.902852027 | 34286.80355723994 |

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
| processRss | 2 | 0 | 2244608 | available; A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory. |
| streamingBuffer | 0 | — | — | The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
