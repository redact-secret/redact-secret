# Performance assessment — rust-core

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.2`
- Commit: `9359f59596f03443254f662db60d553b0610809e`
- Host: macos-25.5.0 / aarch64 / rustc-1.98.1 (48a229cea 2026-09-01)
- Command: `cargo run -p redact-secret --example assessment_adapter -- performance --profile scale-logs-small-whole --runs 5 --json-out assessment-output/rust-core/scale-logs-small-whole.json --markdown-out assessment-output/rust-core/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.009667 | 0.010291 | 0.080292 | 0.080292 | 0.024533199999999998 | 0.02789825667958484 |
| Steady-state processing | milliseconds | 5 | 89.889709 | 91.790292 | 94.794833 | 94.794833 | 91.98990839999999 | 1.6675809093501397 |
| Throughput | bytes-per-second | 5 | 691535.581902444 | 714171.3853573971 | 729271.4675491941 | 729271.4675491941 | 712853.8558331428 | 12811.394353052547 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| browserJsHeap | 0 | — | — | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| nodeExternal | 0 | — | — | The Rust library has no Node external-memory category.; No samples were available. |
| nodeHeap | 0 | — | — | The Rust library does not run inside a Node.js heap.; No samples were available. |
| nodeRss | 0 | — | — | The Rust library does not run inside a Node.js process.; No samples were available. |
| processRss | 5 | 3375104 | 4046848 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| pythonHeap | 0 | — | — | The Rust library does not run inside a Python allocator.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
