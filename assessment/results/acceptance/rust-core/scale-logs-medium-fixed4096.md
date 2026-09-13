# Performance assessment — rust-core

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.1`
- Commit: `054076f1d3cc870a04249eb40fdce0b07f546ed2`
- Host: macos-25.5.0 / aarch64 / rustc-1.98.1 (48a229cea 2026-09-01)
- Command: `cargo run -p redact-secret --example assessment_adapter -- performance --profile scale-logs-medium-fixed4096 --runs 5 --json-out assessment/results/acceptance/rust-core/scale-logs-medium-fixed4096.json --markdown-out assessment/results/acceptance/rust-core/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.010208 | 0.012667 | 0.24745799999999998 | 0.24745799999999998 | 0.06004999999999999 | 0.09373166039924823 |
| Steady-state processing | milliseconds | 5 | 404.84920800000003 | 405.863375 | 409.32983299999995 | 409.32983299999995 | 406.28018340000006 | 1.5926319703274103 |
| Throughput | bytes-per-second | 5 | 640446.8447331568 | 645916.8679608008 | 647534.9211995988 | 647534.9211995988 | 645264.0823979798 | 2517.68865950549 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| browserJsHeap | 0 | — | — | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| nodeExternal | 0 | — | — | The Rust library has no Node external-memory category.; No samples were available. |
| nodeHeap | 0 | — | — | The Rust library does not run inside a Node.js heap.; No samples were available. |
| nodeRss | 0 | — | — | The Rust library does not run inside a Node.js process.; No samples were available. |
| processRss | 5 | 3522560 | 3751936 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| pythonHeap | 0 | — | — | The Rust library does not run inside a Python allocator.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
