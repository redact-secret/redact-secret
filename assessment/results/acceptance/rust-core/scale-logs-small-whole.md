# Performance assessment — rust-core

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.1`
- Commit: `054076f1d3cc870a04249eb40fdce0b07f546ed2`
- Host: macos-25.5.0 / aarch64 / rustc-1.98.1 (48a229cea 2026-09-01)
- Command: `cargo run -p redact-secret --example assessment_adapter -- performance --profile scale-logs-small-whole --runs 5 --json-out assessment/results/acceptance/rust-core/scale-logs-small-whole.json --markdown-out assessment/results/acceptance/rust-core/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.009000000000000001 | 0.011333 | 0.28479200000000005 | 0.28479200000000005 | 0.0655666 | 0.10962274055979444 |
| Steady-state processing | milliseconds | 5 | 89.74891699999999 | 89.958125 | 90.537 | 90.537 | 90.1314002 | 0.31738002139227933 |
| Throughput | bytes-per-second | 5 | 724057.5676242862 | 728716.8335267104 | 730415.499052763 | 730415.499052763 | 727324.9054552806 | 2558.8574062835623 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| browserJsHeap | 0 | — | — | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| nodeExternal | 0 | — | — | The Rust library has no Node external-memory category.; No samples were available. |
| nodeHeap | 0 | — | — | The Rust library does not run inside a Node.js heap.; No samples were available. |
| nodeRss | 0 | — | — | The Rust library does not run inside a Node.js process.; No samples were available. |
| processRss | 5 | 3407872 | 3555328 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| pythonHeap | 0 | — | — | The Rust library does not run inside a Python allocator.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
