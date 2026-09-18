# Performance assessment — rust-core

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.4`
- Commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Host: linux-6.17.0-1022-azure / x86_64 / rustc-1.98.1 (48a229cea 2026-09-01)
- Command: `["target/release/examples/assessment_adapter","performance","--profile","scale-logs-medium-fixed4096","--runs","5","--json-out","assessment-output/rust-core/scale-logs-medium-fixed4096.json","--markdown-out","assessment-output/rust-core/scale-logs-medium-fixed4096.md"]`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.007073 | 0.007795000000000001 | 0.017683 | 0.017683 | 0.010126800000000002 | 0.003948544258331164 |
| Steady-state processing | milliseconds | 5 | 122.641972 | 123.266649 | 125.68791100000001 | 125.68791100000001 | 123.75464280000001 | 1.1122178549689685 |
| Throughput | bytes-per-second | 5 | 2085753.4978045737 | 2126722.857534644 | 2137555.3224144178 | 2137555.3224144178 | 2118506.639168938 | 18910.72088450479 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| browserJsHeap | 0 | — | — | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| nodeExternal | 0 | — | — | The Rust library has no Node external-memory category.; No samples were available. |
| nodeHeap | 0 | — | — | The Rust library does not run inside a Node.js heap.; No samples were available. |
| nodeRss | 0 | — | — | The Rust library does not run inside a Node.js process.; No samples were available. |
| processRss | 5 | 3694592 | 3747840 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| pythonHeap | 0 | — | — | The Rust library does not run inside a Python allocator.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
