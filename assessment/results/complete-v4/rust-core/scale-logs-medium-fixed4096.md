# Performance assessment — rust-core

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.4`
- Commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Host: macos-25.5.0 / aarch64 / rustc-1.98.1 (48a229cea 2026-09-01)
- Command: `["target/release/examples/assessment_adapter","performance","--profile","scale-logs-medium-fixed4096","--runs","5","--json-out","assessment-output-v4-real/rust-core/scale-logs-medium-fixed4096.json","--markdown-out","assessment-output-v4-real/rust-core/scale-logs-medium-fixed4096.md"]`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.0135 | 0.015417000000000002 | 0.151125 | 0.151125 | 0.04240020000000001 | 0.05438384202463081 |
| Steady-state processing | milliseconds | 5 | 139.01070800000002 | 151.371084 | 160.59879099999998 | 160.59879099999998 | 152.00933320000001 | 7.970885035926414 |
| Throughput | bytes-per-second | 5 | 1632353.5088131519 | 1731863.1344411857 | 1885854.721349955 | 1885854.721349955 | 1729463.988241497 | 93017.9538737654 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| browserJsHeap | 0 | — | — | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| nodeExternal | 0 | — | — | The Rust library has no Node external-memory category.; No samples were available. |
| nodeHeap | 0 | — | — | The Rust library does not run inside a Node.js heap.; No samples were available. |
| nodeRss | 0 | — | — | The Rust library does not run inside a Node.js process.; No samples were available. |
| processRss | 5 | 3391488 | 3850240 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| pythonHeap | 0 | — | — | The Rust library does not run inside a Python allocator.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
