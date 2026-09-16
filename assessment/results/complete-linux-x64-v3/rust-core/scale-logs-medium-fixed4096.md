# Performance assessment — rust-core

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.2`
- Commit: `9359f59596f03443254f662db60d553b0610809e`
- Host: linux-6.17.0-1022-azure / x86_64 / rustc-1.98.1 (48a229cea 2026-09-01)
- Command: `cargo run -p redact-secret --example assessment_adapter -- performance --profile scale-logs-medium-fixed4096 --runs 5 --json-out assessment-output/rust-core/scale-logs-medium-fixed4096.json --markdown-out assessment-output/rust-core/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.016415000000000003 | 0.018117 | 0.037036 | 0.037036 | 0.021791 | 0.007714546700876207 |
| Steady-state processing | milliseconds | 5 | 731.724318 | 733.011231 | 751.595132 | 751.595132 | 736.6029329999999 | 7.569971440212375 |
| Throughput | bytes-per-second | 5 | 348796.83068516734 | 357639.8135706055 | 358268.80910086137 | 358268.80910086137 | 355932.99678378686 | 3604.972260763712 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| browserJsHeap | 0 | — | — | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| nodeExternal | 0 | — | — | The Rust library has no Node external-memory category.; No samples were available. |
| nodeHeap | 0 | — | — | The Rust library does not run inside a Node.js heap.; No samples were available. |
| nodeRss | 0 | — | — | The Rust library does not run inside a Node.js process.; No samples were available. |
| processRss | 5 | 4378624 | 4444160 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| pythonHeap | 0 | — | — | The Rust library does not run inside a Python allocator.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
