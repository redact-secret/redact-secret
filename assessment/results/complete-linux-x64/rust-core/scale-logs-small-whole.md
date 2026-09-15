# Performance assessment — rust-core

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret@0.1.0-beta.2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Host: linux-6.17.0-1022-azure / x86_64 / rustc-1.98.1 (48a229cea 2026-09-01)
- Command: `cargo run -p redact-secret --example assessment_adapter -- performance --profile scale-logs-small-whole --runs 5 --json-out assessment-output/rust-core/scale-logs-small-whole.json --markdown-out assessment-output/rust-core/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.014507 | 0.016361 | 0.047329 | 0.047329 | 0.022059600000000002 | 0.012660224762617765 |
| Steady-state processing | milliseconds | 5 | 164.08709499999998 | 166.06027400000002 | 174.190752 | 174.190752 | 167.2710486 | 3.544961745108101 |
| Throughput | bytes-per-second | 5 | 376334.5599426541 | 394760.2784275786 | 399507.3469976417 | 399507.3469976417 | 392074.19590349693 | 8085.836433833917 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| browserJsHeap | 0 | — | — | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| nodeExternal | 0 | — | — | The Rust library has no Node external-memory category.; No samples were available. |
| nodeHeap | 0 | — | — | The Rust library does not run inside a Node.js heap.; No samples were available. |
| nodeRss | 0 | — | — | The Rust library does not run inside a Node.js process.; No samples were available. |
| processRss | 5 | 4575232 | 4587520 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| pythonHeap | 0 | — | — | The Rust library does not run inside a Python allocator.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
