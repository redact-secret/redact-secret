# Performance assessment — node

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.4`
- Commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Host: darwin-25.5.0 / arm64 / node-22.16.0
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-small-whole --runs 5 --addon-dir bindings/node --json-out assessment-output-v4-real/node/scale-logs-small-whole.json --markdown-out assessment-output-v4-real/node/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 3.119082999999989 | 3.810666999999995 | 4.124541000000008 | 4.124541000000008 | 3.638849799999997 | 0.39590767471187366 |
| Steady-state processing | milliseconds | 5 | 28.925083 | 30.411292000000017 | 32.120917000000006 | 32.120917000000006 | 30.569958400000008 | 1.0429891670738685 |
| Throughput | bytes-per-second | 5 | 2040850.8262699968 | 2155580.8940968364 | 2266337.489852665 | 2266337.489852665 | 2146904.809287863 | 73677.67921739104 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 5 | 6895376 | 7045384 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 5 | 60751872 | 61980672 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 5 | 2233606 | 2269925 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
