# Performance assessment — node

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.1`
- Commit: `054076f1d3cc870a04249eb40fdce0b07f546ed2`
- Host: darwin-25.5.0 / arm64 / node-22.16.0
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-small-whole --runs 5 --addon-dir bindings/node --json-out assessment/results/acceptance/node/scale-logs-small-whole.json --markdown-out assessment/results/acceptance/node/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 1.5154169999999993 | 1.532083 | 1.8002500000000055 | 1.8002500000000055 | 1.5843581999999998 | 0.10837802260864794 |
| Steady-state processing | milliseconds | 5 | 10.659042000000007 | 10.851917 | 11.252375 | 11.252375 | 10.919867000000002 | 0.1960123798529047 |
| Throughput | bytes-per-second | 5 | 5825792.332729757 | 6040776.021416307 | 6150083.656673833 | 6150083.656673833 | 6005105.131650895 | 106895.85458217308 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 5 | 6903744 | 7044640 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 5 | 60325888 | 61145088 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 5 | 2232682 | 2268936 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
