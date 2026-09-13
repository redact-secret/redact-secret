# Performance assessment — node

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.1`
- Commit: `a356e702e59b03cf297e0af15ba0423bc8466d48`
- Host: darwin-25.5.0 / arm64 / node-22.16.0
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-medium-fixed4096 --runs 2 --addon-dir bindings/node --json-out assessment/results/complete/node/scale-logs-medium-fixed4096.json --markdown-out assessment/results/complete/node/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 2 | 1.581541999999999 | 1.6257920000000041 | 1.6700420000000094 | 1.6700420000000094 | 1.6257920000000041 | 0.04425000000000523 |
| Steady-state processing | milliseconds | 2 | 44.98895900000002 | 45.36618750000001 | 45.743415999999996 | 45.743415999999996 | 45.36618750000001 | 0.37722849999998687 |
| Throughput | bytes-per-second | 2 | 5730966.834658785 | 5779020.492059215 | 5827074.149459645 | 5827074.149459645 | 5779020.492059215 | 48053.65740043018 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 2 | 15229968 | 15617080 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 2 | 89833472 | 89915392 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 2 | 2232442 | 2232682 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
