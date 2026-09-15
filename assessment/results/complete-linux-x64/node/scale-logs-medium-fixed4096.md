# Performance assessment — node

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Host: linux-6.17.0-1022-azure / x64 / node-22.23.2
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-medium-fixed4096 --runs 5 --addon-dir bindings/node --json-out assessment-output/node/scale-logs-medium-fixed4096.json --markdown-out assessment-output/node/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 2.344436999999999 | 2.4012839999999755 | 2.460284999999999 | 2.460284999999999 | 2.399079799999993 | 0.038214476143996076 |
| Steady-state processing | milliseconds | 5 | 85.847846 | 86.09175499999998 | 86.32608700000003 | 86.32608700000003 | 86.0494456 | 0.180617935056969 |
| Throughput | bytes-per-second | 5 | 3036787.7093745708 | 3045053.501348649 | 3053705.039961049 | 3053705.039961049 | 3046564.131584763 | 6391.997337357202 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 5 | 21306192 | 21656288 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 5 | 93790208 | 93880320 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 5 | 2321371 | 2321625 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
