# Performance assessment — node

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Host: linux-6.17.0-1022-azure / x64 / node-22.23.2
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-small-whole --runs 5 --addon-dir bindings/node --json-out assessment-output/node/scale-logs-small-whole.json --markdown-out assessment-output/node/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 2.314070000000001 | 2.3577219999999954 | 2.388319999999993 | 2.388319999999993 | 2.3495667999999967 | 0.026121314464625362 |
| Steady-state processing | milliseconds | 5 | 18.98377500000001 | 19.090095000000005 | 19.157061999999996 | 19.157061999999996 | 19.086504800000004 | 0.06117978066452661 |
| Throughput | bytes-per-second | 5 | 3421923.466134839 | 3433927.3848558627 | 3453159.342649182 | 3453159.342649182 | 3434608.6612977376 | 11028.196392211206 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 5 | 6906000 | 7069608 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 5 | 66310144 | 67485696 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 5 | 2289891 | 2289931 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
