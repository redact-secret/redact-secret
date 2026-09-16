# Performance assessment — node

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.2`
- Commit: `9359f59596f03443254f662db60d553b0610809e`
- Host: linux-6.17.0-1022-azure / x64 / node-22.23.2
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-small-whole --runs 5 --addon-dir bindings/node --json-out assessment-output/node/scale-logs-small-whole.json --markdown-out assessment-output/node/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 2.308970000000002 | 2.358242000000004 | 2.372336000000004 | 2.372336000000004 | 2.3533046000000013 | 0.02295550455642303 |
| Steady-state processing | milliseconds | 5 | 18.649451999999997 | 19.077056 | 19.612752999999998 | 19.612752999999998 | 19.137848999999996 | 0.3762983422923925 |
| Throughput | bytes-per-second | 5 | 3342417.048743744 | 3436274.444023229 | 3515063.0699497233 | 3515063.0699497233 | 3426682.168869143 | 67307.67170035615 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 5 | 6968024 | 7071840 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 5 | 66359296 | 66703360 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 5 | 2289891 | 2289931 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
