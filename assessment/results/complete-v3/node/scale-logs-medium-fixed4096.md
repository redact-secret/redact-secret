# Performance assessment — node

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.2`
- Commit: `9359f59596f03443254f662db60d553b0610809e`
- Host: darwin-25.5.0 / arm64 / node-22.16.0
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-medium-fixed4096 --runs 5 --addon-dir bindings/node --json-out assessment-output/node/scale-logs-medium-fixed4096.json --markdown-out assessment-output/node/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 1.5913749999999993 | 1.7021660000000054 | 1.7796670000000034 | 1.7796670000000034 | 1.6913998000000021 | 0.07144670324486932 |
| Steady-state processing | milliseconds | 5 | 45.789957999999984 | 48.33129200000002 | 50.130875 | 50.130875 | 48.38385 | 1.5045555539612405 |
| Throughput | bytes-per-second | 5 | 5229392.066266547 | 5424104.9463358 | 5725141.7439605445 | 5725141.7439605445 | 5423563.439157298 | 172134.2117456676 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 5 | 15313880 | 15942104 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 5 | 88817664 | 90275840 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 5 | 2233366 | 2236113 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
