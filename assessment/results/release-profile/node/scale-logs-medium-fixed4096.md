# Performance assessment — node

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.3`
- Commit: `d727f386f8fc2a88eded6f26dd38c79f6b83dc68`
- Host: darwin-25.5.0 / arm64 / node-22.16.0
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-medium-fixed4096 --runs 5 --addon-dir bindings/node --json-out assessment/results/release-profile/node/scale-logs-medium-fixed4096.json --markdown-out assessment/results/release-profile/node/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 3.426542000000012 | 4.131040999999982 | 6.7469580000000065 | 6.7469580000000065 | 4.7669082000000005 | 1.2191213445816487 |
| Steady-state processing | milliseconds | 5 | 106.59258299999999 | 117.73287499999998 | 127.26287500000001 | 127.26287500000001 | 118.5828082 | 7.39924218113954 |
| Throughput | bytes-per-second | 5 | 2059940.890067115 | 2226684.772626168 | 2459401.8891539574 | 2459401.8891539574 | 2219604.602019148 | 142525.4080958591 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 5 | 15292064 | 15630568 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 5 | 89899008 | 90406912 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 5 | 2233366 | 2233606 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
