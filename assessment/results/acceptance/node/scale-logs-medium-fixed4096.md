# Performance assessment — node

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.1`
- Commit: `054076f1d3cc870a04249eb40fdce0b07f546ed2`
- Host: darwin-25.5.0 / arm64 / node-22.16.0
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-medium-fixed4096 --runs 5 --addon-dir bindings/node --json-out assessment/results/acceptance/node/scale-logs-medium-fixed4096.json --markdown-out assessment/results/acceptance/node/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 1.6045420000000092 | 1.6694590000000034 | 1.7414579999999944 | 1.7414579999999944 | 1.6737668000000014 | 0.05227052601762803 |
| Steady-state processing | milliseconds | 5 | 46.33529100000001 | 46.546333000000004 | 47.712917000000004 | 47.712917000000004 | 46.73792480000001 | 0.4945381925742017 |
| Throughput | bytes-per-second | 5 | 5494403.11939008 | 5632108.548701355 | 5657760.949424056 | 5657760.949424056 | 5609639.929974417 | 58498.04808602633 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 5 | 15295792 | 15926240 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 5 | 89440256 | 90931200 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 5 | 2232442 | 2235389 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
