# Performance assessment — node

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/core@0.1.0-beta.1`
- Commit: `a356e702e59b03cf297e0af15ba0423bc8466d48`
- Host: darwin-25.5.0 / arm64 / node-22.16.0
- Command: `node scripts/assessment-node-performance.mjs --profile scale-logs-small-whole --runs 2 --addon-dir bindings/node --json-out assessment/results/complete/node/scale-logs-small-whole.json --markdown-out assessment/results/complete/node/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 2 | 1.452292 | 1.4772084999999997 | 1.5021249999999995 | 1.5021249999999995 | 1.4772084999999997 | 0.024916499999999786 |
| Steady-state processing | milliseconds | 2 | 10.560917000000003 | 10.773104000000004 | 10.985291000000004 | 10.985291000000004 | 10.773104000000004 | 0.21218700000000013 |
| Throughput | bytes-per-second | 2 | 5967434.08982065 | 6087330.111843811 | 6207226.133866972 | 6207226.133866972 | 6087330.111843811 | 119896.02202316094 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 2 | 6895304 | 6979304 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeRss | 2 | 60227584 | 60571648 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| nodeExternal | 2 | 2232682 | 2232722 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| browserJsHeap | 0 | — | — | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| pythonHeap | 0 | — | — | The Node process does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
