# Performance assessment — browser-wasm

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/wasm@0.1.0-beta.4`
- Commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Host: darwin-25.5.0 / arm64 / chromium-153.0.8010.12
- Command: `node scripts/assessment-browser-performance.mjs --engine chromium --artifact-dir /Users/minhokang/orca/workspaces/redact-secret/gate-beta.5-on-precision-gains-and-positive-pres/bindings/wasm/pkg --profile scale-logs-small-whole --runs 5 --json-out assessment-output-v4-real/browser-wasm/scale-logs-small-whole.json --markdown-out assessment-output-v4-real/browser-wasm/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 5 | 6.900000035762787 | 8.800000011920929 | 8.800000011920929 | 6.920000004768371 | 1.4048487414870774 |
| Steady-state processing | milliseconds | 5 | 29.599999964237213 | 30.100000023841858 | 30.600000023841858 | 30.600000023841858 | 30.060000002384186 | 0.37202152487818135 |
| Throughput | bytes-per-second | 5 | 2142287.580030192 | 2177873.752427756 | 2214662.164837922 | 2214662.164837922 | 2181105.446874196 | 26961.234331795407 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 0 | — | — | A browser process does not expose Node heapUsed.; No samples were available. |
| nodeRss | 0 | — | — | Browser pages do not expose process RSS through a standard API.; No samples were available. |
| nodeExternal | 0 | — | — | Browser pages do not expose Node external memory.; No samples were available. |
| browserJsHeap | 5 | 10000000 | 10000000 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. performance.memory is non-standard, engine-dependent, and may be coarsened. |
| wasmLinearMemory | 0 | — | — | The package intentionally keeps its WebAssembly.Memory handle private; the test harness cannot read linear-memory size without adding product instrumentation.; No samples were available. |
| pythonHeap | 0 | — | — | The browser surface does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Browser pages do not expose whole-process RSS through a standard API.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
