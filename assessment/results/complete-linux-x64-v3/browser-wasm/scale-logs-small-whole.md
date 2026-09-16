# Performance assessment — browser-wasm

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/wasm@0.1.0-beta.2`
- Commit: `9359f59596f03443254f662db60d553b0610809e`
- Host: linux-6.17.0-1022-azure / x64 / chromium-153.0.8010.12
- Command: `node scripts/assessment-browser-performance.mjs --engine chromium --artifact-dir /home/runner/work/redact-secret/redact-secret/bindings/wasm/pkg --profile scale-logs-small-whole --runs 5 --json-out assessment-output/browser-wasm/scale-logs-small-whole.json --markdown-out assessment-output/browser-wasm/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 6.2999999999883585 | 7.7000000000116415 | 11.899999999965075 | 11.899999999965075 | 8.45999999998603 | 2.004594722118496 |
| Steady-state processing | milliseconds | 5 | 16.400000000023283 | 17.5 | 20.099999999976717 | 20.099999999976717 | 17.8 | 1.240967364584076 |
| Throughput | bytes-per-second | 5 | 3261393.0348296487 | 3745942.857142857 | 3997195.121945545 | 3997195.121945545 | 3699723.8144898736 | 243100.7763744934 |

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
