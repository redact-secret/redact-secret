# Performance assessment — browser-wasm

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `@redact-secret/wasm@0.1.0-beta.2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Host: linux-6.17.0-1022-azure / x64 / chromium-153.0.8010.12
- Command: `node scripts/assessment-browser-performance.mjs --engine chromium --artifact-dir /home/runner/work/redact-secret/redact-secret/bindings/wasm/pkg --profile scale-logs-medium-fixed4096 --runs 5 --json-out assessment-output/browser-wasm/scale-logs-medium-fixed4096.json --markdown-out assessment-output/browser-wasm/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 14.100000000034925 | 14.400000000023283 | 15.399999999965075 | 15.399999999965075 | 14.54000000001397 | 0.4498888751414787 |
| Steady-state processing | milliseconds | 5 | 64.80000000004657 | 65.10000000003492 | 65.20000000001164 | 65.20000000001164 | 65.06000000002095 | 0.13564659964980363 |
| Throughput | bytes-per-second | 5 | 4020766.8711649263 | 4026943.164360359 | 4045586.419750179 | 4045586.419750179 | 4029436.5567999566 | 8421.78769474506 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 0 | — | — | A browser process does not expose Node heapUsed.; No samples were available. |
| nodeRss | 0 | — | — | Browser pages do not expose process RSS through a standard API.; No samples were available. |
| nodeExternal | 0 | — | — | Browser pages do not expose Node external memory.; No samples were available. |
| browserJsHeap | 5 | 39600000 | 39600000 | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. performance.memory is non-standard, engine-dependent, and may be coarsened. |
| wasmLinearMemory | 0 | — | — | The package intentionally keeps its WebAssembly.Memory handle private; the test harness cannot read linear-memory size without adding product instrumentation.; No samples were available. |
| pythonHeap | 0 | — | — | The browser surface does not run inside a Python allocator.; No samples were available. |
| processRss | 0 | — | — | Browser pages do not expose whole-process RSS through a standard API.; No samples were available. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
