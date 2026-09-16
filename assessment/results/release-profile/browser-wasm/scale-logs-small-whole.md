# Performance assessment — browser-wasm

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/wasm@0.1.0-beta.3`
- Commit: `d727f386f8fc2a88eded6f26dd38c79f6b83dc68`
- Host: darwin-25.5.0 / arm64 / chromium-153.0.8010.12
- Command: `node scripts/assessment-browser-performance.mjs --engine chromium --artifact-dir /Users/minhokang/Work/ops/utilities/redact-secret/bindings/wasm/pkg --profile scale-logs-small-whole --runs 5 --json-out assessment/results/release-profile/browser-wasm/scale-logs-small-whole.json --markdown-out assessment/results/release-profile/browser-wasm/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 4.399999976158142 | 4.899999976158142 | 6.800000011920929 | 6.800000011920929 | 5.459999990463257 | 1.0268398341579024 |
| Steady-state processing | milliseconds | 5 | 15.199999988079071 | 17.5 | 19.100000023841858 | 19.100000023841858 | 17.299999988079072 | 1.407124740654782 |
| Throughput | bytes-per-second | 5 | 3432146.592574411 | 3745942.857142857 | 4312763.161277114 | 4312763.161277114 | 3815057.562018247 | 317959.91294048174 |

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
