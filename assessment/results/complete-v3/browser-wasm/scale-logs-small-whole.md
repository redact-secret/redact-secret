# Performance assessment — browser-wasm

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `@redact-secret/wasm@0.1.0-beta.2`
- Commit: `9359f59596f03443254f662db60d553b0610809e`
- Host: darwin-25.5.0 / arm64 / chromium-153.0.8010.12
- Command: `node scripts/assessment-browser-performance.mjs --engine chromium --artifact-dir /Users/minhokang/orca/workspaces/redact-secret/p2-re-pin-rc-acceptance-criteria-to-the-current/bindings/wasm/pkg --profile scale-logs-small-whole --runs 5 --json-out assessment-output/browser-wasm/scale-logs-small-whole.json --markdown-out assessment-output/browser-wasm/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 2.2999999821186066 | 2.699999988079071 | 3.100000023841858 | 3.100000023841858 | 2.719999998807907 | 0.29933260217257346 |
| Steady-state processing | milliseconds | 5 | 6.800000011920929 | 6.9000000059604645 | 7.4000000059604645 | 7.4000000059604645 | 7.000000011920929 | 0.22803508449706036 |
| Throughput | bytes-per-second | 5 | 8858648.64151329 | 9500579.70193799 | 9640294.100746874 | 9640294.100746874 | 9374554.85208391 | 297766.9983534005 |

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
