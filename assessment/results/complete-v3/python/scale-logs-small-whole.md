# Performance assessment — python

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret==0.1.0b2`
- Commit: `9359f59596f03443254f662db60d553b0610809e`
- Host: darwin-25.5.0 / arm64 / cpython-3.14.7
- Command: `node scripts/assessment-python-performance.mjs --python .venv/bin/python --profile scale-logs-small-whole --runs 5 --json-out assessment-output/python/scale-logs-small-whole.json --markdown-out assessment-output/python/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.843833 | 0.922917 | 1.4825 | 1.4825 | 1.0204832 | 0.23510115309066432 |
| Steady-state processing | milliseconds | 5 | 10.729167 | 10.99 | 14.491042 | 14.491042 | 11.745466799999999 | 1.3987573834133495 |
| Throughput | bytes-per-second | 5 | 4523760.265134833 | 5964877.161055505 | 6109887.188819039 | 6109887.188819039 | 5650273.485309407 | 580680.3613162058 |

Raw samples are preserved in the JSON result under each distribution's `samples` field.

## Memory observations

Memory categories are reported separately and must not be summed.

| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |
| --- | ---: | ---: | ---: | --- |
| nodeHeap | 0 | — | — | The Python process does not run inside a Node.js heap.; No samples were available. |
| nodeRss | 0 | — | — | The Python process is not a Node.js process; its whole-process RSS is reported as processRss.; No samples were available. |
| nodeExternal | 0 | — | — | The Python process has no Node external-memory category.; No samples were available. |
| browserJsHeap | 0 | — | — | The Python process does not run inside a browser JavaScript heap.; No samples were available. |
| wasmLinearMemory | 0 | — | — | The Python package uses a native extension, not WebAssembly linear memory.; No samples were available. |
| pythonHeap | 5 | 0 | 74188 | available; Measured by tracemalloc during a separate untimed processing pass; it observes Python allocations made after tracing starts, not the interpreter's pre-existing heap or native Rust allocations. |
| processRss | 5 | 25935872 | 26525696 | available; Unix ru_maxrss high-water marks sampled immediately before and after a separate untimed processing pass; the value includes the Python interpreter, native extension, allocator, and earlier process activity and cannot isolate Rust-only memory. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
