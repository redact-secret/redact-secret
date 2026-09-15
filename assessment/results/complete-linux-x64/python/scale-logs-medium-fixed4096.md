# Performance assessment — python

- Profile: `scale-logs-medium-fixed4096`
- Schema version: `3`
- Artifact: `redact-secret==0.1.0b2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Host: linux-6.17.0-1022-azure / x64 / cpython-3.12.14
- Command: `node scripts/assessment-python-performance.mjs --python .venv/bin/python --profile scale-logs-medium-fixed4096 --runs 5 --json-out assessment-output/python/scale-logs-medium-fixed4096.json --markdown-out assessment-output/python/scale-logs-medium-fixed4096.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.887883 | 0.935152 | 0.997039 | 0.997039 | 0.9326871999999999 | 0.03746198591852814 |
| Steady-state processing | milliseconds | 5 | 85.18591 | 88.146878 | 88.412317 | 88.412317 | 87.4913486 | 1.189511314907696 |
| Throughput | bytes-per-second | 5 | 2965129.847236104 | 2974058.8203248675 | 3077433.815052278 | 3077433.815052278 | 2996905.8534938325 | 41475.83902156916 |

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
| pythonHeap | 5 | 0 | 537596 | available; Measured by tracemalloc during a separate untimed processing pass; it observes Python allocations made after tracing starts, not the interpreter's pre-existing heap or native Rust allocations. |
| processRss | 5 | 20987904 | 21135360 | available; Unix ru_maxrss high-water marks sampled immediately before and after a separate untimed processing pass; the value includes the Python interpreter, native extension, allocator, and earlier process activity and cannot isolate Rust-only memory. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
