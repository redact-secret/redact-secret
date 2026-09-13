# Performance assessment — python

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret==0.1.0b1`
- Commit: `a356e702e59b03cf297e0af15ba0423bc8466d48`
- Host: darwin-25.5.0 / arm64 / cpython-3.14.7
- Command: `node scripts/assessment-python-performance.mjs --python .venv/bin/python --profile scale-logs-small-whole --runs 2 --json-out assessment/results/complete/python/scale-logs-small-whole.json --markdown-out assessment/results/complete/python/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 2 | 0.834042 | 0.8436045 | 0.853167 | 0.853167 | 0.8436045 | 0.00956250000000003 |
| Steady-state processing | milliseconds | 2 | 10.537666 | 10.5802915 | 10.622917 | 10.622917 | 10.5802915 | 0.04262549999999976 |
| Throughput | bytes-per-second | 2 | 6170998.041310123 | 6195960.103782957 | 6220922.166255792 | 6220922.166255792 | 6195960.103782957 | 24962.062472834252 |

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
| pythonHeap | 2 | 0 | 74188 | available; Measured by tracemalloc during a separate untimed processing pass; it observes Python allocations made after tracing starts, not the interpreter's pre-existing heap or native Rust allocations. |
| processRss | 2 | 25837568 | 25903104 | available; Unix ru_maxrss high-water marks sampled immediately before and after a separate untimed processing pass; the value includes the Python interpreter, native extension, allocator, and earlier process activity and cannot isolate Rust-only memory. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
