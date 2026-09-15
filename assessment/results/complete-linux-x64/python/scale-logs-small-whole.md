# Performance assessment — python

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret==0.1.0b2`
- Commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Host: linux-6.17.0-1022-azure / x64 / cpython-3.12.14
- Command: `node scripts/assessment-python-performance.mjs --python .venv/bin/python --profile scale-logs-small-whole --runs 5 --json-out assessment-output/python/scale-logs-small-whole.json --markdown-out assessment-output/python/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 0.864018 | 0.875349 | 0.905756 | 0.905756 | 0.8813906000000001 | 0.016404523993094125 |
| Steady-state processing | milliseconds | 5 | 18.917954 | 19.958554 | 19.981668 | 19.981668 | 19.73031 | 0.4094729748205604 |
| Throughput | bytes-per-second | 5 | 3280707.0961243077 | 3284506.482784274 | 3465173.8766253474 | 3465173.8766253474 | 3323978.1872013384 | 71117.25359240374 |

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
| pythonHeap | 5 | 0 | 75205 | available; Measured by tracemalloc during a separate untimed processing pass; it observes Python allocations made after tracing starts, not the interpreter's pre-existing heap or native Rust allocations. |
| processRss | 5 | 20746240 | 20799488 | available; Unix ru_maxrss high-water marks sampled immediately before and after a separate untimed processing pass; the value includes the Python interpreter, native extension, allocator, and earlier process activity and cannot isolate Rust-only memory. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
