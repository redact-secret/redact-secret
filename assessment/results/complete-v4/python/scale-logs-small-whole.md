# Performance assessment — python

- Profile: `scale-logs-small-whole`
- Schema version: `3`
- Artifact: `redact-secret==0.1.0b4`
- Commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Host: darwin-25.5.0 / arm64 / cpython-3.14.7
- Command: `node scripts/assessment-python-performance.mjs --python .venv/bin/python --profile scale-logs-small-whole --runs 5 --json-out assessment-output-v4-real/python/scale-logs-small-whole.json --markdown-out assessment-output-v4-real/python/scale-logs-small-whole.md`

## Timing and throughput distributions

| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initialization | milliseconds | 5 | 2.065541 | 2.231958 | 2.453625 | 2.453625 | 2.2442082 | 0.13661557065195754 |
| Steady-state processing | milliseconds | 5 | 29.196 | 32.146875 | 39.729792 | 39.729792 | 33.574491800000004 | 4.345462566305613 |
| Throughput | bytes-per-second | 5 | 1649996.053339519 | 2039202.8774181006 | 2245307.576380326 | 2245307.576380326 | 1984587.0923149013 | 248509.54278928213 |

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
| processRss | 5 | 26755072 | 27574272 | available; Unix ru_maxrss high-water marks sampled immediately before and after a separate untimed processing pass; the value includes the Python interpreter, native extension, allocator, and earlier process activity and cannot isolate Rust-only memory. |
| streamingBuffer | 0 | — | — | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |

Observed maxima are sampled observations, not guaranteed true peaks.
