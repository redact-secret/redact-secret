# Complete cross-language assessment baseline

> Historical measurement: Rust performance lacks release-build evidence and cannot support optimized cross-runtime comparisons or new acceptance decisions. Original samples and status are retained. See [the corrected local run](../release-profile/README.md).

- Status: **COMPLETE**
- Source commit: `9359f59596f03443254f662db60d553b0610809e`
- Accuracy corpus: version `3`, SHA-256 `cc4cb42028fd700bc98dd06dacebe421c5462dd59a46cf013154a4d185849979`
- Workload profiles: version `1`, SHA-256 `b4db2cd22b4c008c9d63789df8ca2e21e697a21a84699466ea5f96c89d8e2806`
- Performance repetitions: 5

A complete status requires accuracy and every named performance profile for Rust, Python, Node, browser WebAssembly, and CLI, all from one source revision and identical corpus/profile identities. Timing samples are expected to vary; identities and repetition counts are not.

## Run inventory

| Surface | Kind | Profile | Path | Status | Raw JSON | Markdown |
| --- | --- | --- | --- | --- | --- | --- |
| rust-core | accuracy | accuracy-corpus | whole-input | complete | [JSON](rust-core/accuracy-corpus.json) | [report](rust-core/accuracy-corpus.md) |
| rust-core | performance | scale-logs-small-whole | whole-input | complete | [JSON](rust-core/scale-logs-small-whole.json) | [report](rust-core/scale-logs-small-whole.md) |
| rust-core | performance | scale-logs-medium-fixed4096 | incremental | complete | [JSON](rust-core/scale-logs-medium-fixed4096.json) | [report](rust-core/scale-logs-medium-fixed4096.md) |
| python | accuracy | accuracy-corpus | whole-input | complete | [JSON](python/accuracy-corpus.json) | [report](python/accuracy-corpus.md) |
| python | performance | scale-logs-small-whole | whole-input | complete | [JSON](python/scale-logs-small-whole.json) | [report](python/scale-logs-small-whole.md) |
| python | performance | scale-logs-medium-fixed4096 | incremental | complete | [JSON](python/scale-logs-medium-fixed4096.json) | [report](python/scale-logs-medium-fixed4096.md) |
| node | accuracy | accuracy-corpus | whole-input | complete | [JSON](node/accuracy-corpus.json) | [report](node/accuracy-corpus.md) |
| node | performance | scale-logs-small-whole | whole-input | complete | [JSON](node/scale-logs-small-whole.json) | [report](node/scale-logs-small-whole.md) |
| node | performance | scale-logs-medium-fixed4096 | incremental | complete | [JSON](node/scale-logs-medium-fixed4096.json) | [report](node/scale-logs-medium-fixed4096.md) |
| browser-wasm | accuracy | accuracy-corpus | whole-input | complete | [JSON](browser-wasm/accuracy-corpus.json) | [report](browser-wasm/accuracy-corpus.md) |
| browser-wasm | performance | scale-logs-small-whole | whole-input | complete | [JSON](browser-wasm/scale-logs-small-whole.json) | [report](browser-wasm/scale-logs-small-whole.md) |
| browser-wasm | performance | scale-logs-medium-fixed4096 | incremental | complete | [JSON](browser-wasm/scale-logs-medium-fixed4096.json) | [report](browser-wasm/scale-logs-medium-fixed4096.md) |
| cli | accuracy | accuracy-corpus | whole-input | complete | [JSON](cli/accuracy-corpus.json) | [report](cli/accuracy-corpus.md) |
| cli | performance | scale-logs-small-whole | whole-input | complete | [JSON](cli/scale-logs-small-whole.json) | [report](cli/scale-logs-small-whole.md) |
| cli | performance | scale-logs-medium-fixed4096 | standard-input | complete | [JSON](cli/scale-logs-medium-fixed4096.json) | [report](cli/scale-logs-medium-fixed4096.md) |

## Accuracy

| Surface | TP | FP | FN | Policy mismatches |
| --- | ---: | ---: | ---: | ---: |
| rust-core | 21 | 1 | 5 | 0 |
| python | 21 | 1 | 5 | 0 |
| node | 21 | 1 | 5 | 0 |
| browser-wasm | 21 | 1 | 5 | 0 |
| cli | 21 | 1 | 5 | 0 |

## Performance

| Surface | Profile | Processing median (ms) | Throughput median (bytes/s) |
| --- | --- | ---: | ---: |
| rust-core | scale-logs-small-whole | 172.870303 | 379209.146177062 |
| rust-core | scale-logs-medium-fixed4096 | 733.011231 | 357639.8135706055 |
| python | scale-logs-small-whole | 17.739039 | 3695465.1263802964 |
| python | scale-logs-medium-fixed4096 | 83.270559 | 3148219.5285851266 |
| node | scale-logs-small-whole | 19.077056 | 3436274.444023229 |
| node | scale-logs-medium-fixed4096 | 91.293567 | 2871549.5364531 |
| browser-wasm | scale-logs-small-whole | 17.5 | 3745942.857142857 |
| browser-wasm | scale-logs-medium-fixed4096 | 64.79999999998836 | 4045586.4197538137 |
| cli | scale-logs-small-whole | 27.323230999999993 | 2399203.8130483185 |
| cli | scale-logs-medium-fixed4096 | 101.69504900000004 | 2577844.2763718017 |

## Metric limitations

Memory categories are separate and may overlap; they must not be summed. Observed maxima remain sampled observations, not guaranteed true peaks.

| Surface | Profile | Category | Availability / sampling limit |
| --- | --- | --- | --- |
| rust-core | scale-logs-small-whole | browserJsHeap | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| rust-core | scale-logs-small-whole | nodeExternal | The Rust library has no Node external-memory category.; No samples were available. |
| rust-core | scale-logs-small-whole | nodeHeap | The Rust library does not run inside a Node.js heap.; No samples were available. |
| rust-core | scale-logs-small-whole | nodeRss | The Rust library does not run inside a Node.js process.; No samples were available. |
| rust-core | scale-logs-small-whole | processRss | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| rust-core | scale-logs-small-whole | pythonHeap | The Rust library does not run inside a Python allocator.; No samples were available. |
| rust-core | scale-logs-small-whole | streamingBuffer | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| rust-core | scale-logs-small-whole | wasmLinearMemory | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |
| rust-core | scale-logs-medium-fixed4096 | browserJsHeap | The Rust library does not run inside a browser JavaScript heap.; No samples were available. |
| rust-core | scale-logs-medium-fixed4096 | nodeExternal | The Rust library has no Node external-memory category.; No samples were available. |
| rust-core | scale-logs-medium-fixed4096 | nodeHeap | The Rust library does not run inside a Node.js heap.; No samples were available. |
| rust-core | scale-logs-medium-fixed4096 | nodeRss | The Rust library does not run inside a Node.js process.; No samples were available. |
| rust-core | scale-logs-medium-fixed4096 | processRss | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| rust-core | scale-logs-medium-fixed4096 | pythonHeap | The Rust library does not run inside a Python allocator.; No samples were available. |
| rust-core | scale-logs-medium-fixed4096 | streamingBuffer | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| rust-core | scale-logs-medium-fixed4096 | wasmLinearMemory | The Rust library surface does not use WebAssembly linear memory.; No samples were available. |
| python | scale-logs-small-whole | nodeHeap | The Python process does not run inside a Node.js heap.; No samples were available. |
| python | scale-logs-small-whole | nodeRss | The Python process is not a Node.js process; its whole-process RSS is reported as processRss.; No samples were available. |
| python | scale-logs-small-whole | nodeExternal | The Python process has no Node external-memory category.; No samples were available. |
| python | scale-logs-small-whole | browserJsHeap | The Python process does not run inside a browser JavaScript heap.; No samples were available. |
| python | scale-logs-small-whole | wasmLinearMemory | The Python package uses a native extension, not WebAssembly linear memory.; No samples were available. |
| python | scale-logs-small-whole | pythonHeap | available; Measured by tracemalloc during a separate untimed processing pass; it observes Python allocations made after tracing starts, not the interpreter's pre-existing heap or native Rust allocations. |
| python | scale-logs-small-whole | processRss | available; Unix ru_maxrss high-water marks sampled immediately before and after a separate untimed processing pass; the value includes the Python interpreter, native extension, allocator, and earlier process activity and cannot isolate Rust-only memory. |
| python | scale-logs-small-whole | streamingBuffer | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| python | scale-logs-medium-fixed4096 | nodeHeap | The Python process does not run inside a Node.js heap.; No samples were available. |
| python | scale-logs-medium-fixed4096 | nodeRss | The Python process is not a Node.js process; its whole-process RSS is reported as processRss.; No samples were available. |
| python | scale-logs-medium-fixed4096 | nodeExternal | The Python process has no Node external-memory category.; No samples were available. |
| python | scale-logs-medium-fixed4096 | browserJsHeap | The Python process does not run inside a browser JavaScript heap.; No samples were available. |
| python | scale-logs-medium-fixed4096 | wasmLinearMemory | The Python package uses a native extension, not WebAssembly linear memory.; No samples were available. |
| python | scale-logs-medium-fixed4096 | pythonHeap | available; Measured by tracemalloc during a separate untimed processing pass; it observes Python allocations made after tracing starts, not the interpreter's pre-existing heap or native Rust allocations. |
| python | scale-logs-medium-fixed4096 | processRss | available; Unix ru_maxrss high-water marks sampled immediately before and after a separate untimed processing pass; the value includes the Python interpreter, native extension, allocator, and earlier process activity and cannot isolate Rust-only memory. |
| python | scale-logs-medium-fixed4096 | streamingBuffer | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| node | scale-logs-small-whole | nodeHeap | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| node | scale-logs-small-whole | nodeRss | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| node | scale-logs-small-whole | nodeExternal | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| node | scale-logs-small-whole | browserJsHeap | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| node | scale-logs-small-whole | wasmLinearMemory | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| node | scale-logs-small-whole | pythonHeap | The Node process does not run inside a Python allocator.; No samples were available. |
| node | scale-logs-small-whole | processRss | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| node | scale-logs-small-whole | streamingBuffer | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| node | scale-logs-medium-fixed4096 | nodeHeap | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| node | scale-logs-medium-fixed4096 | nodeRss | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. |
| node | scale-logs-medium-fixed4096 | nodeExternal | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. External memory can overlap RSS and must not be summed with it. |
| node | scale-logs-medium-fixed4096 | browserJsHeap | The Node process does not expose a browser JavaScript heap.; No samples were available. |
| node | scale-logs-medium-fixed4096 | wasmLinearMemory | The Node N-API surface does not use WebAssembly linear memory.; No samples were available. |
| node | scale-logs-medium-fixed4096 | pythonHeap | The Node process does not run inside a Python allocator.; No samples were available. |
| node | scale-logs-medium-fixed4096 | processRss | Node process RSS is reported as nodeRss; duplicating it as processRss would report one overlapping measure twice.; No samples were available. |
| node | scale-logs-medium-fixed4096 | streamingBuffer | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| browser-wasm | scale-logs-small-whole | nodeHeap | A browser process does not expose Node heapUsed.; No samples were available. |
| browser-wasm | scale-logs-small-whole | nodeRss | Browser pages do not expose process RSS through a standard API.; No samples were available. |
| browser-wasm | scale-logs-small-whole | nodeExternal | Browser pages do not expose Node external memory.; No samples were available. |
| browser-wasm | scale-logs-small-whole | browserJsHeap | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. performance.memory is non-standard, engine-dependent, and may be coarsened. |
| browser-wasm | scale-logs-small-whole | wasmLinearMemory | The package intentionally keeps its WebAssembly.Memory handle private; the test harness cannot read linear-memory size without adding product instrumentation.; No samples were available. |
| browser-wasm | scale-logs-small-whole | pythonHeap | The browser surface does not run inside a Python allocator.; No samples were available. |
| browser-wasm | scale-logs-small-whole | processRss | Browser pages do not expose whole-process RSS through a standard API.; No samples were available. |
| browser-wasm | scale-logs-small-whole | streamingBuffer | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| browser-wasm | scale-logs-medium-fixed4096 | nodeHeap | A browser process does not expose Node heapUsed.; No samples were available. |
| browser-wasm | scale-logs-medium-fixed4096 | nodeRss | Browser pages do not expose process RSS through a standard API.; No samples were available. |
| browser-wasm | scale-logs-medium-fixed4096 | nodeExternal | Browser pages do not expose Node external memory.; No samples were available. |
| browser-wasm | scale-logs-medium-fixed4096 | browserJsHeap | available; Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks. performance.memory is non-standard, engine-dependent, and may be coarsened. |
| browser-wasm | scale-logs-medium-fixed4096 | wasmLinearMemory | The package intentionally keeps its WebAssembly.Memory handle private; the test harness cannot read linear-memory size without adding product instrumentation.; No samples were available. |
| browser-wasm | scale-logs-medium-fixed4096 | pythonHeap | The browser surface does not run inside a Python allocator.; No samples were available. |
| browser-wasm | scale-logs-medium-fixed4096 | processRss | Browser pages do not expose whole-process RSS through a standard API.; No samples were available. |
| browser-wasm | scale-logs-medium-fixed4096 | streamingBuffer | The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.; No samples were available. |
| cli | scale-logs-small-whole | nodeHeap | The CLI is a native process, not a Node.js process.; No samples were available. |
| cli | scale-logs-small-whole | nodeRss | The CLI is a native process, not a Node.js process.; No samples were available. |
| cli | scale-logs-small-whole | nodeExternal | The CLI is a native process, not a Node.js process.; No samples were available. |
| cli | scale-logs-small-whole | browserJsHeap | The CLI is a native process, not a browser JavaScript environment.; No samples were available. |
| cli | scale-logs-small-whole | wasmLinearMemory | The CLI is a native process and does not use WebAssembly linear memory.; No samples were available. |
| cli | scale-logs-small-whole | pythonHeap | The CLI is a native process, not a Python allocator.; No samples were available. |
| cli | scale-logs-small-whole | processRss | available; A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory. |
| cli | scale-logs-small-whole | streamingBuffer | The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.; No samples were available. |
| cli | scale-logs-medium-fixed4096 | nodeHeap | The CLI is a native process, not a Node.js process.; No samples were available. |
| cli | scale-logs-medium-fixed4096 | nodeRss | The CLI is a native process, not a Node.js process.; No samples were available. |
| cli | scale-logs-medium-fixed4096 | nodeExternal | The CLI is a native process, not a Node.js process.; No samples were available. |
| cli | scale-logs-medium-fixed4096 | browserJsHeap | The CLI is a native process, not a browser JavaScript environment.; No samples were available. |
| cli | scale-logs-medium-fixed4096 | wasmLinearMemory | The CLI is a native process and does not use WebAssembly linear memory.; No samples were available. |
| cli | scale-logs-medium-fixed4096 | pythonHeap | The CLI is a native process, not a Python allocator.; No samples were available. |
| cli | scale-logs-medium-fixed4096 | processRss | available; A separate, untimed /usr/bin/time-wrapped repetition's whole-process maximum resident set size; it includes process startup, argument parsing, the Rust runtime, and the entire scan, and cannot isolate steady-state or Rust-only memory. |
| cli | scale-logs-medium-fixed4096 | streamingBuffer | The CLI's standard-input path streams through the incremental core, but the public contract exposes no retained plaintext buffer size.; No samples were available. |
