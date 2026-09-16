# RC performance and resource acceptance

> Historical measurement: Rust performance lacks release-build evidence and cannot support optimized cross-runtime comparisons or new acceptance decisions. Original samples and status are retained. See [the corrected local run](../release-profile/README.md).

- Status: **ACCEPTED**
- Criteria: `rc-performance-resource-v2` (fixed 2026-09-16)
- Environment profile: `macos-arm64-node22-chromium`
- Source commit: `9359f59596f03443254f662db60d553b0610809e`
- Complete assessment: [summary](summary.json)

## Threshold checks

| Check | Observed | Requirement | Result |
| --- | ---: | ---: | --- |
| rust-core:performance:scale-logs-small-whole:initialization-p95-ms | 0.080292 | <= 2 | pass |
| rust-core:performance:scale-logs-small-whole:processing-p95-ms | 94.794833 | <= 200 | pass |
| rust-core:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 691535.581902444 | >= 350000 | pass |
| rust-core:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 4046848 | <= 8388608 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.085166 | <= 2 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:processing-p95-ms | 464.69458299999997 | <= 850 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 564142.5779219811 | >= 300000 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 3686400 | <= 8388608 | pass |
| python:performance:scale-logs-small-whole:initialization-p95-ms | 1.4825 | <= 3 | pass |
| python:performance:scale-logs-small-whole:processing-p95-ms | 14.491042 | <= 25 | pass |
| python:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 4523760.265134833 | >= 3000000 | pass |
| python:performance:scale-logs-small-whole:memory-pythonHeap-maximum-bytes | 74188 | <= 2097152 | pass |
| python:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 26525696 | <= 67108864 | pass |
| python:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 1.266708 | <= 3 | pass |
| python:performance:scale-logs-medium-fixed4096:processing-p95-ms | 49.823042 | <= 100 | pass |
| python:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 5261702.005268968 | >= 2750000 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-pythonHeap-maximum-bytes | 536607 | <= 2097152 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 27279360 | <= 67108864 | pass |
| node:performance:scale-logs-small-whole:initialization-p95-ms | 1.6360829999999993 | <= 5 | pass |
| node:performance:scale-logs-small-whole:processing-p95-ms | 11.773874999999997 | <= 25 | pass |
| node:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 5567750.6343493555 | >= 2900000 | pass |
| node:performance:scale-logs-small-whole:memory-nodeHeap-maximum-bytes | 7105888 | <= 33554432 | pass |
| node:performance:scale-logs-small-whole:memory-nodeRss-maximum-bytes | 60882944 | <= 134217728 | pass |
| node:performance:scale-logs-small-whole:memory-nodeExternal-maximum-bytes | 2323452 | <= 8388608 | pass |
| node:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 1.7796670000000034 | <= 5 | pass |
| node:performance:scale-logs-medium-fixed4096:processing-p95-ms | 50.130875 | <= 100 | pass |
| node:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 5229392.066266547 | >= 2750000 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeHeap-maximum-bytes | 15942104 | <= 50331648 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeRss-maximum-bytes | 90275840 | <= 201326592 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeExternal-maximum-bytes | 2236113 | <= 8388608 | pass |
| browser-wasm:performance:scale-logs-small-whole:initialization-p95-ms | 3.100000023841858 | <= 15 | pass |
| browser-wasm:performance:scale-logs-small-whole:processing-p95-ms | 7.4000000059604645 | <= 20 | pass |
| browser-wasm:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 8858648.64151329 | >= 4000000 | pass |
| browser-wasm:performance:scale-logs-small-whole:memory-browserJsHeap-maximum-bytes | 10000000 | <= 33554432 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 6.5 | <= 15 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:processing-p95-ms | 35.5 | <= 75 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 7384619.71830986 | >= 4000000 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:memory-browserJsHeap-maximum-bytes | 39600000 | <= 100663296 | pass |
| cli:performance:scale-logs-small-whole:initialization-p95-ms | 2.4152500000000003 | <= 6 | pass |
| cli:performance:scale-logs-small-whole:processing-p95-ms | 13.824042000000006 | <= 35 | pass |
| cli:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 4742028.41686968 | >= 2250000 | pass |
| cli:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 2146304 | <= 8388608 | pass |
| cli:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 2.3360000000000127 | <= 6 | pass |
| cli:performance:scale-logs-medium-fixed4096:processing-p95-ms | 57.333292 | <= 110 | pass |
| cli:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 4572456.7847944265 | >= 2500000 | pass |
| cli:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 2277376 | <= 8388608 | pass |
