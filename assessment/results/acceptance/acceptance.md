# RC performance and resource acceptance

> Historical measurement: Rust performance lacks release-build evidence and cannot support optimized cross-runtime comparisons or new acceptance decisions. Original samples and status are retained. See [the corrected local run](../release-profile/README.md).

- Status: **ACCEPTED**
- Criteria: `rc-performance-resource-v1` (fixed 2026-09-13)
- Environment profile: `macos-arm64-node22-chromium`
- Source commit: `054076f1d3cc870a04249eb40fdce0b07f546ed2`
- Complete assessment: [summary](summary.json)

## Threshold checks

| Check | Observed | Requirement | Result |
| --- | ---: | ---: | --- |
| rust-core:performance:scale-logs-small-whole:initialization-p95-ms | 0.28479200000000005 | <= 2 | pass |
| rust-core:performance:scale-logs-small-whole:processing-p95-ms | 90.537 | <= 200 | pass |
| rust-core:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 724057.5676242862 | >= 350000 | pass |
| rust-core:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 3555328 | <= 8388608 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.24745799999999998 | <= 2 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:processing-p95-ms | 409.32983299999995 | <= 850 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 640446.8447331568 | >= 300000 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 3751936 | <= 8388608 | pass |
| python:performance:scale-logs-small-whole:initialization-p95-ms | 1.003917 | <= 3 | pass |
| python:performance:scale-logs-small-whole:processing-p95-ms | 10.817958 | <= 25 | pass |
| python:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 6059738.81577281 | >= 3000000 | pass |
| python:performance:scale-logs-small-whole:memory-pythonHeap-maximum-bytes | 74188 | <= 2097152 | pass |
| python:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 26443776 | <= 67108864 | pass |
| python:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.995833 | <= 3 | pass |
| python:performance:scale-logs-medium-fixed4096:processing-p95-ms | 46.867375 | <= 100 | pass |
| python:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 5593528.547310363 | >= 2750000 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-pythonHeap-maximum-bytes | 536599 | <= 2097152 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 27312128 | <= 67108864 | pass |
| node:performance:scale-logs-small-whole:initialization-p95-ms | 1.8002500000000055 | <= 5 | pass |
| node:performance:scale-logs-small-whole:processing-p95-ms | 11.252375 | <= 25 | pass |
| node:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 5825792.332729757 | >= 2900000 | pass |
| node:performance:scale-logs-small-whole:memory-nodeHeap-maximum-bytes | 7044640 | <= 33554432 | pass |
| node:performance:scale-logs-small-whole:memory-nodeRss-maximum-bytes | 61145088 | <= 134217728 | pass |
| node:performance:scale-logs-small-whole:memory-nodeExternal-maximum-bytes | 2268936 | <= 8388608 | pass |
| node:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 1.7414579999999944 | <= 5 | pass |
| node:performance:scale-logs-medium-fixed4096:processing-p95-ms | 47.712917000000004 | <= 100 | pass |
| node:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 5494403.11939008 | >= 2750000 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeHeap-maximum-bytes | 15926240 | <= 50331648 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeRss-maximum-bytes | 90931200 | <= 201326592 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeExternal-maximum-bytes | 2235389 | <= 8388608 | pass |
| browser-wasm:performance:scale-logs-small-whole:initialization-p95-ms | 4 | <= 15 | pass |
| browser-wasm:performance:scale-logs-small-whole:processing-p95-ms | 7.100000008940697 | <= 20 | pass |
| browser-wasm:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 9232957.734852243 | >= 4000000 | pass |
| browser-wasm:performance:scale-logs-small-whole:memory-browserJsHeap-maximum-bytes | 10000000 | <= 33554432 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 5.600000008940697 | <= 15 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:processing-p95-ms | 32.099999994039536 | <= 75 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 8166791.278775011 | >= 4000000 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:memory-browserJsHeap-maximum-bytes | 39600000 | <= 100663296 | pass |
| cli:performance:scale-logs-small-whole:initialization-p95-ms | 2.096459000000003 | <= 6 | pass |
| cli:performance:scale-logs-small-whole:processing-p95-ms | 13.395375000000001 | <= 35 | pass |
| cli:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 4893778.636283045 | >= 2250000 | pass |
| cli:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 2195456 | <= 8388608 | pass |
| cli:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 2.1104580000000013 | <= 6 | pass |
| cli:performance:scale-logs-medium-fixed4096:processing-p95-ms | 49.474208 | <= 110 | pass |
| cli:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 5298801.347158504 | >= 2500000 | pass |
| cli:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 2310144 | <= 8388608 | pass |
