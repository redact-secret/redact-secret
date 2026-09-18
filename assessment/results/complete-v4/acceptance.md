# RC performance and resource acceptance

- Status: **REJECTED**
- Criteria: `rc-performance-resource-v2` (fixed 2026-09-16)
- Environment profile: `macos-arm64-node22-chromium`
- Source commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Complete assessment: [summary](summary.json)

## Threshold checks

| Check | Observed | Requirement | Result |
| --- | ---: | ---: | --- |
| rust-core:performance:scale-logs-small-whole:initialization-p95-ms | 0.1205 | <= 2 | pass |
| rust-core:performance:scale-logs-small-whole:processing-p95-ms | 31.339583999999995 | <= 200 | pass |
| rust-core:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2091731.657956915 | >= 350000 | pass |
| rust-core:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 4915200 | <= 8388608 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.151125 | <= 2 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:processing-p95-ms | 160.59879099999998 | <= 850 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 1632353.5088131519 | >= 300000 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 3850240 | <= 8388608 | pass |
| python:performance:scale-logs-small-whole:initialization-p95-ms | 2.453625 | <= 3 | pass |
| python:performance:scale-logs-small-whole:processing-p95-ms | 39.729792 | <= 25 | fail |
| python:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 1649996.053339519 | >= 3000000 | fail |
| python:performance:scale-logs-small-whole:memory-pythonHeap-maximum-bytes | 74188 | <= 2097152 | pass |
| python:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 27574272 | <= 67108864 | pass |
| python:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 4.307791 | <= 3 | fail |
| python:performance:scale-logs-medium-fixed4096:processing-p95-ms | 158.896333 | <= 100 | fail |
| python:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 1649842.9828459288 | >= 2750000 | fail |
| python:performance:scale-logs-medium-fixed4096:memory-pythonHeap-maximum-bytes | 536607 | <= 2097152 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 27639808 | <= 67108864 | pass |
| node:performance:scale-logs-small-whole:initialization-p95-ms | 4.124541000000008 | <= 5 | pass |
| node:performance:scale-logs-small-whole:processing-p95-ms | 32.120917000000006 | <= 25 | fail |
| node:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2040850.8262699968 | >= 2900000 | fail |
| node:performance:scale-logs-small-whole:memory-nodeHeap-maximum-bytes | 7045384 | <= 33554432 | pass |
| node:performance:scale-logs-small-whole:memory-nodeRss-maximum-bytes | 61980672 | <= 134217728 | pass |
| node:performance:scale-logs-small-whole:memory-nodeExternal-maximum-bytes | 2269925 | <= 8388608 | pass |
| node:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 5.479333000000054 | <= 5 | fail |
| node:performance:scale-logs-medium-fixed4096:processing-p95-ms | 160.94037500000002 | <= 100 | fail |
| node:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 1628888.959653536 | >= 2750000 | fail |
| node:performance:scale-logs-medium-fixed4096:memory-nodeHeap-maximum-bytes | 15633152 | <= 50331648 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeRss-maximum-bytes | 90603520 | <= 201326592 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeExternal-maximum-bytes | 2233606 | <= 8388608 | pass |
| browser-wasm:performance:scale-logs-small-whole:initialization-p95-ms | 8.800000011920929 | <= 15 | pass |
| browser-wasm:performance:scale-logs-small-whole:processing-p95-ms | 30.600000023841858 | <= 20 | fail |
| browser-wasm:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2142287.580030192 | >= 4000000 | fail |
| browser-wasm:performance:scale-logs-small-whole:memory-browserJsHeap-maximum-bytes | 10000000 | <= 33554432 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 14 | <= 15 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:processing-p95-ms | 137.39999997615814 | <= 75 | fail |
| browser-wasm:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 1907962.1546251045 | >= 4000000 | fail |
| browser-wasm:performance:scale-logs-medium-fixed4096:memory-browserJsHeap-maximum-bytes | 39600000 | <= 100663296 | pass |
| cli:performance:scale-logs-small-whole:initialization-p95-ms | 9.922874999999976 | <= 6 | fail |
| cli:performance:scale-logs-small-whole:processing-p95-ms | 55.13733400000001 | <= 35 | fail |
| cli:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 1188922.1919942664 | >= 2250000 | fail |
| cli:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 2375680 | <= 8388608 | pass |
| cli:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 11.040125000000216 | <= 6 | fail |
| cli:performance:scale-logs-medium-fixed4096:processing-p95-ms | 162.22454200000004 | <= 110 | fail |
| cli:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 1615994.6994949747 | >= 2500000 | fail |
| cli:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 2441216 | <= 8388608 | pass |

## Failures

- `python:performance:scale-logs-small-whole:processing-p95-ms:threshold-not-met`
- `python:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second:threshold-not-met`
- `python:performance:scale-logs-medium-fixed4096:initialization-p95-ms:threshold-not-met`
- `python:performance:scale-logs-medium-fixed4096:processing-p95-ms:threshold-not-met`
- `python:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second:threshold-not-met`
- `node:performance:scale-logs-small-whole:processing-p95-ms:threshold-not-met`
- `node:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second:threshold-not-met`
- `node:performance:scale-logs-medium-fixed4096:initialization-p95-ms:threshold-not-met`
- `node:performance:scale-logs-medium-fixed4096:processing-p95-ms:threshold-not-met`
- `node:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second:threshold-not-met`
- `browser-wasm:performance:scale-logs-small-whole:processing-p95-ms:threshold-not-met`
- `browser-wasm:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second:threshold-not-met`
- `browser-wasm:performance:scale-logs-medium-fixed4096:processing-p95-ms:threshold-not-met`
- `browser-wasm:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second:threshold-not-met`
- `cli:performance:scale-logs-small-whole:initialization-p95-ms:threshold-not-met`
- `cli:performance:scale-logs-small-whole:processing-p95-ms:threshold-not-met`
- `cli:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second:threshold-not-met`
- `cli:performance:scale-logs-medium-fixed4096:initialization-p95-ms:threshold-not-met`
- `cli:performance:scale-logs-medium-fixed4096:processing-p95-ms:threshold-not-met`
- `cli:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second:threshold-not-met`
