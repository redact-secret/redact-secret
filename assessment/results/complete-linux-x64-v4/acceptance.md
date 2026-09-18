# RC performance and resource acceptance

- Status: **ACCEPTED**
- Criteria: `rc-performance-resource-linux-x64-v2` (fixed 2026-09-16)
- Environment profile: `linux-x64-node22-chromium`
- Source commit: `944341903d5b85686a056d3218f4c33110d7d57b`
- Complete assessment: [summary](summary.json)

## Threshold checks

| Check | Observed | Requirement | Result |
| --- | ---: | ---: | --- |
| rust-core:performance:scale-logs-small-whole:initialization-p95-ms | 0.019126 | <= 1 | pass |
| rust-core:performance:scale-logs-small-whole:processing-p95-ms | 27.007543 | <= 350 | pass |
| rust-core:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2427247.8248021305 | >= 180000 | pass |
| rust-core:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 3739648 | <= 11534336 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.017683 | <= 1 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:processing-p95-ms | 125.68791100000001 | <= 1400 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2085753.4978045737 | >= 180000 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 3747840 | <= 11534336 | pass |
| python:performance:scale-logs-small-whole:initialization-p95-ms | 0.832936 | <= 2 | pass |
| python:performance:scale-logs-small-whole:processing-p95-ms | 27.499768 | <= 40 | pass |
| python:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2383801.9288017265 | >= 1600000 | pass |
| python:performance:scale-logs-small-whole:memory-pythonHeap-maximum-bytes | 75205 | <= 2097152 | pass |
| python:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 21442560 | <= 53477376 | pass |
| python:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.853734 | <= 2 | pass |
| python:performance:scale-logs-medium-fixed4096:processing-p95-ms | 115.543756 | <= 200 | pass |
| python:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2268872.0626322725 | >= 1400000 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-pythonHeap-maximum-bytes | 537596 | <= 2097152 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 21123072 | <= 53477376 | pass |
| node:performance:scale-logs-small-whole:initialization-p95-ms | 2.254962000000006 | <= 5 | pass |
| node:performance:scale-logs-small-whole:processing-p95-ms | 23.426551000000003 | <= 40 | pass |
| node:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2798277.9027096215 | >= 1700000 | pass |
| node:performance:scale-logs-small-whole:memory-nodeHeap-maximum-bytes | 7071368 | <= 17825792 | pass |
| node:performance:scale-logs-small-whole:memory-nodeRss-maximum-bytes | 66678784 | <= 168820736 | pass |
| node:performance:scale-logs-small-whole:memory-nodeExternal-maximum-bytes | 2289931 | <= 6291456 | pass |
| node:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 2.412786000000011 | <= 5 | pass |
| node:performance:scale-logs-medium-fixed4096:processing-p95-ms | 107.03277100000003 | <= 200 | pass |
| node:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2449287.2374573946 | >= 1500000 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeHeap-maximum-bytes | 21666160 | <= 54525952 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeRss-maximum-bytes | 93982720 | <= 234881024 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeExternal-maximum-bytes | 2321715 | <= 6291456 | pass |
| browser-wasm:performance:scale-logs-small-whole:initialization-p95-ms | 10.700000000011642 | <= 25 | pass |
| browser-wasm:performance:scale-logs-small-whole:processing-p95-ms | 41.20000000001164 | <= 50 | pass |
| browser-wasm:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 1591116.5048539191 | >= 1400000 | pass |
| browser-wasm:performance:scale-logs-small-whole:memory-browserJsHeap-maximum-bytes | 10000000 | <= 25165824 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 14.199999999982538 | <= 35 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:processing-p95-ms | 123.09999999997672 | <= 150 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2129601.9496348463 | >= 2000000 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:memory-browserJsHeap-maximum-bytes | 39600000 | <= 99614720 | pass |
| cli:performance:scale-logs-small-whole:initialization-p95-ms | 2.1946390000000093 | <= 6 | pass |
| cli:performance:scale-logs-small-whole:processing-p95-ms | 34.449126000000035 | <= 60 | pass |
| cli:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 1902922.0073681965 | >= 1100000 | pass |
| cli:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 3100672 | <= 8388608 | pass |
| cli:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 2.2328800000000086 | <= 6 | pass |
| cli:performance:scale-logs-medium-fixed4096:processing-p95-ms | 127.47920899999997 | <= 250 | pass |
| cli:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2056445.1415759886 | >= 1200000 | pass |
| cli:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 3166208 | <= 8388608 | pass |
