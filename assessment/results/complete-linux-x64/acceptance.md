# RC performance and resource acceptance

- Status: **ACCEPTED**
- Criteria: `rc-performance-resource-linux-x64-v1` (fixed 2026-09-15)
- Environment profile: `linux-x64-node22-chromium`
- Source commit: `9ff702001342ff84acdde8ad9acdec396572a15e`
- Complete assessment: [summary](summary.json)

## Threshold checks

| Check | Observed | Requirement | Result |
| --- | ---: | ---: | --- |
| rust-core:performance:scale-logs-small-whole:initialization-p95-ms | 0.047329 | <= 1 | pass |
| rust-core:performance:scale-logs-small-whole:processing-p95-ms | 174.190752 | <= 350 | pass |
| rust-core:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 376334.5599426541 | >= 180000 | pass |
| rust-core:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 4587520 | <= 11534336 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.031779999999999996 | <= 1 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:processing-p95-ms | 697.4549450000001 | <= 1400 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 375872.3081388433 | >= 180000 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 4493312 | <= 11534336 | pass |
| python:performance:scale-logs-small-whole:initialization-p95-ms | 0.905756 | <= 2 | pass |
| python:performance:scale-logs-small-whole:processing-p95-ms | 19.981668 | <= 40 | pass |
| python:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 3280707.0961243077 | >= 1600000 | pass |
| python:performance:scale-logs-small-whole:memory-pythonHeap-maximum-bytes | 75205 | <= 2097152 | pass |
| python:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 20799488 | <= 53477376 | pass |
| python:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.997039 | <= 2 | pass |
| python:performance:scale-logs-medium-fixed4096:processing-p95-ms | 88.412317 | <= 200 | pass |
| python:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2965129.847236104 | >= 1400000 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-pythonHeap-maximum-bytes | 537596 | <= 2097152 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 21135360 | <= 53477376 | pass |
| node:performance:scale-logs-small-whole:initialization-p95-ms | 2.388319999999993 | <= 5 | pass |
| node:performance:scale-logs-small-whole:processing-p95-ms | 19.157061999999996 | <= 40 | pass |
| node:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 3421923.466134839 | >= 1700000 | pass |
| node:performance:scale-logs-small-whole:memory-nodeHeap-maximum-bytes | 7069608 | <= 17825792 | pass |
| node:performance:scale-logs-small-whole:memory-nodeRss-maximum-bytes | 67485696 | <= 168820736 | pass |
| node:performance:scale-logs-small-whole:memory-nodeExternal-maximum-bytes | 2289931 | <= 6291456 | pass |
| node:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 2.460284999999999 | <= 5 | pass |
| node:performance:scale-logs-medium-fixed4096:processing-p95-ms | 86.32608700000003 | <= 200 | pass |
| node:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 3036787.7093745708 | >= 1500000 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeHeap-maximum-bytes | 21656288 | <= 54525952 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeRss-maximum-bytes | 93880320 | <= 234881024 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeExternal-maximum-bytes | 2321625 | <= 6291456 | pass |
| browser-wasm:performance:scale-logs-small-whole:initialization-p95-ms | 11.900000000023283 | <= 25 | pass |
| browser-wasm:performance:scale-logs-small-whole:processing-p95-ms | 22.600000000034925 | <= 50 | pass |
| browser-wasm:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2900619.4690220663 | >= 1400000 | pass |
| browser-wasm:performance:scale-logs-small-whole:memory-browserJsHeap-maximum-bytes | 10000000 | <= 25165824 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 15.399999999965075 | <= 35 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:processing-p95-ms | 65.20000000001164 | <= 150 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 4020766.8711649263 | >= 2000000 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:memory-browserJsHeap-maximum-bytes | 39600000 | <= 99614720 | pass |
| cli:performance:scale-logs-small-whole:initialization-p95-ms | 2.7157459999999958 | <= 6 | pass |
| cli:performance:scale-logs-small-whole:processing-p95-ms | 27.891756999999984 | <= 60 | pass |
| cli:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2350300.126306135 | >= 1100000 | pass |
| cli:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 3088384 | <= 8388608 | pass |
| cli:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 2.5969520000000017 | <= 6 | pass |
| cli:performance:scale-logs-medium-fixed4096:processing-p95-ms | 102.13445000000002 | <= 250 | pass |
| cli:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2566753.920934611 | >= 1200000 | pass |
| cli:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 3121152 | <= 8388608 | pass |
