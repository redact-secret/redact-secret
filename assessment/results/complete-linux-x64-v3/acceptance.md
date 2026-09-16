# RC performance and resource acceptance

- Status: **ACCEPTED**
- Criteria: `rc-performance-resource-linux-x64-v2` (fixed 2026-09-16)
- Environment profile: `linux-x64-node22-chromium`
- Source commit: `9359f59596f03443254f662db60d553b0610809e`
- Complete assessment: [summary](summary.json)

## Threshold checks

| Check | Observed | Requirement | Result |
| --- | ---: | ---: | --- |
| rust-core:performance:scale-logs-small-whole:initialization-p95-ms | 0.038417999999999994 | <= 1 | pass |
| rust-core:performance:scale-logs-small-whole:processing-p95-ms | 173.138608 | <= 350 | pass |
| rust-core:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 378621.50306764623 | >= 180000 | pass |
| rust-core:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 4612096 | <= 11534336 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.037036 | <= 1 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:processing-p95-ms | 751.595132 | <= 1400 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 348796.83068516734 | >= 180000 | pass |
| rust-core:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 4444160 | <= 11534336 | pass |
| python:performance:scale-logs-small-whole:initialization-p95-ms | 0.92975 | <= 2 | pass |
| python:performance:scale-logs-small-whole:processing-p95-ms | 18.330298 | <= 40 | pass |
| python:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 3576264.8266820326 | >= 1600000 | pass |
| python:performance:scale-logs-small-whole:memory-pythonHeap-maximum-bytes | 75205 | <= 2097152 | pass |
| python:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 20893696 | <= 53477376 | pass |
| python:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 0.949551 | <= 2 | pass |
| python:performance:scale-logs-medium-fixed4096:processing-p95-ms | 83.640968 | <= 200 | pass |
| python:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 3134277.451212664 | >= 1400000 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-pythonHeap-maximum-bytes | 537596 | <= 2097152 | pass |
| python:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 21127168 | <= 53477376 | pass |
| node:performance:scale-logs-small-whole:initialization-p95-ms | 2.372336000000004 | <= 5 | pass |
| node:performance:scale-logs-small-whole:processing-p95-ms | 19.612752999999998 | <= 40 | pass |
| node:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 3342417.048743744 | >= 1700000 | pass |
| node:performance:scale-logs-small-whole:memory-nodeHeap-maximum-bytes | 7071840 | <= 17825792 | pass |
| node:performance:scale-logs-small-whole:memory-nodeRss-maximum-bytes | 66703360 | <= 168820736 | pass |
| node:performance:scale-logs-small-whole:memory-nodeExternal-maximum-bytes | 2289931 | <= 6291456 | pass |
| node:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 2.479997999999995 | <= 5 | pass |
| node:performance:scale-logs-medium-fixed4096:processing-p95-ms | 93.814144 | <= 200 | pass |
| node:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2794397.399181087 | >= 1500000 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeHeap-maximum-bytes | 21641432 | <= 54525952 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeRss-maximum-bytes | 96038912 | <= 234881024 | pass |
| node:performance:scale-logs-medium-fixed4096:memory-nodeExternal-maximum-bytes | 2321564 | <= 6291456 | pass |
| browser-wasm:performance:scale-logs-small-whole:initialization-p95-ms | 11.899999999965075 | <= 25 | pass |
| browser-wasm:performance:scale-logs-small-whole:processing-p95-ms | 20.099999999976717 | <= 50 | pass |
| browser-wasm:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 3261393.0348296487 | >= 1400000 | pass |
| browser-wasm:performance:scale-logs-small-whole:memory-browserJsHeap-maximum-bytes | 10000000 | <= 25165824 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 15.200000000011642 | <= 35 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:processing-p95-ms | 66.40000000002328 | <= 150 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 3948102.4096371694 | >= 2000000 | pass |
| browser-wasm:performance:scale-logs-medium-fixed4096:memory-browserJsHeap-maximum-bytes | 39600000 | <= 99614720 | pass |
| cli:performance:scale-logs-small-whole:initialization-p95-ms | 2.473308000000003 | <= 6 | pass |
| cli:performance:scale-logs-small-whole:processing-p95-ms | 27.976751000000007 | <= 60 | pass |
| cli:performance:scale-logs-small-whole:throughput-minimum-bytes-per-second | 2343159.861557905 | >= 1100000 | pass |
| cli:performance:scale-logs-small-whole:memory-processRss-maximum-bytes | 3039232 | <= 8388608 | pass |
| cli:performance:scale-logs-medium-fixed4096:initialization-p95-ms | 2.813591000000031 | <= 6 | pass |
| cli:performance:scale-logs-medium-fixed4096:processing-p95-ms | 106.94901900000002 | <= 250 | pass |
| cli:performance:scale-logs-medium-fixed4096:throughput-minimum-bytes-per-second | 2451205.279405134 | >= 1200000 | pass |
| cli:performance:scale-logs-medium-fixed4096:memory-processRss-maximum-bytes | 3084288 | <= 8388608 | pass |
