# Edge runtime support matrix

Generated from `docs/reference/edge-runtime-matrix.json` by
`python3 -B scripts/generate-edge-runtime-matrix.py`. The initial target is
Cloudflare Workers; other runtimes need their own observed consumer artifact.

| Runtime | Status | Qualification scope | Evidence and limits |
| --- | --- | --- | --- |
| Cloudflare Workers | `qualified` | Local workerd, full/common profiles, PII off/on; installed package receipts are required by new full qualification runs. | [baseline qualification run](https://github.com/redact-secret/redact-secret/actions/runs/37765743383). Source `5fddf1a60d0297f0914e4b15c42a33c90a3d8fdf`. Local engine evidence, no Cloudflare account deployment or measured isolate memory. Fresh receipts live in each artifact inventory. |
| Vercel Edge | `unsupported` | Reference engine requires an import-free consumer build transform. | [accepted investigation](decisions/2026-09-19-verify-edge-runtimes.md). Production consumer build output remains unqualified; no edge-light loader. |
| Deno Deploy / Bun / Fastly | `not-evaluated` | Candidate workstreams outside the initial target. | [scope #1000](https://github.com/redact-secret/redact-secret/issues/1000). No support claim or runtime-specific artifact evidence. |

## Status meanings

**`qualified`**: A named artifact revision passed the documented real-runtime qualification scope. This does not imply deployment-account, cost, or every-platform qualification.

**`experimentally-working`**: A runtime smoke worked but the exact-artifact qualification record is incomplete.

**`unsupported`**: A verified blocker exists and no qualified consumer loading path ships.

**`not-evaluated`**: No runtime-specific exact-artifact result is available.

## Reproduction and measurement boundary

See [qualification](qualification.md#cloudflare-workers-and-vercel-edge-decision-verify-edge-runtimes)
for packing, installation, and the four real-workerd checks. Every new full
qualification inventory requires matching source, tool versions, package digests,
and selected WASM digests. Browser success alone does not qualify an edge runtime.

Reports include selected WASM raw/gzip size, first initialization wall time, and
21 warm batches of 100 `scanAndRedact` calls, normalized per call, on the named
synthetic fixture, with exact UTF-8
byte and UTF-16 code-unit sizes. Zero timing samples may be below clock resolution.
Offline Wrangler dry-run records the qualification worker's JS/WASM module hashes
and raw/gzip sums, including smoke-check code. These are raw observations, not
every consumer's bundle, cold process startup, CPU budgets, or memory measurements.
Timers describe local Wrangler, not deployed CPU time (deployed timers advance
after I/O). Workerd exposes
no worker memory counter; memory remains unavailable. Bundle/startup/scan budget
judgements and retained measurement evidence belong in `redact-secret-benchmarks`.
