# Issue #378 — per-detector and profile artifact/runtime cost baseline

[Audit archive](../../README.md) · [Epic #377](https://github.com/redact-secret/redact-secret/issues/377) · [Issue #378](https://github.com/redact-secret/redact-secret/issues/378)

Measured 2026-09-18 at commit `8131459fb7f26658c95a1c7eb09f96bf7e141443`
(`workbench/378-detector-artifact-cost`, branched from `main`), working tree
otherwise clean. This is the reproducible artifact/runtime baseline #377
asked for before any packaging-architecture change; it changes no detector,
no public API, and builds no shipped package. It answers what the current
default 42-detector composition costs, and what removing detectors would
plausibly save, using real compiled artifacts rather than Rust source size
as a proxy.

## Files

| File | Contents | Produced by |
| --- | --- | --- |
| [`compositions.json`](compositions.json) | The canonical 42 detector ids in registration order, the `structuralIds`/`groups` partition, and the exact included/excluded id list and count for each of the 8 measured variants. | `scripts/measure-detector-cost.mjs --aggregate` |
| [`artifact-sizes.json`](artifact-sizes.json) | Native raw size and WASM raw/gzip/brotli/glue-JS size per variant. | `scripts/measure-detector-cost.mjs --aggregate` |
| [`raw/<variant>/summary.json`](raw/full/summary.json) | Per-variant composition + size summary (one per variant; also feeds the two files above). | `scripts/measure-detector-cost.mjs --variant <name>` |
| [`raw/<variant>/cli-whole.json`](raw/full/cli-whole.json) | Native CLI init + whole-input (`scale-logs-small-whole`, 64 KiB) processing/throughput, 10 runs, full sample array. | `scripts/assessment-cli-performance.mjs` |
| [`raw/<variant>/wasm-whole.json`](raw/full/wasm-whole.json) | Chromium/WASM init + whole-input processing/throughput, 10 runs. | `scripts/assessment-browser-performance.mjs` |
| [`raw/<variant>/wasm-fixed4096.json`](raw/full/wasm-fixed4096.json) | Chromium/WASM streaming/incremental processing/throughput (`scale-logs-medium-fixed4096`: 256 KiB fed as 4096-byte chunks), 10 runs. | `scripts/assessment-browser-performance.mjs` |

The measurement tool itself is [`scripts/measure-detector-cost.mjs`](../../../../scripts/measure-detector-cost.mjs)
(tested by [`scripts/tests/measure-detector-cost.test.mjs`](../../../../scripts/tests/measure-detector-cost.test.mjs),
run via `npm run detector-cost:test`, not part of `npm run ci` — same
occasional-use category as `benchmark:candidate:test`).

## How a variant is built

`built_in_detectors()` in `crates/secret-scan-core/src/detectors/mod.rs`
lists exactly one constructor per detector, one per line, in the same order
as the canonical id list asserted by that file's own
`built_in_order_matches_the_typescript_oracle` test. To build a variant, the
tool comments out the vec entries at the positions of the excluded ids,
verifying first that the vec's entry count matches the canonical id count
(so a future detector addition/removal fails loudly instead of silently
mismatching positions), builds `redact-secret-cli` (`cargo build --release
--locked`) and the browser artifact (`scripts/build-browser-artifact.mjs`,
itself `cargo build --release --target wasm32-unknown-unknown` +
`wasm-bindgen`), measures, and unconditionally restores the file with `git
checkout --` — verified clean (`git status --porcelain crates/`) before
starting the next variant. No shipped source file, Cargo feature, or public
API changed as a result of this work; every variant's exact diff is fully
reconstructible from its excluded-id list in `compositions.json`.

Detector-dependent code becomes eligible for removal from the final
compiled artifact because `[profile.release]` in the workspace `Cargo.toml`
already sets `codegen-units = 1` and `lto = "fat"` (no `strip`/`panic`
override); whole-program LTO lets the linker discard detector code that
becomes unreachable once its constructor call is removed, without a
separate `wasm-opt` pass (none is on `PATH` in this environment; the build
pipeline doesn't invoke one).

## Compositions measured

8 variants, all built and measured for real (no fabricated numbers). Full
id lists are in [`compositions.json`](compositions.json); this table gives
counts and rationale only.

| Variant | Detectors | Rationale |
| --- | --- | --- |
| `full` | 42 | Default/current shipped composition — baseline. |
| `engine-only` | 0 | All 42 excluded. Isolates fixed registry/pipeline/binding overhead from detector-dependent growth (acceptance criterion 7). |
| `tiny-common` | 6 | Keeps only the structural/contextual detectors (`private-key`, `jwt`, `bearer-token`, `connection-string`, `otpauth-uri`, `generic-token`) that aren't tied to one vendor's format — the epic's "tiny/common" candidate. |
| `minus-ai` | 39 | Full minus `openai-token`, `anthropic-token`, `huggingface-token` (3). |
| `minus-cloud` | 28 | Full minus 14: `aws-access-key`, `vault-token`, `cloudflare-token`, `digitalocean-token`, `supabase-token`, `vercel-token`, `google-api-key`, `microsoft-entra-client-secret`, `datadog-api-key`, `datadog-application-key`, `grafana-service-account-token`, `grafana-cloud-access-policy-token`, `new-relic-user-api-key`, `new-relic-license-key`. |
| `minus-devtools` | 36 | Full minus 6 (source-control/developer tooling): `github-token`, `gitlab-token`, `azure-devops-personal-access-token`, `notion-token`, `atlassian-api-token`, `linear-token`. |
| `minus-pkg-registry` | 39 | Full minus 3: `pypi-token`, `docker-token`, `npm-token`. |
| `minus-saas` | 32 | Full minus 10: `shopify-token`, `stripe-token`, `slack-token`, `sendgrid-token`, `twilio-auth-token`, `twilio-api-key-secret`, `telegram-bot-token`, `discord-bot-token`, `sentry-user-auth-token`, `sentry-org-auth-token`. |

**These groupings are illustrative measurement buckets for this baseline
only — not a proposed pack taxonomy.** A handful of ids are genuinely
ambiguous (`vault-token` is secrets-management infra grouped under
"cloud"; `google-api-key` spans many Google products and is grouped under
"cloud" rather than "ai"; `notion-token`/`linear-token` are workspace/issue
tools grouped under "devtools" rather than "saas"). Which detectors belong
to which named pack, if any, is issue #379's contract to define.

## Artifact size (raw measurement, see `artifact-sizes.json`)

| Variant | Detectors | WASM raw | WASM gzip -9 | WASM brotli -11 | WASM glue JS | Native raw |
| --- | --- | --- | --- | --- | --- | --- |
| `full` | 42 | 281,346 B | 96,324 B | 77,407 B | 28,873 B | 631,200 B |
| `engine-only` | 0 | 156,857 B | 54,687 B | 45,183 B | 28,873 B | 496,928 B |
| `tiny-common` | 6 | 224,879 B | 79,724 B | 65,235 B | 28,873 B | 570,656 B |
| `minus-ai` | 39 | 277,997 B | 95,538 B | 76,909 B | 28,873 B | 630,592 B |
| `minus-cloud` | 28 | 262,971 B | 91,398 B | 74,012 B | 28,873 B | 611,600 B |
| `minus-devtools` | 36 | 271,791 B | 93,366 B | 75,263 B | 28,873 B | 612,624 B |
| `minus-pkg-registry` | 39 | 280,643 B | 96,036 B | 77,332 B | 28,873 B | 631,168 B |
| `minus-saas` | 32 | 265,980 B | 91,920 B | 74,514 B | 28,873 B | 611,888 B |

The glue JS file is identical across every variant (it doesn't reference
detectors), confirming it isn't a detector-sensitive artifact.

**Fixed vs. detector-dependent split (criterion 7).** `full` − `engine-only`
attributes 124,489 B raw / 41,637 B gzip / 32,224 B brotli / 134,272 B
native to the 42 built-in detectors combined — an average of ≈2,964 B raw
(≈991 B gzip, ≈767 B brotli) per detector, ≈3,197 B native per detector.
`engine-only`'s own size (156,857 B raw WASM, 496,928 B native) is the
fixed registry/pipeline/binding/runtime floor with zero detectors compiled
in.

**`tiny-common` vs. `full`.** Saves 56,467 B raw (20.1%), 16,600 B gzip
(17.2%), 12,172 B brotli (15.7%), 60,544 B native (9.6%) relative to `full`.
Its own marginal cost over `engine-only` is 68,022 B raw for 6 detectors
(≈11,337 B/detector) — well above the 42-detector average, i.e. the
structural/contextual detectors (entropy scoring, contextual-assignment
heuristics, multi-format grammars) are individually heavier in compiled
code than the average single-vendor pattern detector.

**Per-group deltas from `full`** (bytes saved by removing that group; the
groups are not disjoint from `tiny-common`'s savings, they overlap with the
36 non-structural detectors):

| Group removed | Detectors removed | WASM raw saved | % of `full` raw | ≈ B/detector |
| --- | --- | --- | --- | --- |
| `minus-pkg-registry` | 3 | 703 B | 0.25% | ≈234 |
| `minus-ai` | 3 | 3,349 B | 1.19% | ≈1,116 |
| `minus-devtools` | 6 | 9,555 B | 3.40% | ≈1,593 |
| `minus-saas` | 10 | 15,366 B | 5.46% | ≈1,537 |
| `minus-cloud` | 14 | 18,375 B | 6.53% | ≈1,313 |

Size deltas are broadly proportional to group size (larger groups save
more), with per-detector averages inside a roughly 2–4x band across groups
— size cost does not look concentrated in one or two outlier detectors at
this composition.

## Runtime cost (raw measurement; median of 10 runs, see `raw/<variant>/*.json` for full samples/stddev)

| Variant | Native init (ms) | Native whole-input processing (ms, process-inclusive) | WASM init (ms) | WASM whole-input processing (ms) | WASM streaming/fixed-4096 processing (ms) |
| --- | --- | --- | --- | --- | --- |
| `full` | 2.80 | 25.98 | 4.35 | 21.55 | 97.75 |
| `engine-only` | 2.27 | 2.68 | 3.95 | 0.35 | 4.00 |
| `tiny-common` | 2.83 | 5.75 | 4.20 | 7.05 | 18.10 |
| `minus-ai` | 2.40 | 22.45 | 4.50 | 20.95 | 130.45 |
| `minus-cloud` | 4.60 | 32.96 | 5.35 | 16.10 | 59.45 |
| `minus-devtools` | 6.26 | 34.66 | 5.95 | 24.50 | 113.10 |
| `minus-pkg-registry` | 3.03 | 24.42 | 3.80 | 18.30 | 110.15 |
| `minus-saas` | 3.30 | 25.09 | 5.00 | 19.30 | 73.00 |

Whole-input profile: `scale-logs-small-whole`, a 64 KiB single-call scan.
Streaming profile: `scale-logs-medium-fixed4096`, a 256 KiB input fed as
4 KiB chunks through the incremental sanitizer. Native has no streaming
number: the CLI binary exposes no incremental entry point to drive from a
subprocess boundary (`scripts/assessment-cli-performance.mjs` only
measures whole-input); the WASM/browser surface is the one that matters
most for #377 anyway.

**Fixed overhead (criterion 7).** `engine-only`'s native processing
(2.68 ms) is only ≈0.4 ms above its own init (2.27 ms) on a 64 KiB input —
the fixed per-call pipeline overhead with zero detectors is small. Every
detector-bearing variant's processing time (16–35 ms native whole-input,
7–25 ms WASM whole-input, 18–130 ms WASM streaming) sits far above that
floor, so almost all processing latency in any real composition comes from
running detectors over the input, not from registry/binding machinery.

**Between detector-bearing variants, deltas are not clean.** `minus-devtools`
(36 detectors) shows *higher* WASM whole-input processing (24.50 ms) than
`full` (42 detectors, 21.55 ms); `minus-ai` (39 detectors) shows *higher*
streaming processing (130.45 ms, stddev 12.83 ms — see
`raw/minus-ai/wasm-fixed4096.json`) than `full` (97.75 ms, stddev 4.56 ms).
These are single-host, 10-run, single-process/browser-context measurements;
run-to-run variance is comparable in magnitude to the deltas between
adjacent-sized compositions once at least a handful of detectors are
present. `tiny-common`'s runtime numbers are the one detector-bearing
composition that reads as unambiguously and consistently lower across
every column, consistent with it running far fewer detector matchers per
input.

## Measurement provenance

| Item | Value |
| --- | --- |
| Source revision | `8131459fb7f26658c95a1c7eb09f96bf7e141443` (branch point of `workbench/378-detector-artifact-cost`); working tree clean at that revision, each variant is a temporary, always-reverted patch to one file |
| rustc / cargo | 1.98.1 (`48a229cea`, 2026-09-01) / 1.98.1 (`797e8a9bc`, 2026-08-05) |
| `wasm-bindgen` CLI/crate | 0.2.128 (matched; the build tool refuses to run on a mismatch) |
| `wasm-opt` | not on `PATH` / not invoked — sizing reflects `rustc`+LTO only, no post-link WASM optimizer pass |
| `[profile.release]` | `codegen-units = 1`, `lto = "fat"`; no `strip`/`panic` override |
| Node.js | v22.16.0 |
| Browser engine | Chromium 153.0.8010.12 via Playwright 1.63.0 (chromium only; firefox/webkit not run) |
| Host OS / CPU | macOS 26.5.2 (`darwin-25.5.0`) / `arm64` |
| Runs per measurement | 10 (both native and WASM harnesses); see each raw JSON's `performance.*.samples` for the full array and `standardDeviation` |
| Workload profiles | `scale-logs-small-whole` (whole-input, 64 KiB) and `scale-logs-medium-fixed4096` (streaming, 256 KiB in 4 KiB chunks), from `assessment/fixtures/workload-profiles.json`, hash recorded per-file as `provenance.corpusHash` |

## Answering #377's decision-use questions (observations only — no threshold, no recommendation)

1. **Is detector growth materially increasing WASM transfer size?** The
   42-detector default is 281,346 B raw / 77,407 B brotli; the zero-detector
   floor is 156,857 B raw / 45,183 B brotli. Detectors account for ≈44% of
   raw WASM size and ≈42% of brotli size in the current composition, at an
   average of ≈767 B brotli per detector. Whether that average, applied to
   future detector growth, is "material" is a judgment #379 makes; the
   measurement is that it is not negligible relative to the fixed floor.
2. **Is it materially increasing initialization or scan cost?** Init cost
   differences across variants (2.3–6.3 ms native, 3.8–6.0 ms WASM) are
   small in absolute terms and not cleanly ordered by detector count.
   Whole-input/streaming processing cost is clearly detector-cost-dominated
   (§ above) but the marginal cost *between* nonzero compositions is noisy
   at this sample size (10 runs, one input per profile) — this baseline
   does not resolve whether per-detector scan cost scales in a way that
   would matter at 2x or 5x today's detector count.
3. **Does a tiny/common composition save enough to justify extra
   distribution complexity?** `tiny-common` saves 15.7–20.1% of WASM size
   and shows the only unambiguous runtime improvement across every profile.
   Whether that magnitude justifies the packaging/versioning/documentation
   cost of a second distributed artifact is #379's trade-off to make
   explicit, not this issue's.
4. **Which groupings, if any, show enough savings to justify a named
   pack?** By WASM raw size, `cloud` (6.53%) and `saas` (5.46%) are the
   largest single-group savings measured; `pkg-registry` (0.25%) is
   negligible. None of the five groups' runtime deltas are distinguishable
   from noise at this sample size. This baseline does not recommend a pack
   boundary; it reports which of the five illustrative groupings currently
   carry the most removable size.

## What this evidence does not claim

It does not set or imply a pass/fail size or latency threshold. It does not
propose a pack taxonomy or compatibility contract (#379). It does not
measure firefox, webkit, the Node native addon, or the Python binding. It
does not repeat measurements across multiple hosts, days, or process
priorities to characterize variance beyond the 10-run stddev each raw file
reports — a single noisy host run is possible and not distinguishable from
a real effect at the smaller deltas above. It does not measure any input
size other than the two workload profiles used elsewhere in this repo's
assessment suite (64 KiB whole, 256 KiB streamed). It does not change, add,
or remove any shipped detector, Cargo feature, or public API; every
variant's source patch is reverted before the next variant builds and
before this evidence was committed (`git status --porcelain crates/` was
verified empty).
