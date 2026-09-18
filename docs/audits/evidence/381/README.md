# Issue #381 — full and common (tiny) WebAssembly artifacts

[Audit archive](../../README.md) · [Epic #377](https://github.com/redact-secret/redact-secret/issues/377) · [Issue #381](https://github.com/redact-secret/redact-secret/issues/381) · [#378 baseline](../378/README.md) · [Profile contract](../../../decisions/2026-09-18-define-detector-profile-and-pack-contract.md)

Measured 2026-09-18 at commit `6bceee2c05f4838e9d9ede3f4bf617bf25ba4922`
(`workbench/381-full-tiny-wasm-artifacts`), with `crates/` and
`bindings/wasm/` clean. `tiny` is this issue's informal name. The artifact
implements the reviewed `common` profile, and this record calls it `common`
from here on.

This is a qualification experiment. It publishes nothing, adds no package
export, and authorizes no release. The `@redact-secret/wasm/common` manifest
export and the `@redact-secret/core/common` entry remain #382's work, in the
contract's delivery order.

## Result

| Question | Answer |
| --- | --- |
| Are there two real compiled artifacts? | Yes. They come from one crate: the default build is `full`, and `--no-default-features` builds `common`. No source is patched, and no runtime filtering happens inside one module. |
| Transfer-size saving | **12,222 B brotli (15.77%)**, 16,583 B gzip (17.2%), 56,354 B raw (20.02%) of `.wasm`. The ≈5.6 KB brotli glue is the same in both. |
| Scan-time saving (Chromium, #378 protocol) | Whole input (64 KiB): 30.30 → 9.60 ms, **3.2× faster**. Streaming (256 KiB in 4 KiB chunks): 116.35 → 20.50 ms, **5.7× faster**. Firefox and WebKit show 2.9–6.1×. |
| Initialization | No difference that can be told apart from noise on any engine. |
| Does `common` contain provider code? | No. Its `name` section references no `provider` detector module, and all 36 provider detectors' behavior is absent. |
| Does `full` change? | Findings do not change. `.wasm` is +140 B raw / −41 B brotli versus `main`, from one added export, `profile`. |
| Browser qualification | Both artifacts pass on Chromium 153, Firefox 155, and WebKit 26.6. |
| Recommendation | Keep `common` as a candidate supported surface, and let #382 qualify it. See the [decision gate](#decision-gate). |

## Files

| File | Contents | Produced by |
| --- | --- | --- |
| [`artifact-sizes.json`](artifact-sizes.json) | Per profile: `.wasm` and glue sizes (raw, gzip -9, brotli -11), SHA-256, toolchain, savings, and delta from the #378 source-patched estimate | `scripts/measure-wasm-profiles.mjs` |
| [`build-evidence.json`](build-evidence.json) | Per profile: linked `detectors::<module>` names classified as common, shared engine, or provider; export list; guard verdict | same |
| [`performance.json`](performance.json) | Median init, processing, and throughput per engine × workload × profile, with a pointer to each raw file | same |
| [`raw/<profile>/<engine>-<workload>.json`](raw/common/chromium-scale-logs-small-whole.json) | The full 10-run assessment result with samples, stddev, and provenance | `scripts/assessment-browser-performance.mjs` |
| [`browser-qualification-full.txt`](browser-qualification-full.txt), [`browser-qualification-common.txt`](browser-qualification-common.txt) | Every check on every engine for the measured artifacts | `scripts/qualify-browser-artifact.mjs` |

Reproduce:

```bash
npm run js:build
node scripts/measure-wasm-profiles.mjs --out-dir docs/audits/evidence/381 \
  --engine chromium --engine firefox --engine webkit
node scripts/qualify-browser-artifact.mjs --artifact-dir target/wasm-profiles/full
node scripts/qualify-browser-artifact.mjs --detector-profile common \
  --artifact-dir target/wasm-profiles/common
```

Two runs at this revision produced byte-identical `.wasm` files (same
SHA-256), so the builds are deterministic on this host.

## How the two artifacts are built

The mechanism follows `decision-define-detector-profile-and-pack-contract`:

- `bindings/wasm` has one additive, default-on Cargo feature, `full`. Under
  it, `lifecycle::build_registry` references
  `DetectorRegistry::with_built_in`. Without it, the function references only
  `DetectorRegistry::with_common_built_in`. The incremental session is
  selected the same way (`IncrementalSanitizer::with_policy_and_formatter`
  versus `with_common_built_in_policy_and_formatter`). Each build references
  exactly one constructor per path, chosen by `#[cfg]` rather than a runtime
  `match`. The core crate still has no Cargo features.
- `npm run wasm:build` is unchanged and emits `redact_secret_wasm*` into
  `bindings/wasm/pkg`. `npm run wasm:build:common` (`--detector-profile common`)
  emits `redact_secret_wasm_common*` into `bindings/wasm/pkg-common`. The
  distinct file names let a package ship both files side by side later.
- Both builds use one release profile (`lto = "fat"`, `codegen-units = 1`),
  rustc 1.98.1, and `wasm-bindgen` 0.2.128. No `wasm-opt` pass runs, the same
  as #378.
- Each artifact exports `profile()`, which returns `"full"` or `"common"`.

**A reachability bug the size check caught.** The first `common` build came
out *larger* than `full` (281,882 B). The binding's `createIncrementalSanitizer`
still called the `full` incremental constructor. So every `provider` detector
was linked, and the `common` artifact's streaming path ran `full` detection.
Routing that constructor through the profile too brought the artifact to
225,195 B. `scripts/measure-wasm-profiles.mjs` now fails on that regression,
and so does the browser check "an incremental session matches scanAndRedact".
A deliberate reintroduction of the bug fails both: the size returns to
281,882 B, and 59 fixtures disagree in the browser.

## Artifact size

| | `full` | `common` | Saved | Saved % |
| --- | --- | --- | --- | --- |
| `.wasm` raw | 281,549 B | 225,195 B | 56,354 B | 20.02% |
| `.wasm` gzip -9 | 96,415 B | 79,832 B | 16,583 B | 17.22% |
| `.wasm` brotli -11 | 77,485 B | 65,263 B | 12,222 B | 15.77% |
| glue `.js` raw / brotli | 29,548 / 5,571 B | 29,569 / 5,574 B | — | — |
| `.wasm` SHA-256 | `137934a8…54d6` | `d40ba652…14f9` | | |

Against #378's source-patched estimate, the real `full` is +203 B raw / +78 B
brotli and the real `common` is +316 B raw / +28 B brotli. That is within
0.15%, so the estimate method was sound. Against `main` (`4734490`), built the
same way, `full` is +140 B raw / −41 B brotli. Its exports gain `profile` and
lose nothing.

The engine floor (#378: 156,857 B raw with zero detectors) is 70% of
`common`'s raw size, so no detector profile can make the artifact much
smaller than `common` already is.

## Build evidence: the common artifact links no provider detector

Both binaries keep a WebAssembly `name` section. After link-time dead-code
removal, it lists every surviving function by its Rust path
([`build-evidence.json`](build-evidence.json)):

| Profile | `common`-pack modules | Shared engine | `provider` modules |
| --- | --- | --- | --- |
| `full` | `bearer_token`, `connection_string`, `generic_token`, `jwt`, `otpauth`, `private_key` | `text` | 24: `additional_providers`, `anthropic`, `atlassian`, `aws`, `azure_devops`, `cloudflare`, `datadog`, `discord`, `github`, `gitlab`, `grafana`, `linear`, `microsoft_entra`, `new_relic`, `notion`, `openai`, `pattern`, `sendgrid`, `sentry`, `shopify`, `slack`, `telegram`, `twilio`, `vault` |
| `common` | the same 6 | `text` | **none** |

`pattern` holds provider-shape primitives, and only provider modules use it,
so it counts as provider code. Both artifacts export the same 40 symbols.
`scripts/measure-wasm-profiles.mjs` turns this into a guard. It fails if
`common` is not smaller than `full`, links any provider module, lacks a
`common`-pack module, or exports a different surface.

## Behavior evidence

- **Committed `common` expectations.** The Rust core runs `common` over all
  1,212 evaluated canonical fixtures. The results are pinned in
  [`conformance/fixtures/common-profile-expectations.json`](../../../../conformance/fixtures/common-profile-expectations.json),
  which holds detector, type, confidence, action, and UTF-8 byte range, and
  never a value. `crates/secret-scan-core/tests/common_profile_corpus.rs`
  asserts that the file matches the core. It also asserts that every `common`
  finding comes from a `common` detector, and that each `common` detector
  emits identical candidates in `common` and `full` over the whole corpus
  (contract obligation 2).
- **What `common` changes relative to `full`:**

  | Outcome over 1,212 fixtures | Count |
  | --- | --- |
  | Identical findings | 805 (135 positive, 670 negative) |
  | A `full` positive that `common` does not detect | 348 (308 positive, 31 adversarial, 9 overlap fixtures). All are provider tokens, for example `digitalocean-token` 25, `openai-token` 24, `docker-token` 18, and `github-token` 16. |
  | A provider finding that falls back to `generic-token` | 59 (44 still `redact`, 15 become `warn`) |
  | A finding in `common` where `full` has none | **0** |
  | A `full` positive made only of `common`-detector findings that changes | **0** |

  This is the false-negative cost the contract describes. `common` adds no
  false positive on the corpus. Where no provider competitor exists, it
  behaves exactly like `full`.
- **The omitted detectors never run.** On the wasm crate, a bare synthetic
  AWS-shaped key is detected by `full` and not by `common`
  (`a_bare_provider_token_is_detected_only_by_the_full_profile`, run natively
  for both feature sets in CI). In the browser, every finding on both the whole-input and
  incremental paths must come from a detector in the artifact's profile.

## Performance

The protocol is unchanged from #378. `scripts/assessment-browser-performance.mjs`
loads each artifact through the public `@redact-secret/core` facade, whose
`@redact-secret/wasm` import is aliased to that artifact's glue. Each run uses
a fresh browser context, with 10 runs. The workloads are
`scale-logs-small-whole` (64 KiB, one call) and `scale-logs-medium-fixed4096`
(256 KiB fed as 4 KiB chunks to an incremental session). Chromium is the
#378-comparable column. Firefox and WebKit were added here. Values are
medians in ms, with processing stddev in parentheses.

| Engine | Workload | Init `full` | Init `common` | Processing `full` | Processing `common` | Speed-up |
| --- | --- | --- | --- | --- | --- | --- |
| Chromium 153 | whole 64 KiB | 6.50 | 5.05 | 30.30 (2.67) | 9.60 (0.68) | 3.2× |
| Chromium 153 | streaming 256 KiB | 11.35 | 11.20 | 116.35 (9.02) | 20.50 (0.89) | 5.7× |
| Firefox 155 | whole 64 KiB | 27.5 | 22.5 | 38.0 (3.01) | 9.5 (1.36) | 4.0× |
| Firefox 155 | streaming 256 KiB | 36.0 | 24.0 | 186.0 (32.15) | 30.5 (9.76) | 6.1× |
| WebKit 26.6 | whole 64 KiB | 14.0 | 13.5 | 26.0 (1.49) | 9.0 (1.42) | 2.9× |
| WebKit 26.6 | streaming 256 KiB | 13.5 | 17.5 | 93.0 (12.48) | 23.5 (3.43) | 4.0× |

Processing gaps are 4.8–11.4 standard deviations of the `full` samples on
every engine, so they are real. Initialization gaps are not. Across the two runs made for this
record, Chromium's whole-input init ordered `full` and `common` both ways
(4.85 vs 5.10, then 6.50 vs 5.05). WebKit's streaming init has `common`
slower. Init is dominated by fetching and instantiating the module plus
building the registry, and 12 KB less brotli does not move it measurably on
a local server.

Do not compare absolute milliseconds across records. Chromium `full`
processing here (30.30 ms whole, 116.35 ms streaming) is 19–41% above #378's
(21.55 / 97.75 ms). An earlier run at this revision measured 25.25 / 115.75
ms. The revision also carries the detector work merged since #378. The
measurement is the `full`/`common` ratio within one run.

## Browser qualification

`scripts/qualify-browser-artifact.mjs` ran both measured artifacts on
Chromium 153.0.8010.12, Firefox 155.0, and WebKit 26.6 (Playwright 1.63.0).
All checks passed: 33 per engine for `full` (artifact and package pages) and
14 per engine for `common`
([logs](browser-qualification-common.txt)). The artifact page gained three
checks, which run for both profiles:

- `profile()` reports the compiled profile;
- every finding comes from a detector in the profile;
- an incremental session fed each positive fixture in two chunks equals
  `scanAndRedact` on the same artifact.

The `common` run checks against the committed `common` expectations rather
than the `full` ones. The package page, which drives the published
`@redact-secret/core` API, is skipped for `common`. `@redact-secret/core` has
no `common` entry yet, so that page would load `full` (#382).

## Distribution complexity

What this change adds, and what a supported `common` surface would still add:

| Item | Now (#381) | For a supported surface (#382) |
| --- | --- | --- |
| Build | One feature on one leaf crate; one extra `wasm:build:common` script | Release qualification must build both, and the `wasm-web` artifact must carry both |
| CI | Clippy, native tests, and wasm32 tests for `--no-default-features` in `ci.yml` | A `--detector-profile common` browser qualification row per engine |
| Conformance | A committed 100 KB expectation file. **Every canonical-corpus change now also needs `REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1` and a reviewed diff**, because the Rust test fails otherwise | Node `/common` qualified against the same file |
| Package | None | `@redact-secret/wasm` `exports` gains `./common`; `@redact-secret/core` gains `./common`, `PROFILE`, and a mismatch check; ≈255 KB more install size per consumer |
| Documentation | This record, `docs/qualification.md`, `bindings/wasm/README.md` | A user-facing opt-in section that states the false-negative tradeoff |
| Release | None | Inventory rows for the second artifact (profile, SHA-256, raw and brotli size) |

The biggest ongoing cost is the expectation file. Beta.4 and beta.5 detector
work changes the canonical corpus often, and each such change now needs one
regeneration command and a review of its `common` diff.

## Decision gate

The issue asks whether the savings are meaningful enough to justify a second
published artifact, or whether the mechanism should stay internal.

- **Transfer size: modest.** 12.2 KB brotli is 15.8% of the `.wasm`, or about
  15% of a ≈83 KB `.wasm` plus glue download. The engine floor caps what any
  profile can save. By itself this would be a weak case.
- **Scan cost: large.** A 3–6× lower processing time on every engine,
  4.8σ or more apart, is the stronger effect, and it was not visible in #378's size-first
  framing. For preventive, keystroke-adjacent browser UX, this is the latency
  budget that matters. `common` streams 256 KiB in ≈20 ms where `full` takes
  ≈116 ms (Chromium).
- **Behavior cost: bounded and well characterized.** There are no new false
  positives, and findings are identical where no provider competitor exists.
  Provider tokens are lost unless a credential-bearing context catches them.

**Recommendation:** the savings are meaningful mainly because of scan cost,
so keep `common` as a candidate supported product surface. #382 should
qualify it and add the package exports. That work should keep the
expectation-file regeneration cheap and visible, for example by naming it in
the canonical-corpus contribution checklist. Publish it opt-in only, with
the false-negative tradeoff stated, and keep `full` the default everywhere.
If #377 judges scan latency irrelevant to its consumers, the size case alone
(≈12 KB) does not justify a second published artifact. In that case, keep
the mechanism internal: this change already gives the Rust crate and future
bindings the compile-time path without publishing anything.

## Measurement provenance

| Item | Value |
| --- | --- |
| Source revision | `6bceee2c05f4838e9d9ede3f4bf617bf25ba4922`, with `crates/` and `bindings/wasm/` clean |
| rustc / cargo | 1.98.1 (`48a229cea` 2026-09-01) / 1.98.1 (`797e8a9bc` 2026-08-05) |
| `wasm-bindgen` CLI and crate | 0.2.128 |
| `[profile.release]` | `codegen-units = 1`, `lto = "fat"` |
| `wasm-opt` | not invoked |
| Node.js / Playwright | v22.16.0 / 1.63.0 |
| Engines | Chromium 153.0.8010.12, Firefox 155.0, WebKit 26.6 |
| Host | macOS 26.5.2 (`darwin-25.5.0`), `arm64` |
| Workload corpus hash | `b4db2cd22b4c008c9d63789df8ca2e21e697a21a84699466ea5f96c89d8e2806` (`assessment/fixtures/workload-profiles.json`) |

## What this evidence does not claim

It does not measure over a network, on a cold HTTP cache, or on a slower
device, where 12 KB and instantiate time could weigh differently. It does not
repeat runs across hosts or days. It does not measure the Node addon, which
the contract gives `common` by runtime registry selection and which is #382's
scope, or Python and the CLI, which are `full` only. It does not qualify the
`@redact-secret/core` facade on the `common` artifact. It publishes or
exports nothing.
