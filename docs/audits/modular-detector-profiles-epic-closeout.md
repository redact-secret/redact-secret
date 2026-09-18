# Modular detector profiles epic closeout

[Documentation home](../README.md) · [Audit archive](README.md)

- Issue: [#377](https://github.com/redact-secret/redact-secret/issues/377).
- Reviewed on: 2026-09-18, at commit `3bac3db` (`main`, after PR #400).
- Status: **COMPLETED EVIDENCE CLOSEOUT; NO RELEASE AUTHORIZATION.**

This note closes the epic by mapping each of its seven completion criteria to
the child issue that delivered it and the evidence that verifies it. All five
child issues are closed:

| Child issue | Delivered | Evidence |
| --- | --- | --- |
| [#378](https://github.com/redact-secret/redact-secret/issues/378) | Artifact/runtime cost baseline for the current 42-detector `full` composition and 7 illustrative alternative compositions | [`docs/audits/evidence/378/README.md`](evidence/378/README.md) |
| [#379](https://github.com/redact-secret/redact-secret/issues/379) | The reviewed detector-profile and pack contract (`full`/`common`, compile-time composition, qualification obligations) | [`docs/decisions/2026-09-18-define-detector-profile-and-pack-contract.md`](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md) |
| [#380](https://github.com/redact-secret/redact-secret/issues/380) | The `common` pack membership table and registry constructor in the core crate, under the contract's reachability rule | `crates/secret-scan-core/src/detectors/mod.rs` (`BUILT_IN_PACKS`, `common_built_in_detectors`), `crates/secret-scan-core/src/registry.rs` (`with_common_built_in`), landed in PR #398 |
| [#381](https://github.com/redact-secret/redact-secret/issues/381) | Real compiled `full`/`common` WebAssembly artifacts, measured against each other with #378's tooling | [`docs/audits/evidence/381/README.md`](evidence/381/README.md) |
| [#382](https://github.com/redact-secret/redact-secret/issues/382) | Qualification of `common` across every profile-exposing runtime surface, plus the `./common` package exports and CI/release wiring | [`docs/audits/evidence/382/README.md`](evidence/382/README.md) |

## Completion criteria

### 1. Current full WASM/native artifact cost and scan-cost baseline is reproducible

Met by #378. `scripts/measure-detector-cost.mjs` rebuilds all 8 measured
compositions from real `cargo build --release` / WASM builds (no fabricated
numbers), and its own test (`npm run detector-cost:test`) is committed. The
baseline is restated and re-verified byte-for-byte by #381
([`docs/audits/evidence/381/README.md`](evidence/381/README.md): the real
`full`/`common` artifacts land within 0.15% of #378's source-patched
estimate).

### 2. A reviewed detector-profile contract defines what is compile-time versus runtime selection

Met by #379. [`docs/decisions/2026-09-18-define-detector-profile-and-pack-contract.md`](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md)
is `status: accepted`. It fixes packs vs. profiles, the reachability rule
(no Cargo features on the core, one additive feature on the `bindings/wasm`
leaf crate only), the per-surface selection mechanism table, and the
qualification obligations that #382 implements against.

### 3. The existing default/full API remains compatible and deterministic

Verified at this revision:

- `cargo test -p redact-secret --test detector_inventory` —
  `built_in_inventory_matches_the_declared_baseline` passes: the canonical
  42-id `full` list and order are unchanged.
- `cargo test -p redact-secret -- common_built_in_detectors_are_exactly_the_common_pack_in_canonical_order common_rejects_a_custom_detector_that_reuses_any_full_built_in_id full_and_common_sessions_report_the_profile_they_were_built_from`
  — all 3 pass: `common`'s ids are exactly the `BUILT_IN_PACKS` table's
  `Pack::Common` rows, in order, and an order-preserving subsequence of
  `full`; reserved-id rejection holds; both profiles report their own
  identity.
- #381 records `full`'s real WASM artifact as +140 B raw / −41 B brotli
  versus pre-epic `main`, from one added export (`profile()`) — findings
  unchanged.

### 4. At least one smaller composition is built and measured against full

Met by #381: `common` is a real compiled WebAssembly artifact (not a
runtime filter), 20.02% smaller raw / 15.77% smaller brotli than `full`,
measured on Chromium, Firefox, and WebKit.

### 5. WASM compressed size and runtime measurements demonstrate the actual effect rather than inferred source-code size

Met by #381: both artifacts are built for real
(`cargo build --release --target wasm32-unknown-unknown` + `wasm-bindgen`,
`lto = "fat"`, `codegen-units = 1`), and #381's own record shows the
real-artifact numbers landing close to but distinct from #378's
source-patched estimate — the estimate method is checked against reality
rather than assumed. Runtime is measured live in a real browser (Playwright)
across 3 engines, not modeled.

### 6. Supported profile behavior is covered by conformance/qualification checks

Met by #382. `common` is qualified against a committed 1,212-fixture
expectation file
([`conformance/fixtures/common-profile-expectations.json`](../../conformance/fixtures/common-profile-expectations.json))
on the Rust core, the WASM artifact (native and real browser, both
`@redact-secret/core` entries), and the Node addon (native and both
`@redact-secret/core` entries). `npm run ci`, `cargo test --workspace`,
`cargo test -p redact-secret-wasm --no-default-features`, and
`cargo clippy --workspace --all-targets -- -D warnings` all pass unmodified
per #382's record. Release wiring guards against publishing `common` under
the `full` package identity (`profile() === "full"` check in
`.github/workflows/release.yml`).

### 7. Documentation explains the default path first; modular selection remains opt-in

Verified directly in [`README.md`](../../README.md) at this revision: every
example before the "Opt-in detector profiles" section (line 263) uses `full`
with no profile argument. That section opens "Everything above uses `full`,
the default on every surface" before introducing `common`, states the
false-negative tradeoff, and links the #382 evidence. `ARCHITECTURE.md`'s
"Detector profiles" section, `docs/qualification.md`, and
`bindings/wasm/README.md` were updated the same way per #382.

## What remains open, by design

- **Named vendor packs (AI, cloud, source-control, package-registry, SaaS)
  are not built.** The contract's three re-measurement triggers (63+
  detectors, 25%+ `full` brotli growth, or a named consumer with a stated
  byte/latency budget) have not fired; #382 confirms this is still true at
  this revision (42 detectors, unchanged `full` brotli size). This matches
  the epic's completion criterion: "at least one smaller composition is
  built and measured against full, **or** the epic records evidence that
  the added distribution complexity is not justified" — the second branch
  applies to named packs specifically, while `common` itself satisfies the
  first branch.
- **`@redact-secret/core/web-stream` and `@redact-secret/core/node-stream`
  are not profile-aware** — documented as a known limitation in #382's
  record and in `README.md`, with a documented workaround (construct the
  sanitizer class directly with a `common`-sourced session). Deferred as
  follow-up work, not required by any of the epic's seven criteria.
- **Python and the CLI stay `full`-only**, an explicit non-goal of the
  accepted contract, not a gap.

## What this evidence does not claim

It does not authorize a version change, tag, publication, deployment, or
release — release authority remains governed by `AGENTS.md`. It does not
re-run the full Firefox/WebKit performance matrix (#381 already did; #382
did not need to repeat it because neither the Rust core nor the WASM
artifact changed in #382). It does not itself add a named vendor pack, make
the stream-adapter convenience functions profile-aware, or add a `common`
profile to Python or the CLI.
