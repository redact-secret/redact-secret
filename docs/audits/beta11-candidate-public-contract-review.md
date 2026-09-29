# Beta.11 candidate public-contract review

[Documentation home](../README.md) · [Audit archive](README.md)

- Issue: [#1006](https://github.com/redact-secret/redact-secret/issues/1006).
- Reviewed on: 2026-09-29.
- Approved version: `0.1.0-beta.11` (PEP 440 `0.1.0b11`), approved by the
  maintainer on 2026-09-29. Version approval is not release approval.
- Previous published source: `v0.1.0-beta.10`,
  `af7f863f29f9fe482dd233c8b7bc5b77dc427314`.
- Reviewed implementation baseline:
  `1dcfa344c358cd554154c3489afa2597c15dff34` (`main`). Its product source
  (`crates/`, `bindings/`, `packages/`, `Cargo.toml`, `Cargo.lock`) is
  byte-identical to `8b6a5fde52ec`, the core the Beta.11 PII qualification
  measured. The candidate branch on top of it changes only documentation,
  the packaged READMEs, and the lockstep version strings.
- Status: public API and compatibility review is complete for this baseline.
  Exact-SHA artifact qualification, the performance evaluation, SAST as a
  CI run, and the support-matrix refresh are **not** complete for the merged
  candidate SHA; see [Baseline evidence and invalidation](#baseline-evidence-and-invalidation).

This review replaces the beta.10 document as the current review input to the
artifact inventory. An inventory binds this document's digest and its own
`sourceCommit` together. Hashing this document alone is not a current API
review.

## Method

The surface was read from an actual diff, not from changelog prose:
`git diff v0.1.0-beta.10..1dcfa344` over each binding's public surface.

| Surface | Files diffed | Result |
| --- | --- | --- |
| Rust core | `crates/secret-scan-core/src/lib.rs` (every `pub use`), `types.rs`, `registry.rs`, `pipeline.rs`, `incremental.rs`, `redact.rs`, `policy.rs`, `error.rs`, `pii.rs`, `limits.rs`, `ruleset.rs`, `entropy.rs`; the `core-public-api` list in `Cargo.toml`; `tests/public_api.rs` | `lib.rs`, `types.rs`, `redact.rs`, `policy.rs`, `error.rs`, `limits.rs`, `ruleset.rs` and `entropy.rs` are unchanged. The other diffs add or change only private functions. `core-public-api` is unchanged. `tests/public_api.rs` changes one fixture name (`AUTH_TOKEN` to `SIGNING_KEY`, since #941 made `auth_token` high-signal) and the expected activation identity (`pii-context/v2`). |
| JavaScript / TypeScript | `packages/javascript/src/index.ts`, `common.ts`, `entry-core.ts`, `types.ts`, `errors.ts`, `adapters/`, `package.json` `exports`; `runtime.ts`, `native.ts`, `runtime/*.ts`, `wasm-artifact.d.ts` | Every public entry file and the `exports` map are unchanged. `NativeBindingLoader` now takes `{ pii: boolean }` (#937), but `native.ts` is internal and not re-exported by any entry point. `runtime/*.ts` pick the default or `pii` WebAssembly build. |
| Python | `bindings/python/python/redact_secret/__init__.py`, `_native.pyi`, `pyproject.toml` | Unchanged. Only `README.md` and a test's expected activation identity changed. |
| Node addon | `bindings/node/src/lib.rs`, `bindings/node/package.json` | Only a unit test's expected identity and the version changed. |
| WebAssembly | `bindings/wasm/src/*.rs` (`#[wasm_bindgen]` exports), `bindings/wasm/Cargo.toml`, `bindings/wasm/npm/package.json` | No `#[wasm_bindgen]` export was added, removed or re-signed. The private crate gains an off-by-default `pii` feature, and the package gains the `./pii` and `./common/pii` subpaths plus their two `.wasm` paths (#937). |
| CLI | `crates/secret-scan-cli/src/` (arguments, usage, output, exit codes) | Only a test's expected `--print-pii-activation` output changed. |

## Public API and compatibility

**Verdict: additive at the type level in every binding. There is no removed
or renamed export, type, error code, subpath, argument, range unit, callback
contract or runtime requirement.** The changes a caller can observe are
value-level (detection results and the PII activation identity string) and
one narrow behavior change on the `@redact-secret/wasm` package, which is
documented as not intended for direct use.

| Surface | Review result |
| --- | --- |
| Rust | No public item added, removed or changed. `SecretScanErrorCode` stays at 22 variants. MSRV stays 1.88. The crate gains a `[[bench]] scan_cost` target (#981), which the package's `include` list keeps out of the published crate. |
| JavaScript | No public export added, removed or renamed on the root, `./common`, `./node-stream`, `./web-stream`, `./common/node-stream` or `./common/web-stream`. The facade pins `@redact-secret/wasm` and the eight native packages at exactly `0.1.0-beta.11`. The public `initialize({ pii })`, `piiActivation()`, selector grammar and error codes behave as in beta.10. New: in a browser, Worker or workerd bundle, a bundler now emits each profile's `pii` build as a second, lazily loaded `.wasm` asset, fetched only when the first `initialize()` selects PII (#937). A deployment that allowlists asset URLs, such as a strict CSP or a fixed asset manifest, must allow the new asset if it selects PII. |
| `@redact-secret/wasm` | Additive subpaths `./pii` and `./common/pii`. Behavior change for direct importers only: the root and `./common` builds no longer link the PII runtime, so they now answer a valid non-empty PII selection with `PII_SELECTOR_UNAVAILABLE` instead of activating it; such code must import `./pii` or `./common/pii`. `@redact-secret/core` does this itself, so no supported caller is affected. |
| Python | No change to the import module, stub, exceptions, callback shapes, range units or incremental API. The distribution version remains derived from Cargo (`0.1.0b11`). |
| CLI | No argument, report, exit code, limit or diagnostic contract changed. |

### Value-level changes a caller can observe

No binding types a finding's `type` as a closed enum, so the following are
value-level changes. A consumer that asserts an exact finding set, an exact
`type` string, an exact `action`, or an exact activation identity can see
them. The dated `CHANGELOG.md` entry lists each one.

- **PII activation identity.** Every identity now ends
  `vocabulary=pii-context/v2` instead of `pii-context/v1` (#924, #927),
  including `selectors=off`. A caller that stored or compared the beta.10
  string sees a different value. The selector grammar and family sets are
  unchanged.
- **New credential findings.** 13 new detectors emit 24 new finding types
  (79 to 92 detectors, 92 to 116 types in
  `docs/coverage/detector-inventory.json`; none removed): `doppler-token`,
  `trigger-dev-token`, `e2b-api-key`, `posthog-token`, `helicone-api-key`,
  `firecrawl-api-key`, `composio-api-key` (#903-#909),
  `convex-deployment-key`, `onepassword-service-account-token`,
  `inngest-signing-key`, `resend-api-key`, `apify-api-token`,
  `wandb-api-key` (#912-#917). Each redacts by default. The six Beta.12
  families (#970-#975) are not in this candidate.
- **More redaction.** A value under a provider-named credential variable
  that the provider's detector declines now gets a `generic-token`
  `contextual_secret` (#948), and the `common` profile now redacts
  provider-named assignments. Several keyword-gated provider values move
  from `warn` to `redact` (#936), as does a secret-shaped value under
  `auth_token` (#941). New forms are found by `generic-token` (#919),
  `connection-string` (#935), `mailchimp-api-key` (#931), the keyword-gated
  Deepgram and Cohere detectors (#932), and three context-gated legacy
  detectors (#933).
- **Less reporting.** Placeholders, masked and elided keys, Make-escaped
  substitutions, documented public keys and the Confluent key id are no
  longer `contextual_secret` (#993), nor are reference names and
  identifiers (#911), repeated-filler Heroku and Stripe placeholders (#934),
  or vendor-prefixed documentation placeholders (#949).
- **Span changes.** `bearer-token` selects `<id>:<secret>` and
  `<name>|<secret>` values whole (#918) and stops before a following
  delimited field (#939).
- **Streaming parity and line semantics (#990).** Incremental output now
  equals the whole-input result on the #985 layouts. In a whole-input scan,
  `X-Authorization: Bearer <token>` (any header name ending in
  `authorization`) is now a bare `Bearer` match, and a lone `\r` ends a line
  for every detector. LF and CRLF input is unaffected.
- **Opt-in PII.** With PII selected, more labelled values are found (#922,
  #924-#927, #940, #943). Nothing changes with PII off. The `pii-v1`
  support state is five families `provisional` and US SSN `pending`; none is
  `stable` (#901, #1003).
- **Performance only.** #950, #982, #983, #985, #986, #989 and #902 change
  time and memory, not findings, ranges, actions or output.

## Runtime, package, and security boundary

All version-bearing Cargo and npm manifests and lockfiles agree on
`0.1.0-beta.11` (`npm run rust:check`: 0 errors). `docs/quickstart.md`,
`docs/getting-started.md` and `docs/specs/threat-model.md` pin the same
version in npm and PEP 440 spellings. The core still has no runtime network,
filesystem, environment, telemetry, secret storage or UI behavior; the new
dependency surface is none (the #902 and #937 changes add no crate). Detection
remains separate from policy enforcement, PII stays off by default and
orthogonal to the `full`/`common` profiles, and findings and diagnostics stay
input-free.

The artifact set is unchanged from beta.10: the npm facade, the WebAssembly
package (now four builds instead of two inside the same package identity),
eight native npm packages, the Rust core and CLI crates, six CLI binaries,
and eight abi3 wheels plus the Python sdist. Measured on this baseline with
`node scripts/measure-wasm-profiles.mjs --guard-only`, the `.wasm` sizes
(raw / gzip level 9) are 542,445 / 187,230 B (`full`), 356,480 / 127,667 B
(`common`), 833,757 / 310,058 B (`full` `pii`) and 647,891 / 248,491 B
(`common` `pii`); beta.10 shipped 742,321 / 275,467 B and
742,433 / 275,477 B. The default builds are above the beta.8 size budgets,
which the benchmarks record as an accepted size tradeoff
([#950 evidence](evidence/950/README.md)).

Local verification on the candidate branch, after the version bump (macOS
arm64): `npm ci --ignore-scripts`, `npm run examples:install` and
`npm run ci` (including `js:test`, 181 tests in 17 files), `npm run
rust:check` (0 errors), `cargo fmt --all --check`, `cargo clippy --workspace
--all-targets --locked -- -D warnings`, `cargo test --workspace --locked`
(2,164 tests in 52 suites, 0 failed), `python3 scripts/run-sast.py` (48
findings and 30 scan errors, all dispositioned in `sast/baseline.json`, 0
unresolved), `python3 -B scripts/check-release-refs.py` (0 errors) and
`npm run registry-preflight:check` (all ten npm identities, both crates and
the PyPI project exist). These are local runs, not CI evidence for the
merged SHA.

## Baseline evidence and invalidation

Complete for this product source:

- The Beta.11 `pii-v1` qualification of core `8b6a5fde52ec`, byte-identical
  product source to this baseline
  ([final record](https://github.com/redact-secret/redact-secret-benchmarks/blob/be0fb9f35045bf05e5b999a2c0ed368541f9e963/evidence/901/428/final-core-8b6a5fde.md)).

Not complete, and required before release approval under
[releasing](../releasing.md#qualify-without-publication):

- The performance evaluation (`performance-evaluation.yml` in
  `redact-secret-benchmarks`) against the merged candidate SHA. #950's runs
  measured earlier branch commits, not this SHA.
- `Artifact qualification` and `Package Release Rehearsal` for the merged
  candidate SHA, including the artifact inventory that binds this document.
- SAST as evidence for the frozen revision.
- The support-matrix refresh. `benchmarks/support-matrix.json` is still the
  2026-09-25 matrix measured on `0.1.0-beta.7`, identical to the copy in
  `v0.1.0-beta.10`. The drift gate therefore reports no regression, but only
  because nothing was re-measured; the 13 new detector families above have
  no support status yet.

Any source change after the reviewed baseline invalidates this compatibility
review. Such a change needs a fresh review before release approval.

No review document, successful workflow, issue closure, or manifest version
authorizes a tag, release, publication, or deployment. Explicit release
approval remains a separate step after the evidence above is produced and
reviewed, and after a final changelog review for the source being released.
