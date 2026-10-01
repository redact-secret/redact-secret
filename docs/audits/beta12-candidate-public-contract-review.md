# Beta.12 candidate public-contract review

[Documentation home](../README.md) · [Audit archive](README.md)

- Release tracking issue: #1112. The artifact inventory's `issue` field
  (`scripts/record-artifact-inventory.py`) names it.
- Reviewed on: 2026-09-30.
- Approved version: `0.1.0-beta.12` (PEP 440 `0.1.0b12`), approved by the
  maintainer on 2026-09-30 for rehearsal, Release and Reconcile. The npm
  `latest` dist-tag is not approved. Version approval is not release approval.
- Previous published source: `v0.1.0-beta.11`,
  `94fc18a974f659ea882c89120dbf1adb3acf2f28`.
- Reviewed implementation baseline:
  `bfc608cce75f79f6a5cab037d7e558ba629777f6` (`main`, merge of #1101). The
  candidate branch on top of it changes only the lockstep version strings in
  `crates/`, `bindings/`, `packages/`, `Cargo.toml` and `Cargo.lock` (15 files,
  30 lines, checked with `git diff --stat bfc608cc..HEAD`), plus
  documentation and the artifact-inventory review path.
- Status: public API and compatibility review is complete for this baseline.
  Exact-SHA artifact qualification, the rehearsal, SAST as a CI run and the
  support-matrix refresh are **not** complete for the merged candidate SHA; see
  [Baseline evidence and invalidation](#baseline-evidence-and-invalidation).

This review replaces the beta.11 document as the current review input to the
artifact inventory (`CURRENT_PUBLIC_API_REVIEW`). An inventory binds this
document's digest and its own `sourceCommit` together. Hashing this document
alone is not a current API review.

## Method

The surface was read from an actual diff, not from changelog prose:
`git diff v0.1.0-beta.11..bfc608cc` over each binding's public surface, then
each `## Unreleased` changelog entry was checked against the code and tests
that implement it.

| Surface | Files diffed | Result |
| --- | --- | --- |
| Rust core | `crates/secret-scan-core/src/lib.rs` (every `pub use`), `types.rs`, `registry.rs`, `pipeline.rs`, `incremental.rs`, `redact.rs`, `policy.rs`, `error.rs`, `limits.rs`, `ruleset.rs`, `pii.rs`, `normalize.rs`; the `core-public-api` list in `Cargo.toml`; `tests/public_api.rs` | Two public functions added (`sanitize`, `sanitize_with_profile`) and both added to `core-public-api`. Every other signature, derive and public accessor is unchanged. `Candidate` and `DetectedFinding` store their type and detector names as `Cow<'static, str>` in private fields; `type_name()`, `detector()` and `id()` still return `&str`, and `PartialEq`, `Eq` and `Hash` still compare content, so a borrowed and an owned name are equal. `Candidate::new(impl Into<String>, ..)` is unchanged. The new `pub(crate)` constructors and accessors are not public. `SecretScanErrorCode` stays at 22 variants. `DefaultPolicy`'s always-redact set grows from 99 to 124 type names (the new finding types). |
| JavaScript / TypeScript | `packages/javascript/src/` (every entry file, `types.ts`, `errors.ts`, `runtime/*.ts`), `package.json` `exports` | The root, `./common`, `./node-stream`, `./web-stream`, `./common/node-stream` and `./common/web-stream` entry files, the `exports` map and every public type are unchanged. `runtime/wasm-binding.ts` (internal) reads WebAssembly results through `takeText()`, `takeFindings()` and `free()` and the flat `start`/`end`; `VERSION` and the exact `@redact-secret/wasm` and eight native-package pins move to `0.1.0-beta.12`. |
| Python | `bindings/python/python/redact_secret/` (`__init__.py`, `_native.pyi`), `pyproject.toml`, `src/lib.rs`, `src/incremental.rs` | The Python package, the stub and `pyproject.toml` are unchanged. The extension's `Finding` attributes became getters over one stored core finding, `ScanResult` stores its text and findings once, detection runs with the GIL released, and the registry is cached per thread. See [Python](#python-behavior). |
| Node addon | `bindings/node/src/lib.rs`, `incremental.rs`, `offsets.rs`, `package.json` | No `#[napi]` export was added, removed or re-signed. Internals only: one forward pass for UTF-16 offset conversion, a compact incremental offset index (#1096), a one-entry ruleset-registry cache (#1059). |
| WebAssembly | `bindings/wasm/src/*.rs` (`#[wasm_bindgen]` exports), `bindings/wasm/Cargo.toml`, `bindings/wasm/npm/package.json` | Additive: `ScanAndRedactResult.takeText()`, `.takeFindings()` and `IncrementalResult.takeText()`, `.takeFindings()`; numeric `Finding.start` and `.end`. No export removed or re-signed. No new dependency, feature or subpath. |
| CLI | `crates/secret-scan-cli/src/` (`args`, `input`, `modes`, `report`, `main`) | No argument, usage, report, exit code, limit or diagnostic changed. `check` builds one registry for all files; `Utf8Stream::push` returns `Cow<'_, str>`, but the CLI is a binary crate and `Utf8Stream` is private. |
| Conformance | `conformance/fixtures/` | Fixtures only; their changes are the detector changes listed below. |

## Public API and compatibility

**Verdict: additive at the type and export level in every binding, with one
breaking value-level change.** No export, type, error code, subpath, argument,
range unit, callback contract, runtime requirement or dependency was removed or
renamed. The one breaking change is a finding type value: `vercel_token` is
split into per-class types for exact `vcp_`, `vca_` and `vcr_` values (#1036).
The other changes a caller can observe are value-level (new findings, spans,
fewer or more redactions) or behavioral (identity, timing, memory), and are
listed below.

### Summary

| Change | Class | Surface | Evidence |
| --- | --- | --- | --- |
| `sanitize`, `sanitize_with_profile` | Additive | Rust core | `lib.rs`, `core-public-api`, `tests/sanitize_golden_path_1078.rs`, `tests/public_api.rs` |
| `vercel-token` finding types per class (`vercel_personal_access_token`, `vercel_app_access_token`, `vercel_app_refresh_token`) | **Breaking** (value) | All bindings, CLI | `detectors/vercel.rs`, `tests/vercel_per_class_1036.rs`; the detector id and always-redact action are unchanged; a non-exact `vcp_`/`vca_`/`vcr_` value, and `vci_`/`vck_`, keep `vercel_token` |
| 18 new detectors, 25 new finding types (92 to 110 detectors, 116 to 141 types in `docs/coverage/detector-inventory.json`; none removed) | Additive, behavior (new findings, new redactions) | All bindings, CLI | list below; `DefaultPolicy` always-redact set 99 to 124 |
| `stripe-token` also matches `sk_org_live_` and `sk_org_test_` + 20 or more `[A-Za-z0-9]` as `stripe_credential` | Behavior (new findings) | All | `detectors/additional_providers.rs:236-237` |
| `gitlab-token` reports a routable `glpat-<payload>.<version>.<length><crc>` whole when the length and CRC-32 verify | Behavior (wider span) | All | #1022 |
| `.npmrc` `_authToken`, `_auth`, `_password`, `secret_access_key` JSON member, masked-lead names, Kubernetes `env` name/value pairs, keyed environment stores, Deepgram forms, AWS secret on the line above an ID | Behavior (more redaction) | All | #1016, #1017, #1018, #1024, #1026, #1038, #1044, #1046 |
| Anthropic Admin and other documented placeholders, Vercel repeated-filler, placeholder-led phrases, vendor-prefix ellipsis, filler layouts, `my`-glued credential words | Behavior (less reporting) | All | #1015, #1041, #1042 |
| `aws-secret-access-key` no longer panics on a multi-byte character before a secret-name identifier | Behavior (bug fix) | All | #1063 |
| Incremental: an AWS access key ID line, with its `aws-access-key` finding, is released when the line closes; a 40-character run waits for exactly one more line | Behavior (streaming timing) | Rust, Node, WebAssembly, Python incremental | #1040, #1044 |
| Python `ScanResult.text` is one `str` object; `ScanResult.findings` is a new `list` of the same `Finding` objects on every read | Behavior (object identity) | Python | [Python](#python-behavior) |
| Python releases the GIL during detection and caches its registry per thread | Behavior (concurrency) | Python | `bindings/python/src/lib.rs` |
| `@redact-secret/wasm` result `takeText`, `takeFindings`; flat `Finding.start`, `.end` | Additive | WebAssembly package (not intended for direct use) | `bindings/wasm/src/result.rs`, `incremental.rs`, `finding.rs` |
| WebAssembly and Node ruleset registry cache (one entry keyed by ruleset bytes) | Behavior (performance; findings and errors unchanged) | WebAssembly, Node | #1059 |
| CLI `check` reuses one registry; `Utf8Stream` borrows a chunk that completes no partial sequence | Behavior (performance; output, exit codes and errors unchanged) | CLI | #1059, #1088 |
| Internal `Cow<'static, str>` metadata, overlap fast path, in-place case-insensitive checks, fewer incremental copies, compact offset indexes, prefilter and index changes | Performance only | All | #1053 to #1060, #1073 to #1077, #1082, #1084, #1086, #1087, #1091 to #1096 |
| WebAssembly artifacts are larger than beta.11 | Behavior (size) | `@redact-secret/wasm`, browser bundles | [Artifact sizes](#runtime-package-and-security-boundary) |

### Rust

`sanitize(input: &str) -> Result<ScanResult, SecretScanError>` and
`sanitize_with_profile(input: &str, profile: Profile)` build the built-in
registry (`with_built_in([])` for `Profile::Full`, `with_common_built_in([])`
for `Profile::Common`) and call `scan_and_redact` with `DefaultPolicy`, the
default placeholder formatter and the default `WholeInputLimits`. They return
the same `ScanResult`, findings, ranges and errors as that path, build the
registry on every call and accept no custom detectors. `scan_and_redact` and
the registry API are unchanged and remain the advanced path. MSRV stays 1.88,
the crate adds no dependency, and the `scan_cost` bench target stays out of the
published package. The plaintext lifetime contract (#1079) is documentation:
no public item changed for it, and no build of the core zeroizes anything (the
opt-in zeroization design, #1080, is not implemented).

### JavaScript

No public export, type or error code changed. The facade pins
`@redact-secret/wasm` and the eight native packages at exactly
`0.1.0-beta.12`, and it now requires the WebAssembly module's `takeText`,
`takeFindings` and `free` on a result, so a mismatched `@redact-secret/wasm`
is not a supported pairing; the exact pin prevents it. Node's addon exports are
unchanged.

### WebAssembly

`@redact-secret/wasm` is documented as not intended for direct use. The
generated surface gains `takeText()` and `takeFindings()` on
`ScanAndRedactResult` and `IncrementalResult`, and `start` and `end` getters on
`Finding`. Each `take` moves the value out once and leaves the result empty
(`takeText()` then returns `""`, `takeFindings()` an empty list), so it is a
take-once read; the existing `text`, `findings` and `range` getters still work
and still clone. A direct importer that reads a result only through the getters
sees no change. The root and `./common` builds still answer a PII selection
with `PII_SELECTOR_UNAVAILABLE`, as in beta.11.

### Python behavior

`redact_secret.scan_and_redact` returns a `ScanResult` whose attributes were
`#[pyo3(get)]` copies and are now stored once:

- `result.text` is the same `str` object on every read, and is read-only.
- `result.findings` is still a `list` (`type(...) is list`) and is a new list
  on each read, so mutating it changes nothing, but its elements are now the
  same `Finding` objects every time: `res.findings[0] is res.findings[0]` is
  now `True` (it was `False`), and `id(...)` of an element is stable. Code that
  relied on getting fresh `Finding` objects per read sees a different identity;
  the objects are immutable, so no supported use is affected.
- `Finding.id`, `type`, `detector`, `confidence`, `action`, `obfuscation`,
  `start` and `end` read the same values. The first six are now getters over
  one stored core finding and remain read-only; `__repr__` is unchanged.
- Detection runs with the GIL released, so scans on several threads run in
  parallel. Policy and formatter callbacks still run on the calling thread
  with the GIL. The registry is cached per thread and rebuilt when
  `initialize` changes the PII selection.
- The import module, stub, exception classes, callback shapes, range unit
  (`unicode-code-points`) and incremental API are unchanged. The distribution
  version remains derived from Cargo (`0.1.0b12`).

### CLI

No argument, report, exit code, limit or diagnostic contract changed. Check
mode builds one registry and reuses it for every file, recording a build
failure against the file that hit it and retrying for the next. Streaming
input hands a chunk that completes no partial UTF-8 sequence to the scanner
without copying it and carries at most 3 bytes; the differential test against
the previous decoder passes, and invalid UTF-8 and split characters give the
same errors.

### Value-level changes a caller can observe

No binding types a finding's `type` as a closed enum, so the following are
value-level changes. A consumer that asserts an exact finding set, an exact
`type` string, an exact `action`, or counts findings by type can see them. The
`CHANGELOG.md` `## Unreleased` section lists each one (the dated entry is
written by the closeout).

- **Breaking: Vercel finding types (#1036).** Exact `vcp_`, `vca_` and `vcr_`
  values (marker plus exactly 56 `[A-Za-z0-9]`) now report
  `vercel_personal_access_token`, `vercel_app_access_token` and
  `vercel_app_refresh_token`. Code that filters, allowlists or counts by
  `vercel_token` must also match these. Spans, redactions, the detector id and
  the always-redact action are unchanged.
- **New credential findings (additive).** Eighteen new detectors, each always
  redacted at provider specificity: `daytona-api-key`,
  `clickhouse-cloud-api-secret`, `nvidia-api-key`, `browserbase-api-key`,
  `runpod-api-key`, `cerebras-api-key` (#970-#975);
  `bitwarden-secrets-manager-access-token`, `polar-token`, `sonarqube-token`,
  `rubygems-api-key`, `clojars-deploy-token` (#1019-#1025); `crates-io-token`,
  `dynatrace-token`, `paddle-api-key`, `honeycomb-api-key`, `axiom-token`
  (#1031-#1035); `google-oauth-client-secret` (#1029) and
  `aws-secret-access-key` (#1028, context-constrained). Together they add 25
  finding types (the 22 counted by the new detectors plus the three Vercel
  class types). None is a support-status claim; the support matrix does not yet
  measure them.
- **More redaction.** Values in new forms: `.npmrc` credential keys (#1024),
  `"SecretAccessKey"` (#1026), Kubernetes `name:`/`value:` env pairs (#1016),
  keyed environment stores such as `os.environ["NAME"] = "..."` (#1038), the
  Deepgram SDK, WebSocket and request-block forms (#1017, #1046), unmasked
  values under a `masked_`/`redacted_`/`hashed_`-led name (#1018), a routable
  GitLab PAT through its CRC (#1022, a wider span), and Stripe `sk_org_live_`
  and `sk_org_test_` (#1030).
- **Less reporting.** Anthropic Admin documentation placeholders (#1015),
  placeholder-led phrases under a credential name (#1041), and the listed
  Vercel, RunPod, Paddle, Bitwarden and ClickHouse documentation placeholders
  (#1042) are no longer reported.
- **Streaming timing (#1040, #1044).** An incremental session releases an AWS
  access key ID line, and its `aws-access-key` finding, as soon as the line
  closes, and scans the line below against a copy of it. Whole-input and
  incremental results still agree.
- **Bug fix (#1063).** No panic on a multi-byte character before an AWS
  secret-name identifier; the input scans as the ASCII case.
- **Performance only.** #1053 to #1060, #1073 to #1077, #1082 to #1084, #1086
  to #1088 and #1091 to #1096 change time, memory or allocation, not findings,
  ranges, ids, order or output; each was checked against its previous
  implementation by a differential or oracle test.
- **Opt-in PII.** Unchanged. The `pii-v1` support state is five families
  `provisional` and US SSN `pending`; none is `stable`. The public US SSN
  identity investigation (#1003) changed no code.

## Runtime, package, and security boundary

All version-bearing Cargo and npm manifests and lockfiles agree on
`0.1.0-beta.12` (`npm run rust:check`: 0 errors). `docs/quickstart.md`,
`docs/getting-started.md`, `docs/specs/threat-model.md` and the bug-report
template pin the same version in npm and PEP 440 spellings. The core still has
no runtime network, filesystem, environment, telemetry, secret storage or UI
behavior; no crate or npm dependency was added. Detection remains separate from
policy enforcement, PII stays off by default and orthogonal to the
`full`/`common` profiles, and findings and diagnostics stay input-free.

The artifact set is unchanged from beta.11: the npm facade, the WebAssembly
package (four builds), eight native npm packages, the Rust core and CLI crates,
six CLI binaries, and eight abi3 wheels plus the Python sdist.

WebAssembly artifact sizes are larger than beta.11's. The `.wasm` sizes (raw /
gzip level 9) were measured at `bfc608cc` by the performance evaluation run
36788351912 (`redact-secret-benchmarks`,
`evidence/603/verified-bfc608c/wasm-sizes.json`), not rebuilt locally; the
candidate differs from that source only in version strings, which do not change
a size:

| Build | beta.11 (raw / gzip) | candidate (raw / gzip) |
| --- | --- | --- |
| `full` | 542,445 / 187,230 | 594,833 / 205,068 |
| `common` | 356,480 / 127,667 | 406,556 / 142,525 |
| `full` `pii` | 833,757 / 310,058 | 896,237 / 328,857 |
| `common` `pii` | 647,891 / 248,491 | 708,032 / 265,924 |

The beta.11 figures are from the
[beta.11 review](beta11-candidate-public-contract-review.md#runtime-package-and-security-boundary).
The growth is the 18 new detectors and the per-scan work (#1073 to #1077) on top
of the #1043 reduction; the `CHANGELOG.md` #1043 entry states the same. The
benchmarks' acceptance results for that run record the size and timing budgets.

Local verification on the candidate branch, after the version bump (macOS
arm64): `npm ci --ignore-scripts`, `npm run examples:install`, `npm run ci`
(every gate through `js:typecheck` passed; `js:test` failed two Node-adapter
assertions only because the shell exported `FORCE_COLOR=3`, and passes with
colors off: 183 tests in 17 files), `npm run rust:check` (0 errors), `npm run
check:docs`, `npm run check:release`, `cargo fmt --all --check`, `cargo clippy
--workspace --all-targets --locked -- -D warnings` and `cargo test --workspace
--locked` (2,557 tests in 66 suites, 0 failed). These are local runs, not CI
evidence for the merged SHA. The registry-preflight check, SAST as a CI run and
`check-release-refs.py --candidate-ref` (which requires `main`) were not run.

## Baseline evidence and invalidation

Complete for this product source:

- The performance evaluation of `bfc608cc` (run 36788351912) with the
  WebAssembly size record above.

Not complete, and required before release approval under
[releasing](../releasing.md#qualify-without-publication):

- The support-matrix refresh. `benchmarks/support-matrix.json` still pins the
  beta.11 candidate measurement (76 providers, 152 families) and does not
  cover the 18 new detectors; the refresh from `redact-secret-benchmarks` and
  the drift gate against `v0.1.0-beta.11` happen separately.
- `Artifact qualification` and `Package Release Rehearsal` for the merged
  candidate SHA, including the artifact inventory that binds this document.
- SAST as evidence for the frozen revision.
- The nine Beta.12 detector handoffs still open (#1102 to #1110: Xata,
  Sourcegraph, Unkey, Buildkite, Pydantic Logfire, Square, Mapbox, Fly, Ory)
  are not in this candidate. If any merges before release, it is a source
  change.

Any source change after the reviewed baseline invalidates this compatibility
review. Such a change needs a fresh review before release approval.

No review document, successful workflow, issue closure, or manifest version
authorizes a tag, release, publication, or deployment. Explicit release
approval remains a separate step after the evidence above is produced and
reviewed, and after a final changelog review for the source being released.
