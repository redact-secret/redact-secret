# #1066 — Freeze the stable public API, behavior and extension contracts

Product judgement. Final record for
[#1066](https://github.com/redact-secret/redact-secret/issues/1066) (parent
[#1065](https://github.com/redact-secret/redact-secret/issues/1065); it
reconciles [#199](https://github.com/redact-secret/redact-secret/issues/199)).
It is an audit, an evidence record and a **draft** contract. It does not change
public behavior, any `core-public-api` entry, any binding source file, or
version, tag and release state, and the owner has accepted nothing in it yet.

What this branch adds:

- **The draft contract**, as a new section "Stable contract 1 (DRAFT)" in
  [`docs/reference/api-contract.md`](../../../reference/api-contract.md), the
  file the repository already uses for API concepts. It is not a parallel
  document.
- **This record**: the audit table of every public name, the surfaces likely
  to break, the verification, and the decisions needed.
- **The ruleset audit**, [#1072](../1072/README.md), whose disposition the
  draft uses for rulesets.
- Three documentation corrections that settle questions the card assigned to
  it (below).

## Summary

| Question | Answer |
| --- | --- |
| Is the surface coherent enough to freeze? | Yes, after the bounded changes listed under [Surfaces likely to break](#surfaces-likely-to-break). The Rust, JavaScript, Python and CLI names, behaviors and error codes match their documentation, declarations and the shared fixtures; 54 Rust root names, 44 Python names, 13 JavaScript values and 25 JavaScript types were reconciled one by one. |
| What is likely to need a breaking change after stable? | Nine surfaces ([list](#surfaces-likely-to-break)). Three should be fixed in Beta.13: Rust enums that grow without `#[non_exhaustive]`, JavaScript incremental limit names that say code units but count bytes, and three ruleset leniencies ([#1072](../1072/README.md)). The rest are documentation or are excluded from the contract. |
| Do all runtimes pass conformance on one commit? | Rust, Python (9,084 tests), the Node addon (`full` and `common`), the CLI, WebAssembly in Chromium, Firefox and WebKit and through the Node fallback, and the 65 examples all pass on one commit. Not run: published artifacts, other operating systems and architectures, other Node and Python versions. [Details](#verification). |
| Does it need an ADR? | Yes, one: the compatibility classes and what "stable" promises are new policy, not an application of an existing decision. Proposed title: *Define the 0.1.x stable public contract and its compatibility classes*, `scope: workspace`, spec `engine`, status `proposed`. A second, for rulesets, is proposed in [#1072](../1072/README.md) (R7). Neither is written here. |
| CLI panic status | Documented as outside the contract: any status other than `0`, `1`, `2` is an internal failure to treat as a failure. Catching panics to exit `2` is not recommended ([below](#cli-panic-exit-status)). |
| `docs/guides/javascript.md` size link | Repointed; the section it linked never held sizes ([below](#documentation-corrections-made)). |

## Method

- Source `4069e52a7eed84274069541498fa08aaed8d3ffe` (`main`), `rustc` 1.98.1,
  Node.js 22.16.0, Python 3.14.7 with `maturin`, Apple M4 (macOS arm64). The
  host was shared and heavily loaded while this ran.
- Names were taken from the source, not the prose: `lib.rs` `pub use` and
  `core-public-api` in `Cargo.toml`; `packages/javascript/package.json`
  `exports` and the generated `dist/*.d.ts` from `npm run js:build`;
  `redact_secret.__all__` and `_native.pyi`; `bindings/node/src/lib.rs` and
  `bindings/wasm/src/lib.rs` exports; `crates/secret-scan-cli/src/main.rs`
  `USAGE` and `help()`; the conformance fixture index.
- Each name was matched to the guide or reference that documents it, the
  declaration or stub that types it, and a test or fixture that exercises it.
- Behavior claims in the draft contract were checked against the code
  (`redact.rs`, `pipeline.rs`, `policy.rs`, `incremental.rs`, `runtime.ts`,
  `errors.ts`, the Python extension) or run.

## Audit table

Status values: **stable** (in contract 1), **stable, Rust-only trusted
extension**, **experimental** (shipped, not promised), **internal** (not for
direct use), **excluded** (not provided and not promised).

### Rust (`redact_secret`, 54 names)

| Names | Status | Evidence |
| --- | --- | --- |
| `scan`, `scan_with_limits`, `redact`, `redact_with_limits`, `scan_and_redact`, `scan_and_redact_with_limits` | stable | `tests/public_api.rs`, `canonical_corpus.rs`, `policy_redaction.rs`, `whole_input_limits.rs` |
| `sanitize`, `sanitize_with_profile` | stable. Call the profile constructor directly for `common`; a run-time `Profile` links both ([#1127](../1127/README.md)) | `tests/sanitize_golden_path_1078.rs`; the rustdoc does not carry the link warning, the Rust guide does |
| `WholeInputLimits`, `DEFAULT_MAX_INPUT_BYTES`, `DEFAULT_MAX_FINDINGS` | stable | `whole_input_limits.rs` |
| `Finding`, `DetectedFinding`, `ScanResult`, `IncrementalResult` (alias of `ScanResult`), `ByteRange` | stable | `public_api.rs`; private fields, accessor-only |
| `Action`, `Confidence`, `Specificity` | stable, closed sets (adding a variant is breaking by design) | `types.rs`; ADR fixes five specificities |
| `Obfuscation` | stable, `#[non_exhaustive]` | `types.rs` |
| `Policy`, `PolicyContext`, `DefaultPolicy` | stable | `policy_redaction.rs`; any `Fn(&DetectedFinding, &PolicyContext) -> Result<Action, PolicyFailure>` is a policy |
| `PlaceholderFormatter`, `PlaceholderContext`, `default_placeholder_formatter`, `typed_placeholder_formatter`, `MAX_PLACEHOLDER_LENGTH` (256) | stable | `redact.rs`, `policy_redaction.rs` |
| `SecretScanError`, `DetectorFailure`, `PolicyFailure`, `FormatterFailure` | stable | `public_api.rs`; fixed, payload-free |
| `SecretScanErrorCode` | stable but **grows** and is not `#[non_exhaustive]`: [LB1](#surfaces-likely-to-break) | `error.rs`; 22 variants; `conformance/fixtures/error-codes.json` |
| `Profile` | stable but not `#[non_exhaustive]`: LB1 | `registry.rs`; two variants, a third needs the #1128 gate |
| `PiiSelection` | stable (selector grammar and identity); family support is the support matrix's | `pii_runtime_conformance.rs`, `pii-runtime-v1.json` |
| `IncrementalSanitizer`, `IncrementalLimits`, `IncrementalPolicy`, `IncrementalPolicyContext`, `SessionState` | stable. Seven constructors, no builder: LB7 | `incremental.rs`, `incremental_partitions.rs`, the incremental corpora |
| `load_ruleset`, `RulesetError`, `RulesetErrorClass` (`#[non_exhaustive]`) | stable **pending** the [#1072](../1072/README.md) disposition | `ruleset_conformance.rs`, `ruleset.rs` tests |
| `Detector`, `Candidate`, `DetectorContext`, `DetectorRegistry`, `RegisteredDetector`, `run_detector_pipeline`, `is_identifier`, `MAX_IDENTIFIER_LENGTH` | stable, Rust-only trusted extension (in-process code, not a sandbox) | `public_api.rs`, `registry.rs`; the pipeline hands a detector the scan copy, so a custom detector's ranges index the text without invisible characters |
| `RANGE_UNIT` (`utf8-bytes`), `VERSION` | stable | `lib.rs` tests |
| `shannon_entropy` | stable utility; result is bit-identical by construction (first-occurrence summation order) | `entropy.rs` |

Methods on these types are covered with their type. Two notes: `Candidate::signals`
returns `&[String]` and is not exposed in public results, so PR #1173's
internal `Cow<'static, [String]>` is not a contract change; and
`DetectorRegistry` has seven public constructors (`new`, `with_built_in`,
`with_common_built_in`, `with_built_in_and_pii`, `with_common_built_in_and_pii`,
`with_built_in_and_pii_custom`, `with_common_built_in_and_pii_custom`).

### JavaScript (`@redact-secret/core`)

| Entry / names | Status | Evidence |
| --- | --- | --- |
| `.` and `./common`: `initialize`, `piiActivation`, `artifact`, `scan`, `redact`, `scanAndRedact`, `createIncrementalSanitizer`, `PROFILE` (`"full"` / `"common"`) | stable | `dist/index.d.ts`, `dist/common.d.ts`; `js:typecheck`; addon qualification |
| `RANGE_UNIT`, `VERSION`, `SecretScanError`, `defaultPlaceholderFormatter`, `typedPlaceholderFormatter` (re-exported by both) | stable | `dist/entry-core.d.ts` |
| Types: `ArtifactKind`, `DetectedSecretFinding`, `IncrementalLimits`, `IncrementalPolicyContext`, `IncrementalSanitizer`, `IncrementalSanitizerOptions`, `IncrementalSanitizerResult`, `IncrementalSanitizerState`, `IncrementalSecretPolicy`, `InitializeOptions`, `PlaceholderContext`, `PlaceholderFormatter`, `PolicyContext`, `RangeUnit`, `RedactOptions`, `ScanAndRedactOptions`, `ScanOptions`, `ScanResult`, `SecretAction`, `SecretConfidence`, `SecretFinding`, `SecretObfuscation`, `SecretPolicy`, `SecretScanErrorCode`, `WholeInputLimits` | stable; `SecretScanErrorCode` is a growing union: LB8; `IncrementalLimits` field names: LB2 | `dist/entry-core.d.ts` |
| `ScanOptions.ruleset` | stable **pending** [#1072](../1072/README.md) | `test/ruleset-option.test.ts` (against a double), the one-off real-addon run below |
| `./node-stream`, `./common/node-stream`: `createNodeStreamSanitizer`, `NodeStreamSanitizer` | stable | addon qualification pass 5 |
| `./web-stream`, `./common/web-stream`: `createWebStreamSanitizer`, `WebStreamSanitizer` | stable | `qualify-browser-artifact` (not run here), `test/adapters/*`, Node WebAssembly fallback qualification |
| `./package.json` | stable (metadata) | `exports` |
| `toSecretScanError` (in `errors.d.ts`, not re-exported) | internal | not in any entry file |
| `@redact-secret/wasm`, its `./common`, `./pii`, `./common/pii` subpaths and `.wasm` assets | internal ("not intended for direct use"); lockstep versioning only | `bindings/wasm/npm/package.json` |
| `@redact-secret/node` (private) and the eight native platform packages | internal | `bindings/node/package.json` |

### Python (`redact_secret`, 44 names in `__all__` plus `__version__`)

| Names | Status | Evidence |
| --- | --- | --- |
| `scan`, `redact`, `scan_and_redact`, `initialize`, `pii_activation`, `default_policy`, `default_incremental_policy`, `default_placeholder_formatter`, `typed_placeholder_formatter` | stable | `test_api.py`, `test_conformance.py`, `test_typing.py` |
| `Finding`, `DetectedFinding`, `ScanResult`, `IncrementalResult`, `PolicyContext`, `PlaceholderContext`, `IncrementalPolicyContext`, `WholeInputLimits`, `IncrementalLimits`, `IncrementalSanitizer` | stable | `.pyi`, `test_incremental*.py`, `test_whole_input_limits.py` |
| `RANGE_UNIT`, `VERSION`, `__version__` | stable | `test_import.py` |
| 23 exception classes (`SecretScanError` and 22 subclasses, one per core code, including `InvalidRulesetError` and four `Pii*Error`) | stable; the set grows | `test_callback_failure.py`, `error-codes.json` |
| `scan(..., ruleset=)`, `scan_and_redact(..., ruleset=)` | stable **pending** [#1072](../1072/README.md) | `test_ruleset.py`, `test_ruleset_conformance.py` |
| `redact_secret._native`, including `version()` and `byte_offset_to_char_offset()` (declared in `_native.pyi`, not in `__all__`) | internal | `__init__.py` |

### CLI (`redact-secret`)

| Surface | Status | Evidence |
| --- | --- | --- |
| Arguments `--json`, `--redact`, `--ruleset <path>`, `--pii <selector>` (repeatable), `--print-pii-activation`, `--version`/`-V`, `--help`/`-h`, `--`, paths | stable | `main.rs` `USAGE`, `tests/cli.rs`, `cli:qualify` |
| Exit codes `0`, `1`, `2` | stable | `docs/guides/cli.md`, `qualify-cli-binary.mjs` pass 3 |
| Any other exit status (`101`, a signal) | outside the contract; documented as an internal failure | [#1130](../1130/README.md) |
| `--json` report: `version`, `rangeUnit`, `findingCount`, `sources`, `failures` | stable, additive-only. No schema version field: LB6 | `report.rs`, `qualify-cli-binary.mjs` |
| Line-per-finding text report | not a parsing contract (for people) | `help()` documents it; the guide says use `--json` |
| Streaming standard input; `--ruleset` requires a file source | stable | `args.rs`, `tests/cli.rs` |

### Conformance and generated artifacts

| Item | Status | Evidence |
| --- | --- | --- |
| `conformance/fixtures/*.json` and their `$schema` labels | the behavior definition; layout not semver-covered | `conformance/README.md`, `schema.test.ts` |
| `docs/releases/<version>/artifact-inventory.json`, `manifest.json` | release records, not API | release runbook |
| Generated `dist/*.d.ts` | stable as the declaration of the JavaScript API | reconciled above |
| `.pyi` stubs | stable as the declaration of the Python API | `test_typing.py` |

## Surfaces likely to break

"Fix" means a change in Beta.13 before the freeze; "exclude" means the contract
says so in words and the surface is not promised.

| # | Surface and evidence | Why it would break | Options | Recommendation |
| --- | --- | --- | --- | --- |
| LB1 | Rust `SecretScanErrorCode` (22 variants; `InvalidRuleset` and four PII codes were added during the betas), `Profile` (two variants), `SessionState`, `Specificity`, `Confidence`, `Action` are exhaustive enums. Only `Obfuscation` and `RulesetErrorClass` are `#[non_exhaustive]`. | A dependent crate that matches an enum exhaustively stops compiling when a variant is added. Error codes have already grown release after release. | (a) Add `#[non_exhaustive]` to `SecretScanErrorCode` and `Profile` now (one-time break, never again); (b) leave all exhaustive and treat a new code as breaking; (c) (a) for the two plus `SessionState` | **(a), fix in Beta.13.** Keep `Action`, `Confidence` and `Specificity` exhaustive and say so: they are closed by design and a new variant changes pipeline semantics. Callers with an exhaustive `match` need a wildcard arm. A source change, so it needs a changelog entry. |
| LB2 | JavaScript `IncrementalLimits` fields `maxInputCodeUnits`, `maxBufferedCodeUnits`, `maxTokenCodeUnits`, `maxMultilineCodeUnits` hold **UTF-8 byte** ceilings (`bindings/node/src/incremental.rs` passes them to the byte limits; each field's doc says so; `docs/guides/streaming.md` says so), while the interface's own doc comment says "UTF-16 code-unit limits". | A name that says one unit and counts another is a bug report waiting; a rename after stable is breaking for every caller. | (a) Freeze as spelled, fix the contradicting comment, document the units; (b) accept `max*Bytes` as additive aliases, deprecate the old names, keep both working; (c) rename now | **(b) if the owner wants the names right; otherwise (a), which needs only a comment fix.** Not (c): it breaks published adapters and vault pins. Either way the contract states the unit. |
| LB3 | Ruleset leniencies: repeated field (last wins), invisible-character prefix (loads, never matches), `+20`/`020` counts. [#1072](../1072/README.md) R1 to R3. | Stable files would pin the defect. | Tighten now / freeze as-is / mark experimental | **Tighten now** (D1 of #1072). |
| LB4 | A ruleset detection is `warn` under the default policy; `--redact --ruleset` cannot change text. Undocumented until this branch's guide edit. [#1072](../1072/README.md) D2. | A user expecting redaction gets reporting only; changing it later is a behavior break. | Document `warn` / let `DefaultPolicy` redact / revision-2 `action` field | **Document as the contract for 0.1.x.** |
| LB5 | CLI report has no schema version; `version` is the product version. `--json` is the machine interface (`docs/guides/cli.md`). | A consumer cannot detect a report change except by product version. | (a) additive-only commitment (done in the draft); (b) add `schemaVersion` now (additive, so it can follow stable) | **(a)** now; (b) is optional and non-breaking later. |
| LB6 | Finding `type` and `detector` strings are open sets that have already changed incompatibly once (`vercel_token` split in beta.12). | A consumer that switches on `type` breaks when a type is split or renamed. | (a) Name it a breaking-class change in the contract; (b) freeze the set (not possible while coverage grows) | **(a).** Included in the draft's compatibility classes. |
| LB7 | `IncrementalSanitizer` has seven constructors, asymmetric (no `with_common_built_in_and_pii` without a policy); adding rulesets or a third profile would add more. | Not breaking: constructors are additive. Ergonomics and growth. | Freeze the seven; or add an options struct now | **Freeze the seven.** "No new public API solely to make a checklist look complete" (epic non-goals). |
| LB8 | Error codes as an open set in JavaScript (`SecretScanErrorCode` union, 27 members) and Python (one exception class per code). | A TypeScript `switch` with a `never` default breaks when a code is added. | Document "unknown codes are failures" | **Document** (done in the draft). |
| LB9 | CLI exit status on an internal panic is `101` or a signal; the exit-code table lists `0`/`1`/`2`. | A caller that matches only `2` for failure misses `101`. | (a) Document: any other status is an internal failure; (b) catch panics at `main` and exit `2` | **(a).** See below. |

### CLI panic exit status

[#1130](../1130/README.md) measured that a CLI panic exits `101` (unwind, the
shipped strategy) with a sanitized prefix flushed, or dies by `SIGABRT` with
none (the rejected abort strategy), and never writes an unsanitized byte. The
README tables list `0`, `1`, `2`. Decision: **documentation, not a new
contract.** Reasons: the workspace denies `panic!`, `unwrap` and `expect` by
lint, so a panic is a defect, not a supported outcome; `catch_unwind` at `main`
would cover only unwinding panics and not an out-of-memory abort, a stack
overflow or a signal, so it would promise an `exit 2` it cannot always deliver;
and it would add an unwind-safety obligation to code that currently has none.
The guide and the CLI README now say that any other status is an internal
failure to treat as `2`, with output discarded. The CLI `--help` text (a
guarded source file) is unchanged and should gain the same sentence in the
next change that touches it.

### Documentation corrections made

| File | Change | Why |
| --- | --- | --- |
| `docs/guides/javascript.md` | The size sentence now links `reference/detection.md#detector-profiles` (gzip sizes of the default builds) and the [#1127 measurement](../1127/README.md) (raw, gzip and brotli for all four assets). | It pointed to `reference/api-contract.md#detector-profiles`, which has no sizes; [#1127](../1127/README.md) recorded the gap for this card. |
| `docs/guides/cli.md`, `crates/secret-scan-cli/README.md` | Added the "any other status" sentence. | LB9. |
| `docs/guides/rulesets.md` | Added "Default action". | A true statement of today's behavior that the guide omitted (LB4); it names no change. |

## Defects found, not fixed here

| Severity | Defect | Evidence | Suggested handling |
| --- | --- | --- | --- |
| Low to medium | Ruleset parser accepts a repeated field (last wins) although the guide and the parser's own comment say each field is required exactly once. | [#1072](../1072/README.md) R1 | Fix in Beta.13 |
| Low to medium | A ruleset `prefix` containing an invisible or format character loads and can never match. | [#1072](../1072/README.md) R2 | Fix in Beta.13 |
| Low | `run: at-least +20` and `020` are accepted. | [#1072](../1072/README.md) R3 | Fix in Beta.13 |
| Low (evidence) | `conformance/fixtures/ruleset-reference.json` says every surface runs it; the Node addon and WebAssembly artifact do not, and the CLI runs it only in part. All 31 checks pass on the Node addon in a one-off run. | [#1072](../1072/README.md) R6 | Add runners, or correct the description |
| Low (docs) | `packages/javascript/src/types.ts` `IncrementalLimits` doc comment says "UTF-16 code-unit limits"; the fields are UTF-8 byte ceilings. | LB2 | Comment fix |
| Low (docs) | The `lib.rs` crate documentation lists the overlap keys without the first one (resolved-action severity), and `sanitize_with_profile`'s rustdoc omits the run-time-profile link warning that the Rust guide carries. | `pipeline.rs` `RankedCandidate::priority`; [#1127](../1127/README.md) | Doc fix |
| Low (docs) | The ruleset ADR says the core has no dependencies and 12 rejection classes; the core now depends on `unicode-normalization` and the catalog has 18 classes. | `crates/secret-scan-core/Cargo.toml`, `ruleset.rs` | Amend the ADR text when R7 is written |
| Low (docs) | 23 of the 44 names in `redact_secret.__all__` appear in no guide, reference or README: 17 exception classes (all but `SecretScanError`, `InvalidInputError`, `InputLimitExceededError`, `FindingLimitExceededError`, `InvalidRulesetError`, `PiiActivationConflictError`), `PolicyContext`, `PlaceholderContext`, `IncrementalPolicyContext`, `IncrementalResult`, `default_policy`, `default_incremental_policy`. They are declared and tested; only the prose is missing. Every Rust root name and every JavaScript export is documented. | scripted name search over `docs/guides`, `docs/reference`, `README.md`, the Python README and `troubleshooting.md` | Add a Python error table to the Python guide ([#1070](https://github.com/redact-secret/redact-secret/issues/1070)) |
| Info (flaky test) | `adversarial_bounds` runtime-cap tests and one JavaScript stream test time out under heavy host load; both passed in isolation (below). | [Verification](#verification) | Known; control is the same commit |

## Verification

Everything below ran on one source commit,
`4069e52a7eed84274069541498fa08aaed8d3ffe`, with conformance tree identity
`e4609c2025634872ff000bb036a061b2d1e661f5` (`git rev-parse HEAD:conformance`),
on one Apple M4 (macOS arm64) host. This is a source-checkout run of the
repository's own scripts. It is **not** a run against published or candidate
artifacts, which is what closing [#199](https://github.com/redact-secret/redact-secret/issues/199)
needs.

| Runtime | Command | Result |
| --- | --- | --- |
| Rust core, canonical corpus, ruleset, incremental partitions, PII, public API | `cargo test --workspace --locked --no-fail-fast` | 2,635 tests passed across 68 test targets, none failed (`canonical_corpus`, `ruleset_conformance`, `public_api`, `incremental_partitions`, `adversarial_bounds`, the CLI's `cli.rs`, doc tests). A first run, before this one, failed the `adversarial_bounds` runtime-cap tests while the host load average was above 60; the same commit passed once the load fell. |
| Python (PyO3, abi3, CPython 3.14.7) | `maturin develop` then `pytest bindings/python/tests` (includes `test_conformance.py`, the incremental, PII, ruleset and AI-context corpora) | 9,084 passed |
| Node.js addon, `full` | `node scripts/qualify-node-addon.mjs --target aarch64-apple-darwin` (inspect, smoke, canonical corpus on the real addon, package public API, Node stream adapter) | passed |
| Node.js addon, `common` | same with `--detector-profile common` | passed |
| JavaScript package | `npm run js:test` | 187 passed, 8 skipped, 1 timed out at 5 s under host load (`stream-argument-limit`); the file passed 4 of 4 on a rerun with `--testTimeout=120000` |
| JavaScript declarations | `npm run js:typecheck` (builds the package, type-checks the tests and the Markdown examples) | passed |
| Examples | `npm run examples:install && npm run examples:test` (adapters installed from the registry) | 65 of 65 |
| CLI | `cargo build --release -p redact-secret-cli`, `node scripts/qualify-cli-binary.mjs` (identity, exit codes, canonical corpus through `--json`, `--redact` byte for byte) | passed |
| WebAssembly through Node (fallback loader), `full` and `common` | `build-browser-artifact.mjs` then `qualify-node-wasm-fallback.mjs` | passed |
| WebAssembly in real engines | `qualify-browser-artifact.mjs` for Chromium, Firefox and WebKit, `full` and `common` artifacts | all six passed |
| Ruleset fixture on every surface | [#1072](../1072/README.md#cross-runtime-conformance) | Rust, Python, Node addon, WebAssembly, CLI: all pass; only Rust and Python are CI-gated |
| Documentation checks | `audits-index:check`, `doc-links:check`, `docs-reachability:check`, `cross-repo-links:check`, `json-path-citations:check`, `decisions:validate` | `npm run check:docs` passed |

Not run, and why:

- **Published or candidate artifacts, and the clean-install paths**
  (`artifacts:check`, `golden-path:qualify`, `workerd:qualify`, release
  rehearsal): they need the candidate artifact set, which is #1069's track.
- **Other operating systems and architectures** (Linux, Windows, x86-64, musl),
  **Node.js 20 and 24**, **Python 3.10 to 3.13**: one host with one Node and one
  Python.
- **The 8 skipped JavaScript tests** are skipped by the suite itself.
- **`adversarial_bounds` runtime caps** time out when the host is saturated (this
  host's load average was 40 to 80). The result for that binary is in the Rust
  row.
- **A run against `redact-secret-benchmarks`**: measurement, not conformance.

## Decisions needed from the owner

1. **Accept the draft contract** in `docs/reference/api-contract.md` (or amend
   it), and decide the version number a breaking change costs (the draft marks
   this open). The matching decision record is not written.
2. **LB1**: add `#[non_exhaustive]` to `SecretScanErrorCode` and `Profile`
   before the freeze? Recommended yes.
3. **LB2**: correct the JavaScript incremental limit names additively, or
   freeze the misnomer with a documented unit? Recommended additive aliases.
4. **#1072 D1 to D4**: the ruleset disposition (recommended: revise before
   stable, then freeze) and its three smaller choices.
5. **#199**: closing it needs a run of this verification against the exact
   candidate artifacts (published packages, not a source checkout). That
   happens at candidate qualification, not here.

## Reproduce

```bash
export CARGO_TARGET_DIR=$PWD/.target CARGO_BUILD_JOBS=4
cargo test --workspace --locked --no-fail-fast
python3 -m venv .venv && . .venv/bin/activate
pip install pytest && maturin develop --locked --manifest-path bindings/python/Cargo.toml
python -m pytest bindings/python/tests -q
npm ci --ignore-scripts && npm ci --prefix bindings/node --ignore-scripts
(cd bindings/node && npx napi build --platform --release)
node scripts/qualify-node-addon.mjs --target aarch64-apple-darwin
node scripts/qualify-node-addon.mjs --target aarch64-apple-darwin --detector-profile common
npm run js:test && npm run js:typecheck
cargo build --release --locked -p redact-secret-cli
node scripts/qualify-cli-binary.mjs --binary .target/release/redact-secret
node scripts/build-browser-artifact.mjs --out-dir wasm-full
node scripts/qualify-node-wasm-fallback.mjs --wasm-dir wasm-full
```

## Implementation

Owner decisions D5 and D6 were implemented on `workbench/1184-1185-api-docs`.

### #1184: LB1 and LB2

- **LB1 (D5).** `SecretScanErrorCode` and `Profile` are `#[non_exhaustive]`. The only exhaustive `match` expressions outside the core crate were in `bindings/node/src/lib.rs` (five over `Profile`), `bindings/python/src/lib.rs` (`map_error_code`) and `crates/secret-scan-core/tests/sanitize_golden_path_1078.rs`; each gained a wildcard arm. The CLI, the WebAssembly binding, the examples and the other tests had none. `Action`, `Confidence`, `Specificity` and `SessionState` are unchanged.
- **LB2 (D6).** `IncrementalLimits` accepts `maxInputBytes`, `maxBufferedBytes`, `maxTokenBytes` and `maxMultilineBytes` as aliases of the four `CodeUnits` names. The public wrapper (`packages/javascript/src/runtime.ts`) resolves them once, so the Node addon and the WebAssembly binding keep receiving the legacy shape and need no alias of their own. Precedence: one name per limit uses it; both names with equal values are accepted; both with different values, a missing limit, or an invalid value in either name throw `INVALID_LIMITS`; an explicitly `undefined` field counts as not given. `packages/javascript/test/incremental-limit-aliases.test.ts` covers both binding shapes and the unchanged old names. The contradicting "UTF-16 code-unit limits" comment is replaced.

### #1185: documentation gaps

- `crates/secret-scan-core/src/lib.rs` now lists resolved-action severity as the first overlap key, matching `RankedCandidate::priority`.
- `sanitize_with_profile`'s rustdoc carries the run-time-profile link note and points to `with_common_built_in`.
- The ruleset ADR (`decision-define-declarative-detector-ruleset-contract`) is amended in place, as the profile/pack ADR already is: the core depends on `unicode-normalization` (and its `tinyvec`), and the catalog is 18 rejection classes; the decision itself is unchanged. The ADR text listed 13 classes, not 12; the five added at implementation (`RulesetTooLarge`, `PrefixTooLong`, `NameBucketNotClaimable`, `NameTooLong`, `TooManyNames`) are now listed.
- `docs/guides/python.md` gained an exception table (all 23 exception names, with `code` and when raised, and the "set grows" wording) and a table of the callback context types and default policies.
