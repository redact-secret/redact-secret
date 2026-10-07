# API concepts and contracts

[Documentation home](../README.md)

| Operation | JavaScript | Python / Rust | Result |
| --- | --- | --- | --- |
| Detect and apply policy | `scan` | `scan` | Findings |
| Replace supplied ranges | `redact` | `redact` | Text |
| Both together | `scanAndRedact` | `scan_and_redact` | Text and findings |
| Supported defaults, Rust only | none | `sanitize`, `sanitize_with_profile` | Text and findings, as `scan_and_redact` |
| Compare action policies, preview only (whole input) | `compareActionPolicies` | `compare_action_policies` (Python and Rust); the CLI's `--compare-action-policy` | Per-finding actions and reasons for 1 to 4 policies over one detection pass, no text |

Bindings adapt arguments and results; they do not copy detector logic. Rust
additionally takes a registry, policy, and formatter; `sanitize(input)` and
`sanitize_with_profile(input, Profile)` are the one-call Rust path over the
built-in registry, `DefaultPolicy`, the default placeholder formatter, and the
default whole-input limits, with no custom detectors
([Rust guide](../guides/rust.md)). Python uses optional
`policy` and `formatter`; JavaScript uses an options object with `policy` and
`placeholderFormatter`.

Whole-input operations are bounded by default to 64 MiB of input and 50,000
findings (`decision-bound-whole-input-operations-by-default`). Exceeding a
bound fails with `INPUT_LIMIT_EXCEEDED` or `FINDING_LIMIT_EXCEEDED` rather
than truncating. Raise or lower it with JavaScript's
`limits: { maxInputBytes, maxFindings }` option, Python's
`limits=WholeInputLimits(...)`, or Rust's `WholeInputLimits` with
`scan_with_limits`, `redact_with_limits`, and `scan_and_redact_with_limits`.

## Findings and coordinates

Each finding has `id`, `type`, `detector`, `confidence`, `action`,
`obfuscation`, `start`, and `end` (Rust exposes methods and a range object).
`obfuscation` is `none`, or `invisible-characters` when zero-rendering or
format code points were removed from the matched span before detection. No
matched value is included.
Ranges are half-open: `start` is included and `end` excluded.

| Surface | Unit | Exported `RANGE_UNIT` |
| --- | --- | --- |
| JavaScript | UTF-16 code units | `utf16-code-units` |
| Python | Unicode code points | `unicode-code-points` |
| Rust and CLI | UTF-8 bytes | `utf8-bytes` |

All offsets refer to original input. For example, `🔑 ` before a finding adds
3 JavaScript units, 2 Python code points, or 5 UTF-8 bytes. Do not copy numeric
positions between runtimes without converting against the same input. The
conformance corpus's schema label `utf8-byte` names the same byte coordinate
system; it is a separate field from runtime `rangeUnit`.

Within a scan, findings are sorted by position and numbered from `finding-1`.
Incremental sessions use absolute positions and continuous numbering. CLI
multi-file reports renumber findings across the run. IDs are not persistent
identities across changed inputs or separate scans.

## Overlap and replacement

Candidate precedence is resolved-action severity (`block` > `redact` > `warn`
> `allow`, by the default classification), specificity, confidence, narrower
span, detector order, then emission order. The pipeline selects the
non-overlapping subset with the greatest total evidence weight, not a greedy
walk, so a weaker candidate never displaces an overlapping stricter one, but
several disjoint candidates can outweigh one overlapping candidate that ties
them on the stronger keys. A policy runs on the selected findings afterward.

Direct `redact` accepts unsorted findings, sorts them, and rejects overlaps,
invalid bounds, and ranges off character boundaries. It does not resolve
conflicting caller-supplied findings. Use the same original input that was
scanned; validation cannot establish that a finding belongs to that input.

Only `redact` and `block` consume placeholders. Default labels are `<SECRET_1>`,
`<SECRET_2>`, etc.; `warn` and `allow` preserve input. Placeholders are not an
encoding of the removed text and cannot be used to recover it. Numbering restarts
at 1 on every call; a host that scans several leaves of one request offsets the
index in its own formatter, as the [Rust](../guides/rust.md#request-wide-placeholder-numbering),
[JavaScript](../guides/javascript.md#request-wide-placeholder-numbering) and
[Python](../guides/python.md#request-wide-placeholder-numbering) guides show. The
core provides no helper for it.

## Detector profiles

Two detector profiles exist: `full` (every built-in detector, the default and
compatibility baseline everywhere) and `common` (a smaller, opt-in
structural/contextual subset for preventive use). The `@redact-secret/core`
root and `./common` entry points (in Node, browser, and `workerd` builds;
`./common/node-stream` and `./common/web-stream` bind streams to `common`)
and the Rust `DetectorRegistry`/
`IncrementalSanitizer` constructors expose which profile they were built
from — the `PROFILE` constant in JavaScript (`"full"` on the root export,
`"common"` on `./common`), and `DetectorRegistry::profile()` /
`IncrementalSanitizer::profile()` in Rust. JavaScript `initialize()` rejects
with `INITIALIZATION_FAILED` if the loaded artifact reports a
different profile than the entry point that loaded it, the same detail-free
rejection an unusable or version-mismatched artifact already gets. Python and
the CLI expose `full` only. See [detection coverage](detection.md#detector-profiles)
for profile membership and the false-negative tradeoff, and the
[JavaScript](../guides/javascript.md#detector-profiles) and
[Rust](../guides/rust.md#detector-profiles) guides for per-runtime usage.

## Status query

`status()` (JavaScript, root and `./common`) and `redact_secret.status()`
(Python) report whether the binding is initialized and its public activation
without initializing or reconfiguring anything. They take no input, never
throw or raise, and return only fixed fields: `initialized` (boolean),
`profile` (`"full"` or `"common"`) and `activation` (the `piiActivation()` /
`pii_activation()` identity once initialized, otherwise `null` / `None`). Both
types are named `CoreStatus`. They are additive stable names, not available in
releases before the one that adds them, and they are not a detection-readiness
claim. The Rust crate and the CLI add nothing: Rust has no lifecycle to query
and the CLI runs one shot. A core-published synthetic readiness probe is
deliberately not part of the contract
([`decision-add-a-side-effect-free-status-query-and-defer-a-published-readiness-probe`](../decisions/2026-10-05-add-a-side-effect-free-status-query-and-defer-a-published-readiness-probe.md)).

## Artifact manifest

`artifact-manifest/v1` says what the exact loaded artifact contains, without a
scan and without initializing anything: build identity, the built-in detectors
in canonical order with their pack and the finding types each can emit, whether
the PII runtime is linked, capabilities, build defaults, bounds and a digest.
The Rust core generates it from the registration rows the artifact links, so
every surface forwards one value and keeps no detector table of its own.

| Surface | Name |
| --- | --- |
| Rust | `ArtifactManifest::full` / `::common`, `ArtifactKind`, `ArtifactManifestError` |
| JavaScript (root and `./common`) | `artifactManifest()`, types `ArtifactManifest`, `ArtifactManifestDetector` |
| Python | `redact_secret.artifact_manifest()` (a `dict`) |
| CLI | `--print-artifact-manifest` (one JSON line, reads no input, accepts no other argument) |

`detectors[].types` is each built-in's declared list, not a closed vocabulary:
a ruleset, a custom detector and the PII adapter emit other types, and
`typeVocabulary.complete` is `false`. The document holds no input, ruleset,
literal, path, host name or timestamp, and reading it builds no registry and
reads no PII selection. In JavaScript it reports the artifact `initialize()`
loaded, and `initialize()` rejects with `INITIALIZATION_FAILED` when the
manifest is missing from an artifact that should report one, or has another
schema, version or variant, or a digest that is not its own, echoing none of it.
`status()` is unchanged; no runtime detector selection exists yet, and the
manifest says so (`capabilities.detectorSelection` is `false`)
([`decision-define-the-artifact-manifest-and-configuration-data-contracts`](../decisions/2026-10-07-define-the-artifact-manifest-and-configuration-data-contracts.md)).

## Errors and extensions

Failures use fixed codes and input-free messages. JavaScript exposes
`SecretScanError`; Python has subclasses of the same name; Rust returns
`SecretScanError` in `Result`. [Troubleshooting](../troubleshooting.md) covers
common causes. Policy and formatter callbacks are supported across languages;
custom detector callbacks are a direct Rust surface only.

## Stable contract 1

> **Accepted by the owner on 2026-10-02 for the 0.1.x series.** The policy
> behind this section is decided by
> [`decision-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes`](../decisions/2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md)
> and, for declarative rulesets,
> [`decision-define-declarative-ruleset-revisioning`](../decisions/2026-10-02-define-declarative-ruleset-revisioning.md).
> The name-by-name audit, the surfaces that were likely to break, the owner
> decisions and the verification this rests on are in the
> [contract audit](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1066/README.md) and the
> [ruleset audit](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1072/README.md). Conformance against the
> exact candidate artifacts is a separate, later step
> ([#199](https://github.com/redact-secret/redact-secret/issues/199)).

### What the contract covers

| Surface | Covered | Not covered |
| --- | --- | --- |
| Rust | The 72 names the `redact_secret` crate root exports, pinned by `core-public-api` in the workspace manifest and by `tests/public_api.rs` | Every private module; `Detector` implementations you write |
| JavaScript | `@redact-secret/core` and its subpaths `./common`, `./node-stream`, `./web-stream`, `./common/node-stream`, `./common/web-stream`: exported functions, constants, classes and types | `@redact-secret/wasm`, `@redact-secret/node` and the platform packages: installed as dependencies, not for direct use, versioned only in lockstep |
| Python | Names in `redact_secret.__all__` and the shipped `.pyi` stubs | `redact_secret._native` and anything not re-exported |
| CLI | Arguments, exit codes `0`/`1`/`2`, the `--json` report fields, standard-stream behavior | The line-per-finding text format (it is for people; parse `--json`), and diagnostic wording beyond the fixed code |
| Conformance | The fixtures under `conformance/fixtures/` define behavior for every surface above | Fixture file layout and the runners |

Detection coverage is not part of this contract. Which credentials are found
is governed by the [support matrix](../support-matrix.md) and the detection
reference; the contract says how findings are reported, not which exist.

### Compatibility classes

| Class | Meaning | Examples | Rule |
| --- | --- | --- | --- |
| Breaking | A correct call stops compiling, stops working, or changes what a documented value means | Removing or renaming an export; changing a signature, a range unit, an action's meaning, an error code's meaning or a ruleset field; adding a variant to a Rust enum that is not `#[non_exhaustive]`; changing a published finding `type` or `detector` string (rename, split, remove) | Needs a contract review and a `Changed` entry; never in a patch release. While the major version is 0, a breaking change to a stable surface bumps the minor version (0.2.0). |
| Additive | A new name, option, accepted input, error code or `type`/`detector` value that existing correct code can ignore | A new export; a new optional argument; a new finding type; a new error code (consumers must treat error codes as an open set) | Needs a changelog entry and a manifest review where the Rust root changes. Ships in a patch release (0.1.x). |
| Behavioral | The same call returns different findings, spans or timing | A new detector, a tuned span, fewer or more redactions, the default policy's always-redact set growing | Changelog entry; covered by the evidence and support matrix, not frozen. Ships in a patch release (0.1.x). |
| Internal | Everything outside the "Covered" column | Private modules, `_native`, wasm glue | No promise. |

### Frozen behavior

**Operations.** `scan`, `redact` and `scanAndRedact` (`scan_and_redact`) keep
the semantics in this document: findings are sorted by position, numbered
`finding-1`..., half-open, and index the original input; overlap precedence is
the documented order; `redact` validates caller findings and replaces only
`redact`/`block` ranges; identical input and configuration give identical
output. Whole-input calls are bounded by default (64 MiB, 50,000 findings) and
fail rather than truncate.

**Python result objects.** `ScanResult` and `IncrementalResult` are immutable:
they have no setters. `.text` is a `str`, and `.findings` is a `list` of
`Finding` objects in input order. In 0.1.x each read of `ScanResult.findings`
returns a new list that holds the same cached `Finding` objects, so reading it
is cheap, mutating the list you got never affects the result or another read,
and `Finding` cannot be mutated. Do not depend on whether two reads, or the
elements of two reads, are the same object. The `list` type is part of the
contract: changing `.findings` to a `tuple` (immutable, O(1) per read) would
break callers that append, sort, test `isinstance(x, list)` or compare with a
list, so it is a breaking change that needs a minor version bump. Callers in a
hot loop read `.findings` once into a local variable.

**Range units.** UTF-16 code units (JavaScript), Unicode code points
(Python), UTF-8 bytes (Rust and CLI). Frozen per surface; the exported
`RANGE_UNIT` names it.

**Errors.** Every failure carries a fixed code and an input-free message. The
23 core codes (the latest is `INVALID_ACTION_POLICY`) are identical in Rust, JavaScript and Python; JavaScript adds
five host codes (`NOT_INITIALIZED`, `INITIALIZATION_FAILED`, `INVALID_CHUNK`,
`INVALID_UTF8`, `UNPAIRED_SURROGATE`). A lone surrogate cannot reach the core
in either host: JavaScript rejects it with `UNPAIRED_SURROGATE`, Python with
`InvalidInputError`. The set of codes grows over time; handle an unknown code
as a failure. Rust's `SecretScanErrorCode` and `Profile` are
`#[non_exhaustive]`, so a `match` over either needs a wildcard arm and a new
variant is not a breaking change. `Action`, `Confidence` and `Specificity`
stay exhaustive by design: they are closed sets, and a new variant changes
pipeline semantics (a breaking change).

**Policy and placeholder callbacks.** They receive safe metadata only (never
the input or a matched value). A policy returns one of `redact`, `block`,
`warn`, `allow`, exactly once per selected finding in order; anything else is
`INVALID_POLICY_ACTION`, a throw is `POLICY_FAILURE`. A formatter returns a
non-empty placeholder of at most 256 bytes that reproduces no finding's
matched value; otherwise `INVALID_PLACEHOLDER` (a throw is
`PLACEHOLDER_FAILURE`). JavaScript policies are objects with `evaluate`,
Python and Rust policies are callables; the behavior is the same.

**Incremental and streaming.** A session requires explicit limits (no
defaults), keeps findings absolute, evaluates policy once per final finding,
and for accepted input produces output and findings equal to one whole-input
operation at every chunk partition. A failure leaves a sanitized, incomplete
prefix and a terminal state; the states are `accepting`, `finalized`,
`aborted` and `failed`.
The four limits are UTF-8 byte ceilings on every surface. The JavaScript
fields `maxInputCodeUnits`, `maxBufferedCodeUnits`, `maxTokenCodeUnits` and
`maxMultilineCodeUnits` say code units but count bytes, so `maxInputBytes`,
`maxBufferedBytes`, `maxTokenBytes` and `maxMultilineBytes` are accepted as
additive aliases. The old names are deprecated, keep working and are not
removed. Naming both spellings of one limit with different values is
`INVALID_LIMITS`. Sessions accept no custom detector and no ruleset, on any
surface.

**Detector profiles and PII.** `full` is the default and the authoritative
baseline; `common` is a smaller structural/contextual subset for preventive
use and by design reports fewer findings. Python and the CLI expose `full`
only. In Rust, call `DetectorRegistry::with_common_built_in` (or
`IncrementalSanitizer::with_common_built_in`) for `common`: a run-time
`Profile` value passed to `sanitize_with_profile` links both profiles. PII is
off unless selected, with the selector grammar and activation identity of the
PII contract; a selected family's support level is the support matrix's, not
this contract's.

**Declarative rulesets.** `ruleset-revision: 1` is the grammar in the
[rulesets guide](../guides/rulesets.md); it rejects repeated fields,
invisible-character prefixes and non-canonical counts. A ruleset can add detections and can never outrank a
built-in; every ruleset detection is medium confidence, so under the default
policy it is `warn` and `redact` leaves its text unchanged unless the caller's
policy says otherwise (the CLI has no policy hook, so `--redact` never changes
text for a ruleset match). Revision 1 is frozen byte for byte; any new
alphabet, validator, field or bound is revision 2, and revision 1 stays
supported through the major series in which revision 2 ships and the next
one. Unknown revisions, fields and vocabulary are rejected, never skipped.
JavaScript ruleset errors keep one fixed message per code, with no
rejection-class field in 0.1.x (an additive optional field may follow); Rust,
Python and the CLI report the class. A ruleset is one per call, applies
to whole-input calls only, and is available on Rust, JavaScript (Node and
WebAssembly), Python and the CLI with an explicit file source.

**Custom extension boundary.** Rust consumers may implement `Detector` and
register it: trusted in-process code, not a sandbox. JavaScript and Python
have no custom detector callback and will not get one; their extension is the
ruleset. No surface performs network access, and a detector, policy or
formatter never receives more than its documented inputs.

**CLI.** Exit `0` (clean), `1` (check mode found something), `2` (usage,
decoding, limit, read or write failure). Any other status (for example `101`
from a panic, or death by signal) is an internal failure outside the contract:
treat it as a failure and discard the output. Standard output may then hold a
sanitized, incomplete prefix; the CLI never writes an unsanitized byte. The
`--json` report keeps its field set (`version`, `rangeUnit`, `findingCount`,
`sources`, `failures`) and may only add fields.

### Completeness of `Ok`

A *whole-input call* is one call that receives the entire input and returns
once: Rust `scan`, `redact`, `scan_and_redact`, their `_with_limits` siblings
and `sanitize`/`sanitize_with_profile`; JavaScript `scan`, `redact` and
`scanAndRedact`; Python `scan`, `redact` and `scan_and_redact`; and a file path
given to the CLI. This holds with or without a profile, a PII selection or a
ruleset. The incremental API, the JavaScript stream adapters and CLI standard
input are not whole-input calls; their own rule is the last row of the table.

**`Ok` means complete inspection.** When a whole-input call returns a value
(`Ok` in Rust, a returned value in JavaScript and Python, exit status `0` or
`1` for a CLI check source, `0` for a CLI redaction), every detector of the
registry the call selected has examined the whole normalized input, the policy
ran on every selected finding, and every replacement was formatted and
validated. Every other outcome is an error: `Err`, a thrown `SecretScanError`,
a raised `SecretScanError` subclass, or CLI exit status `2`. There is no
partial success, no "truncated" flag and no per-detector status in a result,
and no error carries findings or redacted text beside it.

This is part of the stable contract. Under the
[compatibility ADR](../decisions/2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md),
changing what a documented value means is a breaking change, which bumps the
minor version while the major version is 0. A future time budget, deadline or
best-effort mode therefore has to be opt-in and additive, and it must not make
a partial result look like `Ok`: it needs its own option and its own error
code or result type. Consumers that treat `Ok` as the only completeness signal
stay correct across 0.1.x.

| Fact | Evidence |
| --- | --- |
| A limit breach fails the whole call and nothing is truncated. `max_input_bytes` is checked before any detection work; `max_findings` is checked after detection and before the policy runs, so a finding-limit breach also discards the redacted text rather than returning the first findings. | `WholeInputLimits::check_input` and `check_findings` (`crates/secret-scan-core/src/limits.rs`), `scan_with_limits` and `scan_and_redact_with_limits` (`src/pipeline.rs`). Tests: `an_input_one_byte_over_the_byte_bound_is_rejected_with_input_limit_exceeded`, `a_finding_count_one_over_the_bound_is_rejected_with_finding_limit_exceeded` (`tests/whole_input_limits.rs`); `input_limit_error_is_identical_and_not_truncated`, `finding_limit_error_is_identical` (`tests/sanitize_golden_path_1078.rs`); the Node, WebAssembly and Python bindings repeat the limit cases (`bindings/node/src/lib.rs`, `bindings/wasm/src/lib.rs`, `bindings/python/tests/test_whole_input_limits.py`). |
| A detector failure, an invalid candidate, a policy failure, a placeholder failure and an invalid placeholder each fail the whole call with their own fixed code. A callback that throws or raises never yields `Ok`. | `collect_candidates`, `validate_candidate` (`src/pipeline.rs`); `redact_shifted_into` (`src/redact.rs`). Tests: `detector_failure_is_reported_with_a_fixed_code_and_no_payload`, `policy_failure_is_reported_with_a_fixed_code_and_no_payload`, `first_invalid_candidate_fails_the_whole_scan` (`tests/pipeline.rs`); `scan_and_redact_reports_the_error_of_whichever_stage_fails` (`tests/public_api.rs`); `bindings/python/tests/test_callback_failure.py`. |
| An invalid ruleset, an invalid or unavailable PII selection, invalid limits and invalid input (such as a lone surrogate) are errors raised before any scan result exists. | `load_ruleset` (`src/ruleset.rs`), `PiiSelection::parse` (`src/pii.rs`), `WholeInputLimits::new` (`src/limits.rs`). Tests: `every_declared_rejection_class_is_reproduced` (`tests/ruleset_conformance.rs`); the `PiiSelectorUnsupported` and `PiiSelectorUnavailable` cases in `src/pii.rs`; `new_rejects_a_zero_max_input_bytes` (`tests/whole_input_limits.rs`); `a_malformed_ruleset_fails_the_whole_run_before_any_source_is_scanned` (`crates/secret-scan-cli/tests/cli.rs`). |
| A detector is skipped only when the shared literal prefilter shows that none of the detector's declared required literals occurs in the input. Such a skip cannot change the result, so it does not weaken the statement above. | `collect_candidates` (`src/pipeline.rs`). Test: `tests/prefilter_soundness.rs` (debug builds only: every skipped detector is run and must propose nothing). |
| No partial text is returned beside an error. The Rust return types carry a value or an error, never both. `redact` formats and validates every placeholder before it writes a byte, so a failing formatter leaves no partial output. The crate-internal `redact_into` leaves a caller-supplied buffer untouched on error; no public function takes an output buffer in 0.1.x. | `redact_shifted_into` (`src/redact.rs`, "Phase 1" and "Phase 2"). Test: `redact_into_appends_what_redact_returns_and_is_untouched_on_error` (`src/redact.rs`). |
| `Ok` describes inspection, not the policy outcome. Under the default policy a `warn` or `allow` finding stays in the returned text, and a credential format no detector covers is not found. Check the actions of the findings to see what was replaced. | [Policy and safe integration](../guides/safe-integration.md#actions-are-decisions-your-host-consumes); [detection coverage](detection.md). |
| CLI file sources follow the whole-input rule: a source that cannot be read, decoded or scanned contributes a failure and no findings, and a `--redact` run over a file writes nothing before the call returns `Ok`. In a multi-file check, sources that were scanned are still reported in full, and exit status `2` outranks `1`. A write failure during `--redact` (for example a closed pipe) can still leave a sanitized prefix on standard output. | `check_file`, `redact` (`crates/secret-scan-cli/src/modes.rs`). Tests: `a_malformed_file_fails_closed_and_is_not_scanned_in_part`, `a_failure_outranks_a_finding`, `a_closed_downstream_pipe_fails_the_run_instead_of_hanging` (`crates/secret-scan-cli/tests/cli.rs`). |
| **Incremental sessions, stream adapters and CLI standard input are not whole-input calls.** A successful `append` returns the text and findings whose detection window has closed. They are sanitized and final, but the call says nothing about the rest of the input, and text held back is not yet released. Only a successful `finalize` means the session accepted the whole input; then the concatenated output and findings equal the whole-input result at every chunk partition. A later error leaves the earlier results released: that output is a sanitized, incomplete prefix, the session is `failed`, it discards retained plaintext and it rejects every further call. `abort`, and cancelling or aborting a stream adapter, discard retained text without finalizing and are never complete. A host that needs atomic output stages it until `finalize` succeeds. CLI standard input follows this rule, so a `--redact` failure on standard input can leave a sanitized prefix on standard output together with exit status `2`. | `IncrementalSanitizer::append`, `finalize`, `abort` (`src/incremental.rs`); `stream` (`crates/secret-scan-cli/src/modes.rs`). Tests: `ordinary_closed_lines_emit_immediately_without_finalize`, `a_failure_discards_retained_text_and_rejects_every_later_call`, `a_callback_that_fails_at_finalize_never_releases_the_retained_unit` (`tests/incremental.rs`); `tests/incremental_partitions.rs` for partition invariance. No test asserts the content of standard output after a failed `--redact` run on standard input. |

### Cancellation and time bounds

There is no cancellation, no deadline and no work budget in 0.1.x. This is the
current contract, stated here so that no consumer has to infer it.

| Fact | Evidence |
| --- | --- |
| Every whole-input call is synchronous. A started call runs until it returns a value or an error and cannot be interrupted. No whole-input function, option or callback takes a cancellation token, a deadline or a budget. JavaScript `scan`, `redact` and `scanAndRedact` are plain functions; only `initialize()` is asynchronous, and it loads the artifact. The Node addon and the WebAssembly binding run on the calling thread. Python releases the GIL during detection, so other Python threads keep running, but the native code does not poll for signals and the call cannot be interrupted. | `scan`, `redact`, `scanAndRedact` (`packages/javascript/src/runtime.ts`); `bindings/node/src/lib.rs`; `detect` (`bindings/python/src/lib.rs`). The names and signatures are pinned by `tests/public_api.rs` (the 72 root names), `packages/javascript/test/exact-exports.test.ts`, `packages/javascript/test/type-contracts.ts` and the Python `__all__`; no test asserts the absence of a cancellation parameter by that name. |
| Policy and formatter callbacks cannot act as a deadline. The policy runs only after detection has finished and the formatter only after the policy, so neither can cut detection short. A Rust custom `Detector` may return `DetectorFailure`, but that is the detector's own choice; the core never preempts it. | `scan_with_limits`, `scan_and_redact_with_limits` (`src/pipeline.rs`). |
| `abort()` on an incremental session, and `cancel()` or `abort()` on a stream adapter, discard retained plaintext between calls. They cannot interrupt an `append` or `finalize` that is already running. | `IncrementalSanitizer::abort` (`src/incremental.rs`); `WebStreamSanitizer` (`packages/javascript/src/adapters/web-stream-core.ts`). Tests: `abort_rejects_every_later_call` (`tests/incremental.rs`), `packages/javascript/test/adapters/`. |
| The only bounds are `max_input_bytes`, 64 MiB (67,108,864 bytes), and `max_findings`, 50,000. Both fail closed, as described in the previous section. They bound input size and finding count, not running time: the time a call takes depends on the host, the build, the profile, the PII selection, the ruleset and the content of the input. A CLI file source uses the same 64 MiB bound, and CLI standard input runs under the explicit incremental limits that `--help` lists. | `DEFAULT_MAX_INPUT_BYTES`, `DEFAULT_MAX_FINDINGS` (`src/limits.rs`); `crates/secret-scan-cli/src/limits.rs`. Tests: `default_matches_declared_constants` (`src/limits.rs`), the 50,001-finding and 64 MiB + 1 cases in `tests/sanitize_golden_path_1078.rs`. No test asserts the literal values 67,108,864 and 50,000. |
| The repository does not publish a worst-case cost bound. The adversarial tier of the synchronous corpus declares, per fixture, `maxInputBytes`, `maxFindings` and `maxRuntimeMs`, and `tests/adversarial_bounds.rs` asserts them on the whole-input and the incremental path (an optimized build against the declared value, a debug build against 32 times it). At 0.1.0-beta.13 the declared runtime caps are 250 to 300 ms and the largest adversarial input is 337,521 bytes. These are test-only caps meant to catch superlinear blowup. They name no reference hardware, they can fail when the host is heavily loaded, and they say nothing about inputs near the 64 MiB ceiling. Do not read them as a per-byte or per-call guarantee. | `conformance/fixtures/synchronous-corpus.json`; `crates/secret-scan-core/tests/adversarial_bounds.rs`. |

A host must therefore size `max_input_bytes` to the CPU time and memory it is
willing to hold until a call really returns, and measure on its own hardware
with its own profile and rulesets. A host that needs a hard deadline runs the
scan where it can terminate the worker (a thread, a child process or a
JavaScript worker), discards everything that worker produced and treats the
request as failed. Dropping a promise, abandoning a future or timing out an
await does not stop the scan or release what it holds. See
[Policy and safe integration](../guides/safe-integration.md#completeness-limits-and-deadlines).

Adding an opt-in cooperative cancel or deadline check is an additive change:
it does not alter what `Ok` means, because a stopped call returns an error.
Applying a default deadline or work budget to the existing calls is not
additive, since correct calls would start to fail, and is a breaking change
under the same ADR.

### Unsupported and experimental

Not part of contract 1: custom detector callbacks in JavaScript or Python;
rulesets in incremental sessions, stream adapters or CLI standard input; more
than one ruleset per call; decoding encoded input; a third detector profile;
the `@redact-secret/wasm` package used directly; detector coverage claims
beyond the support matrix.
