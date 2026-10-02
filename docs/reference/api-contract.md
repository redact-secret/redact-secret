# API concepts and contracts

[Documentation home](../README.md)

| Operation | JavaScript | Python / Rust | Result |
| --- | --- | --- | --- |
| Detect and apply policy | `scan` | `scan` | Findings |
| Replace supplied ranges | `redact` | `redact` | Text |
| Both together | `scanAndRedact` | `scan_and_redact` | Text and findings |
| Supported defaults, Rust only | none | `sanitize`, `sanitize_with_profile` | Text and findings, as `scan_and_redact` |

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
encoding of the removed text and cannot be used to recover it.

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

## Errors and extensions

Failures use fixed codes and input-free messages. JavaScript exposes
`SecretScanError`; Python has subclasses of the same name; Rust returns
`SecretScanError` in `Result`. [Troubleshooting](../troubleshooting.md) covers
common causes. Policy and formatter callbacks are supported across languages;
custom detector callbacks are a direct Rust surface only.

## Stable contract 1 (DRAFT)

> **Draft, pending owner approval.** This section is the proposed 0.1.x
> stable contract from [#1066](https://github.com/redact-secret/redact-secret/issues/1066).
> It is not in force until the owner accepts it and records the policy it
> relies on as a decision (proposed title: *Define the 0.1.x stable public
> contract and its compatibility classes*). Items marked **open** wait on an
> owner decision listed in the
> [audit record](../audits/evidence/1066/README.md), which also holds the
> name-by-name audit, the surfaces likely to break, and the verification this
> draft rests on. The declarative ruleset part follows the recommendation in
> the [ruleset audit](../audits/evidence/1072/README.md), also pending.

### What the contract covers

| Surface | Covered | Not covered |
| --- | --- | --- |
| Rust | The 54 names the `redact_secret` crate root exports, pinned by `core-public-api` in the workspace manifest and by `tests/public_api.rs` | Every private module; `Detector` implementations you write |
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
| Breaking | A correct call stops compiling, stops working, or changes what a documented value means | Removing or renaming an export; changing a signature, a range unit, an action's meaning, an error code's meaning or a ruleset field; adding a variant to a Rust enum that is not `#[non_exhaustive]`; changing a published finding `type` or `detector` string (rename, split, remove) | Needs a contract review and a `Changed` entry; never in a patch release. **Open:** which version number a breaking change costs. |
| Additive | A new name, option, accepted input, error code or `type`/`detector` value that existing correct code can ignore | A new export; a new optional argument; a new finding type; a new error code (consumers must treat error codes as an open set) | Needs a changelog entry and a manifest review where the Rust root changes. |
| Behavioral | The same call returns different findings, spans or timing | A new detector, a tuned span, fewer or more redactions, the default policy's always-redact set growing | Changelog entry; covered by the evidence and support matrix, not frozen. |
| Internal | Everything outside the "Covered" column | Private modules, `_native`, wasm glue | No promise. |

### Frozen behavior

**Operations.** `scan`, `redact` and `scanAndRedact` (`scan_and_redact`) keep
the semantics in this document: findings are sorted by position, numbered
`finding-1`..., half-open, and index the original input; overlap precedence is
the documented order; `redact` validates caller findings and replaces only
`redact`/`block` ranges; identical input and configuration give identical
output. Whole-input calls are bounded by default (64 MiB, 50,000 findings) and
fail rather than truncate.

**Range units.** UTF-16 code units (JavaScript), Unicode code points
(Python), UTF-8 bytes (Rust and CLI). Frozen per surface; the exported
`RANGE_UNIT` names it.

**Errors.** Every failure carries a fixed code and an input-free message. The
22 core codes are identical in Rust, JavaScript and Python; JavaScript adds
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

**Declarative rulesets (pending the ruleset audit).** `ruleset-revision: 1` is
the grammar in the [rulesets guide](../guides/rulesets.md), with the changes
the audit recommends (reject repeated fields, invisible-character prefixes and
non-canonical counts). A ruleset can add detections and can never outrank a
built-in; every ruleset detection is medium confidence, so under the default
policy it is `warn` and `redact` leaves its text unchanged unless the caller's
policy says otherwise (the CLI has no policy hook, so `--redact` never changes
text for a ruleset match). Revision 1 is frozen byte for byte; any new
alphabet, validator, field or bound is revision 2. Unknown revisions, fields
and vocabulary are rejected, never skipped. A ruleset is one per call, applies
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

### Unsupported and experimental

Not part of contract 1: custom detector callbacks in JavaScript or Python;
rulesets in incremental sessions, stream adapters or CLI standard input; more
than one ruleset per call; decoding encoded input; a third detector profile;
the `@redact-secret/wasm` package used directly; detector coverage claims
beyond the support matrix.
