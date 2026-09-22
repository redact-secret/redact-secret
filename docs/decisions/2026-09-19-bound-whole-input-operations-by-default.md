---
decision_id: decision-bound-whole-input-operations-by-default
status: accepted
scope: workspace
title: Bound whole-input operations by default
decided_at: 2026-09-19
spec: engine
---

# Bound whole-input operations by default

## Context

Issue [#439](https://github.com/redact-secret/redact-secret/issues/439)
identified a contradiction between the two halves of this crate's public API.
An incremental session always requires explicit, positive `IncrementalLimits`
and fails closed the moment one is exceeded — there is no environment-derived
or silent default, by design. Whole-input `scan`, `redact`, and
`scan_and_redact`, by contrast, had no bound at all: `README.md` stated
plainly that "whole-input operations have no implicit input-size or
finding-count limit" and left bounding entirely to the caller. The easiest
call in the whole public API, `scanAndRedact(untrustedInput)`, was therefore
the one call with no resource safety of its own, and the failure mode for an
oversized input was memory exhaustion at the authoritative boundary rather
than a fixed, input-free error — the opposite of how this library treats
every other failure surface (invalid UTF-8, a limit failure in a session, a
CLI read failure all already fail closed and outrank a finding).

"The caller must bound it" is a defensible general library stance. It is a
weak default for a security tool whose entire value proposition is failing
closed, especially when the CLI in this same repository already made the
opposite choice for its own whole-file reads (`crates/secret-scan-cli`'s
`MAX_INPUT_BYTES`, applied before a file ever reaches the core).

FRS-1 was consulted as external prior art — it sets `maxInputLength` 16 MiB
and `maxFindings` 50,000 per string as engine defaults, both failing with an
error rather than truncating — but its exact values are not copied into this
decision; only the shape of the problem (two independent bounds, fail rather
than truncate) is shared.

## Decision

Whole-input `scan`, `redact`, and `scan_and_redact` default to a declared
`WholeInputLimits { max_input_bytes, max_findings }` and fail closed with a
fixed, input-free error when either bound is exceeded, instead of scanning or
redacting without bound. Their existing signatures are unchanged — an
ordinary caller is protected with no code change — and a new `_with_limits`
sibling function accepts an explicit `WholeInputLimits` for a caller that
needs to raise or lower it.

### Defaults, and why those values

- **`DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024` (64 MiB).** This reuses
  `crates/secret-scan-cli`'s own pre-existing `MAX_INPUT_BYTES`, the bound
  the CLI already applies to a whole file read and to standard input's total
  logical size. Rather than introduce a second, independently chosen number
  that could drift from the CLI's, the core now owns this constant
  (`DEFAULT_MAX_INPUT_BYTES`) and the CLI derives its own `MAX_INPUT_BYTES`
  from it, so the product has one whole-input byte bound instead of two, and
  the CLI's documented behavior is unchanged.
- **`DEFAULT_MAX_FINDINGS = 50_000`.** Independently derived, not copied from
  FRS-1's reference value, from two considerations: a `Finding` serializes to
  roughly 150-300 bytes of JSON in a binding response, so 50,000 findings
  bounds a scan result's finding payload to a low-double-digit-megabyte
  ceiling regardless of how the caller consumes it; and it sits comfortably
  above every legitimate workload and the existing conformance corpus's
  densest known adversarial fixture (`adversarial-dense-aws-findings`, 250
  findings in 5,249 bytes) while remaining a real, reachable ceiling for a
  deliberately dense-packed large adversarial input well before that input
  reaches the 64 MiB byte bound. That gap is the reason this is a second,
  independent bound rather than a restatement of the byte bound: a dense
  adversarial input can exhaust a caller's downstream finding-handling
  capacity long before it exhausts the input-byte budget, so bounding bytes
  alone would not catch it. FRS-1's own reference value happens to land in
  the same order of magnitude, which is corroboration, not the basis for
  this number.

### Error identity

`SecretScanErrorCode::InputLimitExceeded` and `InvalidLimits` are broadened
rather than replaced. Both codes already describe a condition wider than
"incremental sanitizer": `InputLimitExceeded` is the exact code
`crates/secret-scan-cli/src/input.rs`'s pre-existing whole-file bound check
already raised — a check with nothing to do with an incremental session — so
their previous "incremental sanitizer ..." message text was already
imprecise for an existing caller. Broadening their doc comments and message
text ("Secret scan input limit exceeded.", "Secret scan limits are invalid.")
to explicitly cover both incremental sessions and whole-input operations
fixes that imprecision instead of introducing a new inconsistency, and keeps
the limits vocabulary consistent between the two halves of the API rather
than forking it. One new code, `FindingLimitExceeded`, is added for the
finding-count bound, because it has no incremental equivalent: an incremental
session's `IncrementalPolicyContext` deliberately carries no total finding
count (a progressive evaluation cannot know how many findings the whole
session will produce), so there is nothing for a finding-count bound to mean
in that API, and reusing an existing code for a genuinely new failure
condition would have been misleading.

### Opt-out mechanism

The Rust core adds `WholeInputLimits` (byte and finding-count bounds only —
it does not reuse `IncrementalLimits`'s shape, because `IncrementalLimits`
has no finding-count field and its buffered/token/multiline fields describe
incremental retention concepts that do not exist for a whole-input call) and
`scan_with_limits`/`redact_with_limits`/`scan_and_redact_with_limits`,
composable siblings of `scan`/`redact`/`scan_and_redact` that take the limits
explicitly instead of defaulting them. Each binding exposes an equivalent:
`JsWholeInputLimits` and a trailing optional parameter on Node's `scan`/
`redact`/`scan_and_redact` (and their `common`-profile counterparts);
`maxInputBytes`/`maxFindings` optional parameters on the WebAssembly binding's
exports; a `WholeInputLimits` `pyclass` and a `limits` keyword argument on
Python's `scan`/`redact`/`scan_and_redact`; and a `WholeInputLimits`
TypeScript interface plus a `limits` option on `@redact-secret/core`'s
`ScanOptions`/`RedactOptions`.

### `run_detector_pipeline` and the incremental sanitizer are deliberately untouched

`run_detector_pipeline` keeps its existing unbounded contract, and no default
whole-input bound is threaded into `IncrementalSanitizer`. Two things call
`run_detector_pipeline` directly, bypassing `scan`: `IncrementalSanitizer`
scans each closed retained unit, which is already bounded by that session's
own explicit `max_buffered_bytes`; and some bindings' own scan entry points,
which now apply the same `WholeInputLimits` check explicitly before calling
it, rather than have it applied inside the shared primitive. Adding a silent
64 MiB/50,000 default inside `run_detector_pipeline` itself would leak an
undocumented implicit bound into the one API surface whose whole design
point, stated in its own module documentation, is that it has "no
environment-derived or silent defaults" — a caller who configured a large
`max_buffered_bytes` would be silently capped by a number they never chose
and cannot see. The new bound belongs only at the whole-input entry points
that previously had none, not inside a primitive that already has an
explicit bounding mechanism of its own.

## Consequences

This decision supersedes the "no implicit limit" language at `README.md`
(the "Whole-input operations have no implicit input-size or finding-count
limit" paragraph), `ARCHITECTURE.md:495` ("Whole-input APIs have no implicit
input or finding-count limit..."), and `docs/reference/detection.md:66`
("Whole-input operations have no implicit resource cap..."); all three are
updated in this same change to state the new defaults and how to change them,
alongside `docs/guides/rust.md`, `docs/guides/javascript.md`, and
`docs/guides/python.md`, each gaining a short example of the opt-out for that
language.

Unlike `decision-normalize-invisible-characters-before-detection`, whose
implementation issue (#438) landed separately from the ADR issue (#444) that
authorized it, this ADR and its implementation land together in this same
change, because issue #439 itself bundles both under one set of acceptance
criteria: the ADR, the default bound and opt-out mechanism, the broadened and
new error codes, conformance coverage of at-bound acceptance, over-bound
rejection, and the finding-count bound, and every documentation and
changelog update, all in one pull request.

This is a breaking change for any existing caller whose whole-input input or
finding count exceeds the new defaults; `CHANGELOG.md` records the migration.
It does not change the CLI's documented `--help` output or its declared
64 MiB total-input bound — the CLI's `MAX_INPUT_BYTES` now derives from the
core's `DEFAULT_MAX_INPUT_BYTES` instead of duplicating the same literal, so
the two cannot drift apart — but CLI file-path scanning newly inherits the
50,000-finding bound it never had before, which is additional protection,
not a behavior CLI documentation ever promised the absence of.
