---
decision_id: decision-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes
status: accepted
scope: workspace
title: Define the 0.1.x stable public contract and its compatibility classes
decided_at: 2026-10-02
spec: engine
---

# Define the 0.1.x stable public contract and its compatibility classes

## Context

Before 0.1.0 the project has shipped betas whose public names, error codes and
finding `type` strings changed between releases. "Stable" had no definition:
nothing said which names are promised, which version number a breaking change
costs, or which sets are allowed to grow
([#1066](https://github.com/redact-secret/redact-secret/issues/1066), under
[#1065](https://github.com/redact-secret/redact-secret/issues/1065)).

The audit in [`docs/audits/evidence/1066`](../audits/evidence/1066/README.md)
reconciled every public name of the four surfaces (54 Rust root names, 44
Python names, the JavaScript exports and the CLI) against its documentation,
declaration and tests, and listed nine surfaces likely to break after a
freeze. The declarative ruleset part is decided separately in
[`decision-define-declarative-ruleset-revisioning`](2026-10-02-define-declarative-ruleset-revisioning.md).

## Decision

The owner accepted the draft contract on 2026-10-02, as recommended in the
audit. The facts live in
[`docs/reference/api-contract.md`](../reference/api-contract.md#stable-contract-1);
this record decides the policy that section relies on.

1. **Compatibility classes.** Every public surface is in exactly one class.
   - **Stable**: the names, behavior and values the contract lists for Rust
     (the `core-public-api` root names), JavaScript (`@redact-secret/core` and
     its subpaths), Python (`redact_secret.__all__` and the `.pyi` stubs), the
     CLI (arguments, exit statuses, `--json` fields) and the conformance
     fixtures' behavior.
   - **Experimental**: shipped but not promised, such as the line-per-finding
     CLI text report, and constructs the contract names as unsupported.
   - **Internal**: private modules, `redact_secret._native`, the WebAssembly
     glue, `@redact-secret/wasm`, `@redact-secret/node` and the platform
     packages. No promise; versioned in lockstep only.
   - **Excluded**: not provided and not promised, such as JavaScript or Python
     custom detector callbacks, decoding of encoded input and a third
     detector profile.
2. **Change kinds.** A *breaking* change makes a correct call stop compiling or
   working, or changes what a documented value means (removing or renaming an
   export, changing a signature, a range unit, an action's meaning, an error
   code's meaning or a published finding `type` or `detector` string). An
   *additive* change adds a name, option, accepted input, error code or
   `type`/`detector` value that correct code can ignore. A *behavioral* change
   alters findings, spans or timing for the same call (a new detector, a tuned
   span); it needs a changelog entry and is covered by the support matrix and
   evidence, not frozen.
3. **Version rule.** While the major version is 0, a breaking change to a
   stable surface bumps the MINOR version (the first would be 0.2.0), and
   additive and behavioral changes ship in patch releases (0.1.x). A breaking
   change needs a contract review and a `Changed` changelog entry, and is never
   in a patch release.
4. **Open sets.** Finding `type` and `detector` strings, JavaScript
   `SecretScanErrorCode` members, Python exception classes and the Rust
   `SecretScanErrorCode` and `Profile` enums (`#[non_exhaustive]`) are open:
   they grow additively. A consumer handles an unknown code or value as a
   failure and a `match` over a Rust open enum carries a wildcard arm. Renaming,
   splitting or removing a published `type` or `detector` string is breaking.
5. **Closed by design.** `Action`, `Confidence` and `Specificity` are
   exhaustive Rust enums. A new variant changes pipeline semantics, so adding
   one is a breaking change.
6. **CLI statuses.** Exit status `0` is clean, `1` is a check-mode finding and
   `2` is a usage, decoding, limit, read or write failure. Any other status
   (for example `101` from a panic, or death by signal) is an internal failure
   outside the contract: treat it as a failure and discard the output. The CLI
   never writes an unsanitized byte. The `--json` report keeps its fields
   (`version`, `rangeUnit`, `findingCount`, `sources`, `failures`) and may only
   add fields.
7. **JavaScript errors** stay one fixed message per code. A rejection-class
   field is not part of 0.1.x; an additive optional field may follow later.
8. **Coverage is outside the contract.** Which credentials are found is the
   support matrix's, not this contract's.

## Trade-offs

A MINOR bump for a breaking change makes pre-1.0 breakage visible in the
version number at the cost of a lower patch cadence for risky work. Open sets
keep the product free to add detectors and codes, and move the burden to
consumers, who must treat unknown values as failures. Closing `Action`,
`Confidence` and `Specificity` keeps exhaustive matches useful and makes any
extension a deliberate breaking change.

Rejected alternatives:

- Freeze every enum. Error codes have grown every release; this would make each
  new code breaking.
- Catch panics and exit `2`. It cannot cover aborts or signals and would
  promise a status the CLI cannot always deliver
  ([#1130](../audits/evidence/1130/README.md)).
- Freeze the finding `type` set. Detector coverage grows.

## Consequences

The API contract reference carries the accepted facts. A change that is
breaking under item 2 needs this record's review and a MINOR bump; a change to
the contract's facts that is additive updates the reference and the changelog.
The stable claim rests on a source-checkout run on one host; conformance
against the exact candidate artifacts, other operating systems and other Node
and Python versions remains with
[#199](https://github.com/redact-secret/redact-secret/issues/199).
