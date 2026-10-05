---
decision_id: decision-add-a-side-effect-free-status-query-and-defer-a-published-readiness-probe
status: accepted
scope: workspace
title: Add a side-effect-free status query and defer a published readiness probe
decided_at: 2026-10-05
spec: engine
---

# Add a side-effect-free status query and defer a published readiness probe

## Context

[#1172](https://github.com/redact-secret/redact-secret/issues/1172) comes from
the adapters' input-free readiness check
([redact-secret-adapters#182](https://github.com/redact-secret/redact-secret-adapters/issues/182),
PR #189). To learn whether the core is initialized, and with which PII
activation, it has no call that does not change something. It re-calls
`initialize()` and absorbs the repeat-call conflict, relies on the optional
`piiActivation()` accessor (which throws `NOT_INITIALIZED` before
initialization), and scans a synthetic probe it hardcodes itself.

`initialize()` is one-shot per selection, so an observer that calls it can
fix the process-wide PII selection or fail with `PII_ACTIVATION_CONFLICT`. The
JavaScript runtime already holds the loaded binding and the active selector
key; Python holds the selected `PiiSelection` in a process-wide cell that
scanning reads without setting.

## Decision

1. **Add `status()` to JavaScript and Python, named identically.** JavaScript
   exports `status(): CoreStatus` from the root and `./common` entry points;
   Python exports `redact_secret.status() -> CoreStatus`. It is synchronous,
   takes no argument and never throws or raises. `CoreStatus` is a frozen
   object with exactly three fields:
   - `initialized: boolean`: `true` only after an initialization has
     succeeded. It is `false` before the first call, while a JavaScript load is
     pending, and after a failed load. In Python it is `true` once
     `initialize()` has fixed the selection; scanning without `initialize()`
     works and leaves it `false`.
   - `profile`: `"full"` or `"common"`, the entry point's profile (always
     `"full"` in Python).
   - `activation`: the `piiActivation()` / `pii_activation()` identity once
     initialized, otherwise `null` (`None` in Python). It is the value an
     initialized module reports, never a guess for an uninitialized one.
2. **No effect and no leak.** The query never loads an artifact, calls
   `initialize`, locks a selection, or changes any state; calling it before
   `initialize()` leaves a later `initialize()` free to choose any selection.
   The result holds fixed values and public capability metadata only: no
   exception text, path, input or secret-derived value. A failure to read the
   activation in JavaScript reports `activation: null`, not an error.
3. **JavaScript derives it in the shared runtime, with no native call.** The
   Node addon and WebAssembly binding are unchanged, so the root and `./common`
   entry points, every runtime (Node, browser, `workerd`) and both artifacts
   report identically. Python adds one native function and pyclass. Rust has no
   lifecycle to query and the CLI is one shot, so neither adds anything.
4. **Class: stable, additive.** `status` and `CoreStatus` join the stable
   JavaScript surface and Python `__all__` under
   [`decision-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes`](2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md)
   item 2 (additive, so a patch release). Releases before it do not export the
   name; probing for the name is the consumer's fallback.
5. **No core-published readiness probe now.** The issue's optional second part
   (a versioned synthetic input plus an expected result shape) is deferred.
   `status()` answers the lifecycle question without any detection behavior.
   A probe is a published detection claim: its expected shape would pin a
   detector, a finding type and a range under the stable contract, and fold
   "the detector registry changed" into "the readiness contract changed" while
   [item 8 of that decision](2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md)
   keeps coverage outside the contract. It would also need one fixture
   mirrored in the Rust core, the Node addon, WebAssembly and Python, with the
   offset-unit differences between them, and a synthetic token that passes the
   repository's secret-scanning push protection. The adapters carry a working
   probe today.

## Trade-offs

A boolean `initialized` cannot say a binding is healthy, only that it has been
set up; the guide states that it is not a detection-readiness claim.
Reporting `null` before initialization differs from Python's scan behavior
(credential-only without `initialize()`), but it gives one rule across both
languages and cannot be mistaken for an activation someone chose.

Rejected alternatives:

- `isInitialized()` alone. It cannot report the activation without a second
  call that throws before initialization.
- Returning the activation string only. The empty/absent case needs a code, and
  a pending or failed load must not read as an exception.
- A native `status` in the addon and WebAssembly. It adds three surfaces to
  keep in step for state the JavaScript runtime already owns, and an older
  artifact paired with a newer package would not have it.
- Publishing the probe now. See item 5.

## Revisit triggers

Reconsider a published probe when two or more consumers need the same fixture
and a conformance corpus entry can carry it with its versioned expected shape,
or when the support matrix gains a cross-binding detection claim a readiness
check could cite.

## Consequences

`docs/specs/engine.md` gains one row, `docs/reference/api-contract.md` states
the contract, and the JavaScript and Python guides document the call. The
public export lists, the type contracts, the Python stub and
`__all__`-versus-stub tests pin the names. No detector, policy, limit or
initialization behavior changes. Adapters keep supporting older cores by
feature-testing the name.
