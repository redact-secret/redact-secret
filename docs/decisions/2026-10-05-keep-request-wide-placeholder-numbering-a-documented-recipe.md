---
decision_id: decision-keep-request-wide-placeholder-numbering-a-documented-recipe
status: accepted
scope: workspace
title: Keep request-wide placeholder numbering a documented recipe, not a helper
decided_at: 2026-10-05
spec: engine
---

# Keep request-wide placeholder numbering a documented recipe, not a helper

## Context

[#1180](https://github.com/redact-secret/redact-secret/issues/1180) comes from
the gateway's core-bridge probe (gateway #5, architecture origin
[#1001](https://github.com/redact-secret/redact-secret/issues/1001)). Every
`scan_and_redact` call numbers placeholders from `<SECRET_1>`, so scanning the
N string leaves of one JSON request needs request-wide unique numbers. The
gateway offsets numbering itself in a `RequestScope`, so the request is optional:
a helper, or a documented formatter recipe, to reduce divergence between hosts
and bindings.

The formatter already receives `PlaceholderContext::placeholder_index` in Rust,
JavaScript, Python and WebAssembly: one-based among the findings a call
replaces. A host that adds a base to it and advances the base by the
placeholders the leaf used needs no core support.

## Decision

1. **A documented, tested recipe in each guide; no new public API.** The Rust,
   JavaScript and Python guides each show a formatter that returns
   `base + placeholder_index` and advances `base` by the last index the leaf
   used. The host keeps one integer per request; the closure holds no matched
   value, input or placeholder text.
2. **Every claim the guides make is executed.** `request_wide_numbering_1180.rs`
   (Rust), `request-wide-numbering.test.ts` (JavaScript, real engine through the
   built package) and `test_request_wide_numbering.py` (Python) prove: a bare call
   restarts at 1; leaves are numbered uniquely in visit order; several findings
   in a leaf take consecutive numbers; identical values are numbered per
   occurrence; `block` takes a number and `warn` takes none (the formatter does
   not run for it), so the offset equals the count of `redact` and `block`
   findings; a failing formatter fails the call with no partial text and the
   offset is not advanced; and one incremental session per streamed leaf takes
   the same base.
3. **Key context stays in the host.** The guides tell the host to record each
   leaf's path with the first and last number it used, in its own list, and not
   to place the path in the placeholder text, because a key name is
   caller-controlled input.

## Trade-offs

A recipe puts the offset bookkeeping in each host, so hosts can still diverge on
traversal order or on what they do after a failed leaf. A helper would have
fixed the arithmetic but not those two choices, because the core scans one string
and has no notion of a request, a JSON structure or a key.

Rejected alternatives:

- A request-scope object in the core (Rust, JavaScript and Python). It is a new
  stable name on every surface, owns state across calls in a library that keeps
  none, and has to pick the failure semantics of a half-redacted request. The
  contract is frozen under
  [`decision-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes`](2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md),
  and an additive name can still be added later.
- A `placeholder_offset` option on `scan_and_redact`. It makes the numbering
  contract depend on a second input and does nothing for `redact` called with
  findings from another call or for incremental sessions, which a formatter
  covers uniformly.
- A multi-leaf scan call. It would need the core to define leaf order and
  per-leaf limits, which is the gateway's request-wide limit logic, not
  detection.

## Revisit triggers

Add a helper when two or more hosts need the same bookkeeping beyond an offset
(for example request-wide limits or a shared leaf report) and the recipe's
tests show the hosts diverging, or when a binding gains a formatter that cannot
express the offset.

## Consequences

`docs/specs/engine.md` gains one row, `docs/reference/api-contract.md` points to
the recipe, and the three guides document it. No detector, policy, limit,
formatter or numbering behavior changes, and no export is added.
