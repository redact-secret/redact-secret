---
decision_id: decision-define-key-aware-sanitize-value
status: accepted
scope: workspace
title: Scan a structured leaf with its immediate key through a key-context view
decided_at: 2026-09-25
spec: distribution
---
# Scan a structured leaf with its immediate key through a key-context view

## Decision

[`decision-rule-on-the-mcp-boundary-open-questions`](2026-09-25-rule-on-the-mcp-boundary-open-questions.md)
ruled that a value identified only by its key is redacted at its leaf in
place (beta.10). This record settles how, for
[#842](https://github.com/redact-secret/redact-secret/issues/842). The rules
are in [`docs/reference/ai-context-boundary.md`](../reference/ai-context-boundary.md#key-aware-sanitizevalue)
and [`docs/reference/mcp-boundary.md`](../reference/mcp-boundary.md#key-context-backstop).

1. **No new core API.** Key context reaches the core through the documented
   whole-input `scanAndRedact` (`scan_and_redact`), on a key-context view of
   the leaf: the text `{"<key>":"<leaf>"}`, key and leaf verbatim. The
   core's existing contextual detection and policy decide; the walker holds
   no key list.
2. **Leaf first, view second.** A leaf is scanned alone first. The view is
   scanned only when that scan redacts or blocks nothing, and its result is
   used, whole, when it redacts or blocks, or when the leaf alone reported
   nothing. Findings from the two scans are never merged.
3. **Leaf offsets.** A view finding inside the leaf's span is shifted back by
   the length of `{"<key>":"`. A view finding outside it is not reported for
   the leaf, and one that would redact or block blocks the value as `policy`.
4. **Immediate key only.** The context of a leaf is the name of the object
   property whose value it is. Array elements, the root, parent keys, and
   sibling keys give none. Non-string scalars are unchanged.
5. **MCP rule 3 narrowed to a backstop.** The serialized rescan of the
   sanitized result stays. Once the leaf pass redacts key-identified leaves,
   it blocks only on context the leaf pass cannot see (a sibling or parent
   key, a pair split across leaves).
6. **Limits.** The view is bounded by the same whole-input limits, so a
   view over `maxInputBytes` blocks as `limit_exceeded`, even when the leaf
   alone fits.

## Rationale

- **Reuse the core's detection unchanged.** A `{"key":"leaf"}` view is what
  `JSON.stringify` writes for a one-pair object, so a pair in
  `structuredContent` and the same pair in a text block get the same result
  (fixture `result-structured-content-key-context-redacts-in-place`), and no
  rule in [`contextual-detection`](../specs/contextual-detection.md) is
  widened or duplicated. A new core option that takes a key would need a
  Rust, N-API, WASM, and Python change to reach the same result.
- **Verbatim embedding keeps the offset map trivial.** Offsets shift by one
  prefix length in every runtime's own unit. Escaping the leaf would need a
  per-runtime escape map. The cost is that a `"` or a line terminator inside
  the leaf ends the view's contextual value there, the same place it ends in
  text.
- **Leaf first keeps the leak surface from growing.** A leaf that its own
  scan redacts keeps exactly that result, so nothing beta.9 redacted can
  pass now; the view is consulted only where the leaf alone redacts nothing.
  Choosing one whole core result, never merging two, keeps overlap
  resolution in the core.
- **Immediate key only bounds the false positives.** Parent and sibling
  keys would redact every string under an `auth` or `credentials` object,
  including user names and URLs, and the text scan does not do that either.
  Array elements under a credential name are rare in tool output, and the
  text scan does not read `"password": ["..."]` as an assignment.
- **The backstop costs nothing where the leaf pass works.** Placeholders are
  not detected again, so a redacted leaf never trips it; it still closes
  sibling-context detections such as a keyword-gated provider token
  (`{"provider": "twilio", "value": "<hex>"}`), which would otherwise be a
  new false negative under MCP.

## Alternatives considered

- **Add a key-context option to the core API.** Rejected: every binding
  changes for what the existing API already does, and the contract would
  then depend on a beta.10 core instead of any supported one.
- **Escape key and leaf as JSON.** Rejected for the offset-map cost above.
- **View only, no leaf-alone scan.** Rejected: a line-anchored grammar
  stops matching behind the prefix. A `heroku auth:token` line followed by
  a legacy Heroku key warns as a leaf and reports nothing inside
  `{"x":"..."}`, so a view-only walker would lose findings, and could let
  pass a leaf that beta.9 redacted.
- **Merge the two scans' findings.** Rejected: it is overlap resolution in
  the walker.
- **Carry parent or array keys.** Rejected for the false positives above;
  it stays an open question until someone measures a need.
- **Remove MCP rule 3 entirely.** Rejected: sibling-context detections
  would pass in `structuredContent` while the text copy caught them.

## Consequences

- Plain AI-context `sanitizeValue` now redacts leaves it passed; under MCP,
  results and arguments that were blocked only through the key-context check
  are `ok` with the leaf replaced. Hosts that relied on the block use
  `onFinding`. The changelog and both reference docs carry the migration
  note.
- One more whole-input scan runs for each string leaf under an object key
  that its own scan does not redact.
- `conformance/fixtures/ai-context-boundary.json`, its Python twin, and
  `conformance/fixtures/mcp-boundary.json` pin the behavior, including the
  false-positive and false-negative bounds; redact-secret-adapters#32
  implements it in `adapter-ai-context` and `adapter-mcp`.
- Still open: whether a secret-bearing key should be redacted and renamed,
  and whether key context should extend past the immediate key.
