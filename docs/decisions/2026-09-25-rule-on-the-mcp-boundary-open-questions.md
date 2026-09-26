---
decision_id: decision-rule-on-the-mcp-boundary-open-questions
status: accepted
scope: workspace
title: Redact key-identified leaves in place, make `resources/read` the next MCP boundary, and defer Python MCP
decided_at: 2026-09-25
spec: distribution
---
# Redact key-identified leaves in place, make `resources/read` the next MCP boundary, and defer Python MCP

## Decision

The maintainer ruled on 2026-09-25 on the three open questions that
[`decision-define-the-supported-mcp-redaction-boundary`](2026-09-25-define-the-supported-mcp-redaction-boundary.md)
(#612) left undecided. That record is not rewritten: its rules govern
beta.9 unchanged, and this record decides what replaces or extends them.

1. **Key-context findings redact the matching leaf in place (beta.10).**
   The AI-context `sanitizeValue` becomes key-aware: a string leaf that is
   identified as a secret only by the key it sits under (for example the
   value of `"api_key"`) is redacted at that leaf, with leaf offsets,
   instead of passing unredacted under plain AI-context or blocking the
   whole result as `policy` under MCP rule 3. It is an AI-context contract
   change, shipped in beta.10, with a migration note for the `block` ->
   `redact` behaviour change. Detection stays in the core
   ([#609](https://github.com/redact-secret/redact-secret/issues/609)): the
   core's contextual detection decides whether a key/value pair is a
   secret, and the walker carries no key regex or name list of its own.
   Core contract and fixtures:
   [#842](https://github.com/redact-secret/redact-secret/issues/842).
   Adapter walker and removal of the MCP key-context block:
   redact-secret-adapters#32.
2. **`resources/read` is the next supported MCP boundary.** Its contract is
   a thin specialization of the AI-context contract, modelled on #612, and
   is written after (1), because resource contents will likely carry
   structured values. `prompts/get`, sampling, elicitation, completion, and
   the logging and progress notifications stay excluded. Core contract:
   [#843](https://github.com/redact-secret/redact-secret/issues/843);
   adapter: redact-secret-adapters#33; black-box qualification:
   redact-secret-benchmarks#321.
3. **Python MCP stays unsupported.** No Python MCP adapter until a Python
   AI-context adapter exists and there is demonstrated demand. No
   implementation issue is filed.

Dependency order: #842 -> redact-secret-adapters#32 -> #843 ->
redact-secret-adapters#33 -> redact-secret-benchmarks#321.

## Rationale

- **Blocking a whole result for one field costs too much availability.**
  Under beta.9 a structured tool result that names a secret only by its key
  is blocked in full, and a host's only escape is dropping
  `structuredContent`. Peers such as flare-redact redact the leaf in place
  by key name. Redacting the leaf keeps the rest of the result usable and
  leaks nothing that the block protected.
- **Key-aware in the core's terms, not the adapter's.** The #612 record
  rejected redacting on a key-context finding because the finding's offsets
  point into a serialization, not a leaf. Carrying the key into the leaf's
  own scan removes that obstacle without an adapter-side key list, which
  #609 rules out. The false positives it opens (non-secret values under
  credential-like keys) are bounded by the core's existing contextual-name
  rules and exclusions, which #842 must not widen and must measure.
- **`resources/read` is a real leak path.** Resource contents a client reads
  go into model context, logs, and storage exactly as tool results do, and
  nothing in the beta.9 contract scans them. The other excluded messages
  carry less content or content the host writes itself, so they stay out
  until someone shows a need.
- **Python waits for its prerequisite.** An MCP contract specializes the
  AI-context adapter, and no Python AI-context adapter exists. A support
  claim without an adapter that tests it is not evidence.

## Alternatives considered

- **Keep blocking on key-context findings.** Rejected for the availability
  cost above.
- **Match credential-like key names in the adapter.** Rejected. It moves
  detection out of the core and would drift from the core's contextual
  rules.
- **Supersede the #612 record.** Rejected. Seven of its eight rules, its
  exclusions, and its supported range stay in force, and its rule 3 governs
  until beta.10 ships. Supersession replaces a whole record.
- **Add `resources/read` and `prompts/get` together.** Rejected for now:
  prompts are host-authored templates more often than untrusted content,
  and one boundary at a time keeps the claim tested.
- **File a Python MCP issue now.** Rejected. There is no demand evidence and
  no Python AI-context adapter to specialize.

## Consequences

- `docs/specs/distribution.md` links this record from the AI-context and MCP
  rows. The rows keep stating the beta.9 rules in the present tense until
  #842 and #843 ship and restate them.
- #842 changes `docs/reference/ai-context-boundary.md`,
  `docs/reference/mcp-boundary.md`, both conformance fixtures, the Python
  twin, and the changelog. #843 adds a `resources/read` contract and fixture.
- Still open: whether a secret-bearing key should be redacted and renamed
  instead of blocking (the AI-context record's question, which (1) does not
  answer); whether key context extends past the immediate key; and the
  milestones for #843 and its counterparts.
