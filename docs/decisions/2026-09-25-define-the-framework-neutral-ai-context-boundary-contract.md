---
decision_id: decision-define-the-framework-neutral-ai-context-boundary-contract
status: accepted
scope: workspace
title: Define the framework-neutral AI-context boundary contract
decided_at: 2026-09-25
spec: distribution
---
# Define the framework-neutral AI-context boundary contract

## Decision

Integrations that sanitize user input, tool output, constructed context,
and streamed text for an AI workflow implement one contract,
[`docs/reference/ai-context-boundary.md`](../reference/ai-context-boundary.md).
That contract has four operations (`sanitizeText`, `sanitizeValue`,
`buildContext`, `openStream`) and three outcomes: `ok` with value and
findings, `blocked` with a fixed reason and an optional registry code, and
`aborted`. Its behavior is pinned by the cross-language fixture
[`conformance/fixtures/ai-context-boundary.json`](../../conformance/fixtures/ai-context-boundary.json).
That fixture is replayed against publish-shaped artifacts: the packed
JavaScript package on the Node addon lane and in three browser engines, and
each installed Python wheel.

The contract is framework-neutral. It names no model vendor, agent
framework, message schema, or transport, and it is implementable from
documented core APIs alone: `initialize`, whole-input `scanAndRedact` with
`policy` and `limits`, the incremental session (`append`, `finalize`,
`abort`), the finding's safe metadata, and `SecretScanError.code`. The core
gains no new export for it. The installable implementation is
`redact-secret-adapters`' job
([redact-secret-adapters#12](https://github.com/redact-secret/redact-secret-adapters/issues/12)).

### Rules that are new policy, not a restatement of the beta.7 example

1. **Fail closed on traversal.** Exceeding a depth or node limit, meeting
   an unsupported value type, or meeting a cycle blocks the whole value.
   Beta.7's example substituted a marker or silently dropped array items.
2. **Object keys are scanned.** A key with a `redact` or `block` finding
   blocks the whole value.
3. **A non-`ok` outcome carries nothing derived from input.** That means no
   value, no findings, and no message. Auditing uses the telemetry callback,
   which gets the same allowlisted safe metadata.
4. **Safe metadata is an allowlist.** The allowlist is `id`, `type`,
   `detector`, `confidence`, `action`, `obfuscation`, `start`, `end`. A
   field the core adds later cannot cross the boundary without a change to
   this contract. That includes the internal evidence score #768 keeps
   shadow-only.
5. **Streams are staged.** Nothing is released before a successful
   `finalize`. Finalization is single-use, and a `block`, limit, or callback
   failure mid-stream aborts the core session at once.
6. **Whole-input/incremental equivalence is a contract obligation.** Within
   both limit sets, the staged stream outcome equals the whole-input
   outcome at every chunk partition. The only exception is the finding-count
   limit, which incremental sessions do not have.

### The adapter dependency surface widens, deliberately

[`decision-graduate-adapters-to-a-separate-repository`](2026-09-19-graduate-adapters-to-a-separate-repository.md)
held the adapters' dependency on this repository's core to four items and
said that widening it "reopens this decision rather than being absorbed
silently". This record is that reopening, for the AI-context adapter only.
The AI-context adapter may also depend on:

- the whole-input `policy` and `limits` options;
- the incremental session and its limits;
- `SecretScanError.code` values from the fixed registry;
- the full safe finding field set above.

These are all documented, type-exported, lockstep-versioned core APIs
already exercised by this repository's conformance corpora. They stop being
an unprotected surface because the AI-context fixture is replayed against
every publish-shaped JavaScript and Python artifact this repository
qualifies. A change to any of them now fails artifact qualification here
before it can surprise the adapter. The logging and tracing adapters keep
the original four-item surface.

## Rationale

- **Framework-neutral, because the risk sits at the boundary, not in the
  framework.** Every AI framework moves untrusted text across the same
  edges: input into a prompt, tool output into context, a stream into a
  buffer. Binding the contract to a vendor or framework API would couple
  this repository's lockstep release to that framework's churn, the exact
  cost the adapter graduation removed. It would also invite detection or
  policy logic into adapters, which #609 rules out. A neutral contract lets
  MCP (#612) and any later framework adapter be thin consumers.
- **Derived from measurement.** Every operation and outcome comes from
  behavior the beta.7 golden path already tests (#587). Where that example
  was lossy or left a case open, the contract takes the fail-closed choice
  and records it as a divergence. It does not invent a new capability.
- **Security first where availability pays.** Blocking a whole value on a
  traversal limit, a secret-bearing key, or an unsupported type loses
  availability for rare inputs. The alternative is releasing text that was
  never scanned, or scanned only in part. A caller who needs more headroom
  raises the explicit limits.

## Alternatives considered

- **Ship the boundary helper in `@redact-secret/core`.** Rejected. It would
  put a framework-shaped API in the lockstep public surface and make every
  adapter change a core release. The core already has every primitive the
  contract needs.
- **Adopt beta.7's per-leaf marker behavior as the contract.** Rejected. A
  marker keeps a partially scanned structure flowing into model context,
  and silent array truncation changes tool output without saying so.
- **Keep findings on blocked outcomes.** Rejected in favor of telemetry. It
  keeps one fixed blocked shape, and it lets whole-input and incremental
  outcomes stay equal even when a stream stops early on a `block`.
- **Allow progressive stream release.** Rejected for this version.
  Released text cannot be recalled after a later `block`, which contradicts
  the policy decision the host asked for.

## Consequences

- `docs/specs/distribution.md` states the rule and names the widened
  AI-context adapter surface.
- `scripts/consumer-harness.mjs` replays the fixture on every installed
  JavaScript lane, and `scripts/record-artifact-inventory.py` requires
  `aiContextBoundary: passed` from each one. `bindings/python/tests/`
  carries the Python twin, which wheel qualification runs.
- `examples/mcp-redact/` stays an example. Migrating it onto the adapter
  package is redact-secret-adapters#12. Until then the example's divergences
  are the ones listed in the contract.
- The following are recorded as open maintainer questions, not decided
  here: whether key scanning should redact-and-rename instead of blocking;
  whether a later version should offer an opt-in progressive stream mode
  for `warn`-only policies; and whether a Rust runner is wanted before a
  Rust adapter exists.
