---
decision_id: decision-define-cross-language-evaluation-protocol
status: accepted
scope: workspace
title: Define the cross-language evaluation protocol
decided_at: 2026-09-12
spec: evidence-and-gates
---

# Define the cross-language evaluation protocol

## Decision

Add one repeatable assessment protocol, covering the Rust core, Python,
Node, the browser WebAssembly artifact, and the CLI, under a new top-level
`assessment/` directory kept distinct from `conformance/`: `conformance/` is
the executable behavioral contract every binding must pass to release;
`assessment/` measures accuracy and performance against a common result
contract and is never itself a release gate.

The protocol has three parts:

- A **synthetic assessment corpus** of reviewed accuracy fixtures across
  `logs`, `code`, `chat`, and `negative-text`, some exercising Unicode
  (including the astral-character boundary case), each with a reviewed
  expected finding set in UTF-8 byte ranges and the policy-aware outcome
  (`block`, `redact`, `warn`, or `allow`) the shipped default policy applies.
  Canonical ranges are UTF-8 byte offsets; a runner normalizes its own native
  offsets to UTF-8 bytes before comparing, then verifies the converted span
  selects the same original substring in its own native units — the same
  model `conformance/` uses.
- **Named workload profiles** declaring a `purpose` of `"accuracy"` or
  `"scale"`, a category, a target input size, a target finding density, a
  chunk profile, and whether the input mixes non-ASCII filler text. An
  accuracy profile stays at or under a fixed minimal-size cap and is always
  fed whole, so accuracy measurement never contends with chunking or timing
  overhead; a scale profile is always larger and exists to measure
  initialization, processing time, throughput, repeated-run variance, and
  peak memory instead. A scale profile's input text is never committed as
  data — it is reproduced deterministically from the profile's own fields by
  a pure generator function, so the profile itself is complete provenance.
- A **common result contract** every surface reports through:
  `schemaVersion`, `surface`, `profileId`, either `accuracy` or `performance`
  metrics (or both), and a `provenance` block recording the source commit,
  the exact built artifact identity, the corpus version and hash, OS, CPU,
  runtime, and the exact command — so a result is reproducible and placeable
  without re-deriving any of that by hand.

This item defines the schema, the corpus, the profiles, and the result
contract, plus deterministic tests proving the corpus and profiles validate,
the generator is deterministic, and known-answer cases produce their exact
expected output. It does not build the five per-surface runners that execute
a profile and emit a real `AssessmentResult`; that is separate, larger work,
on the same terms `conformance/README.md` already draws between defining a
contract and building every language's consumer of it.

## Rationale

A repeatable protocol requires the same three things `conformance/` already
established for behavior: one schema everyone validates against, ranges
expressed in one canonical unit that every surface converts to and from, and
inputs and diagnostics that can never leak a matched value. Splitting
accuracy measurement from scale measurement, with a hard size cap on
accuracy profiles, prevents the two most common ways an evaluation protocol
quietly becomes unrepeatable: an accuracy check whose timing varies with
unrelated I/O or chunking overhead, and a scale check whose findings count
depends on a corpus that also carries hand-reviewed boundary cases. Requiring
full provenance on every result — commit, artifact, corpus hash, host, and
command — is what makes a number comparable across surfaces and across time
instead of an anecdote.

## Alternatives considered

- Extending `conformance/`'s existing schema with timing and memory fields
  was rejected because it would make the release-gating behavioral contract
  depend on machine-specific, non-deterministic measurements.
- Committing large generated workload inputs as fixture data was rejected in
  favor of committing only the generating profile: a multi-megabyte fixture
  is expensive to review for safety and to keep in sync with its own
  generator, while a profile plus a pure generator function is itself
  reviewable and reproduces byte-for-byte.
- Building the five per-surface runners in the same change was rejected as
  premature: without an agreed schema and result contract first, each runner
  would encode its own ad hoc metrics shape, which is the drift this decision
  exists to prevent.

## Consequences

- A change to `assessment/schema.ts` or `assessment/schema.json` is reviewed
  as a cross-language contract change, on the same terms a `conformance/`
  schema change already is.
- Building a runner for any of the five surfaces must emit `AssessmentResult`
  records conforming to this contract; a runner that reports different
  fields is not evaluating this protocol.
- A future scale workload profile whose generation would take a meaningfully
  long time must be inspected before it is proposed, per `AGENTS.md`'s rule
  for any command expected to exceed five minutes.

**Amended 2026-09-22 by `decision-move-performance-results-criteria-and-judgement-to-benchmarks`:**
this protocol's committed corpus, profiles, and result contract stay in
`assessment/`. The RC acceptance criteria and pinned baselines this
repository committed on top of that contract, and the pass/fail judgement
against them, were never part of this protocol and are now explicitly owned
by `redact-secret-benchmarks`, not committed here as `assessment/results/` or
`assessment/acceptance-criteria*.json`.
