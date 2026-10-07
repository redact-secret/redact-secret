---
decision_id: decision-define-the-implementation-ready-handoff-contract
status: accepted
scope: workspace
title: Define the implementation-ready handoff as a coding-only work-item state with a frozen field list and shared vocabulary
decided_at: 2026-10-07
spec: evidence-and-gates
---

# Define the implementation-ready handoff as a coding-only work-item state with a frozen field list and shared vocabulary

## Context

[#1049](https://github.com/redact-secret/redact-secret/issues/1049), under
[#999](https://github.com/redact-secret/redact-secret/issues/999), asks for one
state in which research and the product contract are finished and an outside
contributor can implement without repeating provider research. The benchmarks
repository already decided a five-word work-item vocabulary
([`decision-define-benchmark-handoff-states`](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/decisions/2026-09-30-define-benchmark-handoff-states.md))
and names this issue as its core counterpart. Core had no definition: the Ory
issue [#1110](https://github.com/redact-secret/redact-secret/issues/1110) shows
the cost, a handoff whose first screen is a research disposition and whose
contract sits behind a permalink. This is new cross-repository policy, so it is
an ADR and not a spec row alone.

## Options

1. **Define the states only in the issue forms.** Rejected: the forms are
   intake and cannot express an adoption ruling, ownership or the boundary that
   a state is not a support verdict.
2. **Invent a core-specific vocabulary.** Rejected: two vocabularies for one
   funnel would force every contributor and every tool to translate.
3. **Adopt the benchmarks five words unchanged, add a frozen field list, a
   contributor-first layout and a machine-readable form.** Chosen.

## Decision

- The vocabulary is `intake`, `research-needed`, `implementation-ready`,
  `verification-needed`, `complete`, applied to core implementation issues as
  `state:<word>` labels, one at a time. They label work items, never a family's
  support status, and no status, tier or verdict is inferred from them.
- `implementation-ready` requires every field of the
  [handoff contract](../contracts/contribution/implementation-ready-handoff.md#required-fields):
  identity and route, task, positives, exclusions, near-miss twins and benign
  siblings, policy classification with both trade-offs, conformance
  expectations, the revision-bound research handoff and core's adoption ruling,
  independent-evaluation linkage, surfaces and exact scoped commands. A missing
  field keeps the issue in `research-needed`.
- Every unresolved limitation is an exclusion. No credential-shaped literal
  appears in a handoff. Research and implementation are never one issue.
- Ownership: credential-evidence owns provider facts and the research handoff;
  core owns the product contract, implementation and the `implementation-ready`
  and `verification-needed` moves (core maintainer); benchmarks owns
  independent evaluation, `complete` and support-status promotion
  (`benchmarks-maintainer`).
- The issue body is contributor-first: task, positives, negatives and twins,
  surfaces, commands, then maintainer evidence collapsed.
- The machine-readable form is
  `<slug>.handoff.json` under the schema `redact-secret.implementation-handoff/v1`,
  generated from or passed with the issue, not committed under `docs/audits/`.
- `implementation-ready` is a coding handoff. It grants no stable support and
  weakens no benchmark, conformance, provenance or promotion gate.

## Consequences

- The scaffold (#1050) and the CI summary (#1051) read the schema; the issue
  forms (#1048) route to the vocabulary.
- `credential-evidence` and `redact-secret-benchmarks` mirror the vocabulary and
  owners; neither is edited by this record.
- Adding an optional field is not a decision; removing a field or changing a
  state word is a new decision that amends this one.
