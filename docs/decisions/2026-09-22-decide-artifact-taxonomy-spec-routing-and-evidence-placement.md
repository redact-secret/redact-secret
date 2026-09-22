---
decision_id: decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement
status: accepted
scope: workspace
title: Decide the artifact taxonomy, spec routing, and evidence placement
decided_at: 2026-09-22
---

# Decide the artifact taxonomy, spec routing, and evidence placement

## Decision

Every committed document or generated file under `docs/`, `assessment/`, and
`benchmarks/` has exactly one kind from the table below. A file's kind is
found by what reads or produces it, never by its current path -- paths that
disagree with this table are a defect this ADR records but does not fix (see
[Scope](#scope)).

| Kind | Test | Location |
| --- | --- | --- |
| Live contract / input | CI, a script, or code reads it | a non-archive path (for example `docs/contracts/`) |
| Generated | a script produces it | committed only with a regeneration-equality test; otherwise gitignored |
| Final evidence, product judgement | an ADR or release relies on it | `docs/audits/evidence/<issue>/`, frozen |
| Final evidence, benchmark measurement | a benchmark or scanner run produced it | `redact-secret-benchmarks`, per [`decision-govern-benchmark-regression-promotion`](2026-09-18-govern-benchmark-regression-promotion.md) |
| Iterative / exploratory log | only people read it, not a final record | an issue comment; final records keep a permalink to it, not a copy |
| Detail of a settled record | nothing reads the full text any more | a commit-pinned permalink plus a summary |
| Release record | one per version | `docs/releases/<version>/` |

Two examples motivate the "live contract" and "generated" rows and are not
themselves resolved here: `scripts/audit-precision-contracts.py` reads
`docs/audits/evidence/367/precision-contracts.json` at CI time, so that file
is a live contract sitting inside the frozen-evidence archive by row three's
test, not row one's; and `docs/coverage/fp-fn-summary-NNN.json` is a
generated report whose `-NNN` issue-numbered naming spread from one
docstring example (`scripts/generate-fp-fn-summary.py`, written for #319),
not from a decision, and several of the committed copies have no
regeneration-equality check. Both are placement defects under this taxonomy;
resolving them is [#596](https://github.com/redact-secret/redact-secret/issues/596)
(DS4) and [#595](https://github.com/redact-secret/redact-secret/issues/595) (DS3).

### Spec routing

Five spec files route current rules to the ADRs that set them:
`docs/specs/detector-families.md`, `contextual-detection.md`, `engine.md`,
`distribution.md`, and `evidence-and-gates.md`. A spec file states a rule in
the present tense and links the ADR that decided it. An ADR itself records
why and when a decision was made and stays immutable except by supersession;
it is not rewritten to track the rule's current wording once a spec exists.
Creating these files, adding the `spec:` frontmatter field, and migrating the
67 existing ADRs onto them is [#597](https://github.com/redact-secret/redact-secret/issues/597)
(DS6a); this ADR fixes only the destination and the routing rule they must
satisfy.

### ADR disposition grades

An existing ADR is graded one of three ways as the epic works through it:

- **Keep** -- the ADR stays as it is.
- **Summarize in place** -- the path and `decision_id` stay; the body becomes
  a short summary plus a `full_record:` permalink to the pre-summary text.
- **Merge** -- the ADR folds into a representative ADR that covers the same
  policy; the folded-in `decision_id` survives in the survivor's `aliases:`
  field so old links still resolve.

### Permalink rule

Every permalink used for a summarized or merged detail, or for an evidence
README's link back to superseding history, takes the form
`https://github.com/redact-secret/redact-secret/blob/<40-hex main commit>/<path>`.
The commit is always a `main` commit reachable at the time the permalink is
written; a workbench-branch SHA is never used, because that history is not
guaranteed to stay reachable. `main` history is never rewritten, so a
permalink written this way stays resolvable indefinitely.

### ADR criterion

A decision that applies an existing policy to one more provider family or
one more instance is a spec-file row plus its supporting evidence, not a new
ADR. A new ADR is warranted only for new policy, a new trade-off, or a
precedent that spans families. This is the criterion
[#597](https://github.com/redact-secret/redact-secret/issues/597) enforces in
`decisions:validate` and adds to `AGENTS.md` and `CONTRIBUTION.md`; it is why
25 of the 67 current ADRs (per-provider grammar freezes) are merge or
summarize candidates rather than a pattern to keep repeating.

### Wiki

The GitHub Wiki is unchanged by this ADR and stays out of scope for the whole
epic. Repository Markdown under `docs/`, plus `AGENTS.md`, `CONTRIBUTION.md`,
and `CONVENTIONS.md`, remains the source documentation, as
[`convention-feature-documentation`](../../conventions/feature-documentation.md)
already states. Whether a separate web-app repository or the GitHub Wiki ever
becomes the public delivery platform remains undecided and is not this ADR's
question to answer.

## Scope

This ADR decides the taxonomy, the spec-file set and routing rule, the ADR
disposition grades, the permalink form, the ADR criterion, and the wiki's
status. It moves no file: every existing misplacement it names (the frozen
evidence folder holding a live contract, unpinned generated coverage
snapshots, undifferentiated iterative logs, per-family ADR sprawl) is left
exactly where it is for the dependent issues listed in
[#591](https://github.com/redact-secret/redact-secret/issues/591) to resolve
against this record.

## Consequences

Every later move, merge, or summary in the DS epic cites this ADR for *why*
a file belongs where it is going, instead of re-deriving the taxonomy per
issue. `docs/README.md` gains the same taxonomy table so a reader lands on
one authoritative placement rule from either the decision record or the
documentation home. `AGENTS.md` and `CONTRIBUTION.md` state where new
evidence goes so a contributor does not have to find this ADR first. The ADR
criterion in [#597](https://github.com/redact-secret/redact-secret/issues/597)
now has a decision to cite instead of shipping as an unmotivated rule, and
beta.7's own family issues (#308-#315, #574) are expected to add spec rows,
not new per-family ADRs, once #597 lands.
